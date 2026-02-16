"""
NEXUS QA Celery Tasks

Async task definitions for scans, reports, and background jobs.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from celery import current_task
from celery.exceptions import SoftTimeLimitExceeded

from app.core.config import settings
from app.core.logging import get_logger, set_request_context, clear_request_context
from app.core.exceptions import ScanTimeoutError, ScanError
from app.db.base import get_db_session
from app.db.models import ScanStatus
from app.db.repositories import ScanRepository, FindingRepository, WebhookRepository

from .celery_app import celery_app

logger = get_logger(__name__)


def run_async(coro):
    """Run async function in sync context."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# =============================================================================
# Scan Tasks
# =============================================================================


@celery_app.task(
    bind=True,
    name="app.queue.tasks.run_scan_task",
    max_retries=2,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_backoff_max=300,
)
def run_scan_task(
    self,
    scan_id: str,
    tenant_id: str,
    url: str,
    scan_type: str = "deep",
    config: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    Execute a security scan.

    This task:
    1. Updates scan status to RUNNING
    2. Executes the scan phases
    3. Saves checkpoints for recovery
    4. Updates results when complete
    """
    set_request_context(scan_id=scan_id, tenant_id=tenant_id)

    logger.info(
        f"Starting scan task",
        scan_id=scan_id,
        url=url,
        scan_type=scan_type,
        task_id=self.request.id
    )

    try:
        result = run_async(_execute_scan(
            scan_id=scan_id,
            tenant_id=tenant_id,
            url=url,
            scan_type=scan_type,
            config=config or {},
            task_id=self.request.id
        ))
        return result

    except SoftTimeLimitExceeded:
        logger.warning(f"Scan soft time limit exceeded", scan_id=scan_id)
        run_async(_handle_scan_timeout(scan_id))
        raise ScanTimeoutError(
            scan_id=scan_id,
            timeout_seconds=settings.scan_timeout_seconds,
            phase="unknown"
        )

    except Exception as e:
        logger.error(f"Scan task failed: {e}", scan_id=scan_id, exc_info=True)
        run_async(_handle_scan_failure(scan_id, str(e)))
        raise

    finally:
        clear_request_context()


@celery_app.task(
    bind=True,
    name="app.queue.tasks.resume_scan_task",
    max_retries=1,
)
def resume_scan_task(
    self,
    scan_id: str,
    tenant_id: str
) -> Dict[str, Any]:
    """
    Resume a failed/paused scan from checkpoint.

    Loads checkpoint data and continues from last saved state.
    """
    set_request_context(scan_id=scan_id, tenant_id=tenant_id)

    logger.info(f"Resuming scan from checkpoint", scan_id=scan_id)

    try:
        result = run_async(_resume_scan(
            scan_id=scan_id,
            task_id=self.request.id
        ))
        return result

    except Exception as e:
        logger.error(f"Resume task failed: {e}", scan_id=scan_id, exc_info=True)
        run_async(_handle_scan_failure(scan_id, str(e)))
        raise

    finally:
        clear_request_context()


async def _execute_scan(
    scan_id: str,
    tenant_id: str,
    url: str,
    scan_type: str,
    config: Dict,
    task_id: str
) -> Dict[str, Any]:
    """Execute the actual scan logic."""
    async with get_db_session() as db:
        scan_repo = ScanRepository(db)

        # Update scan to running
        await scan_repo.update_status(
            scan_id=scan_id,
            status=ScanStatus.RUNNING.value,
            progress=0,
            phase="initializing"
        )

        # Store task ID for tracking
        await scan_repo.update(scan_id, task_id=task_id)

        # Import scanner here to avoid circular imports
        from app.scanner.orchestrator import ScanOrchestrator

        # Create and run scanner
        orchestrator = ScanOrchestrator(
            scan_id=scan_id,
            url=url,
            scan_type=scan_type,
            config=config
        )

        try:
            result = await orchestrator.run()

            # Get severity counts
            finding_repo = FindingRepository(db)
            severity_counts = await finding_repo.get_severity_counts(scan_id)

            # Update scan with results
            await scan_repo.update_status(
                scan_id=scan_id,
                status=ScanStatus.COMPLETED.value,
                progress=100
            )

            await scan_repo.update_results(
                scan_id=scan_id,
                overall_score=result.get("overall_score", 0),
                findings_count=result.get("findings_count", 0),
                severity_counts=severity_counts,
                framework_scores=result.get("framework_scores", {})
            )

            # Clear checkpoint on success
            await scan_repo.clear_checkpoint(scan_id)

            logger.info(
                f"Scan completed successfully",
                scan_id=scan_id,
                findings_count=result.get("findings_count", 0),
                score=result.get("overall_score", 0)
            )

            # Trigger webhooks
            trigger_webhooks_task.delay(
                tenant_id=tenant_id,
                event_type="scan.completed",
                payload={
                    "scan_id": scan_id,
                    "status": "completed",
                    "findings_count": result.get("findings_count", 0),
                    "overall_score": result.get("overall_score", 0)
                }
            )

            return {
                "status": "completed",
                "scan_id": scan_id,
                "findings_count": result.get("findings_count", 0),
                "overall_score": result.get("overall_score", 0)
            }

        except Exception as e:
            # Save checkpoint before failing
            checkpoint = await orchestrator.get_checkpoint()
            if checkpoint:
                await scan_repo.save_checkpoint(
                    scan_id=scan_id,
                    checkpoint_data=checkpoint,
                    phase=orchestrator.current_phase or "unknown"
                )
            raise


async def _resume_scan(scan_id: str, task_id: str) -> Dict[str, Any]:
    """Resume scan from checkpoint."""
    async with get_db_session() as db:
        scan_repo = ScanRepository(db)

        # Get scan with checkpoint
        scan = await scan_repo.get_by_id(scan_id)
        if not scan:
            raise ScanError(f"Scan not found: {scan_id}", scan_id=scan_id)

        if not scan.checkpoint:
            raise ScanError(f"No checkpoint available for scan: {scan_id}", scan_id=scan_id)

        # Update status
        await scan_repo.update_status(
            scan_id=scan_id,
            status=ScanStatus.RUNNING.value,
            phase=scan.checkpoint_phase or "resuming"
        )
        await scan_repo.update(scan_id, task_id=task_id)

        # Import and run scanner with checkpoint
        from app.scanner.orchestrator import ScanOrchestrator

        orchestrator = ScanOrchestrator(
            scan_id=scan_id,
            url=scan.url,
            scan_type=scan.scan_type,
            config=scan.config or {},
            checkpoint=scan.checkpoint
        )

        result = await orchestrator.run()

        # Update results
        finding_repo = FindingRepository(db)
        severity_counts = await finding_repo.get_severity_counts(scan_id)

        await scan_repo.update_status(
            scan_id=scan_id,
            status=ScanStatus.COMPLETED.value,
            progress=100
        )

        await scan_repo.update_results(
            scan_id=scan_id,
            overall_score=result.get("overall_score", 0),
            findings_count=result.get("findings_count", 0),
            severity_counts=severity_counts,
            framework_scores=result.get("framework_scores", {})
        )

        await scan_repo.clear_checkpoint(scan_id)

        return {
            "status": "completed",
            "scan_id": scan_id,
            "resumed": True,
            "findings_count": result.get("findings_count", 0)
        }


async def _handle_scan_timeout(scan_id: str) -> None:
    """Handle scan timeout - save state and update status."""
    async with get_db_session() as db:
        scan_repo = ScanRepository(db)
        await scan_repo.update_status(
            scan_id=scan_id,
            status=ScanStatus.TIMEOUT.value,
            error_message="Scan exceeded time limit"
        )


async def _handle_scan_failure(scan_id: str, error_message: str) -> None:
    """Handle scan failure - update status and notify."""
    async with get_db_session() as db:
        scan_repo = ScanRepository(db)
        await scan_repo.update_status(
            scan_id=scan_id,
            status=ScanStatus.FAILED.value,
            error_message=error_message[:1000]  # Truncate long errors
        )


# =============================================================================
# Report Tasks
# =============================================================================


@celery_app.task(
    bind=True,
    name="app.queue.tasks.generate_report_task",
    max_retries=2,
)
def generate_report_task(
    self,
    scan_id: str,
    tenant_id: str,
    format: str = "pdf",
    options: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    Generate a report for a completed scan.

    Supports: PDF, HTML, JSON, CSV formats.
    """
    set_request_context(scan_id=scan_id, tenant_id=tenant_id)

    logger.info(f"Generating report", scan_id=scan_id, format=format)

    try:
        result = run_async(_generate_report(
            scan_id=scan_id,
            format=format,
            options=options or {}
        ))
        return result

    except Exception as e:
        logger.error(f"Report generation failed: {e}", scan_id=scan_id)
        raise

    finally:
        clear_request_context()


async def _generate_report(
    scan_id: str,
    format: str,
    options: Dict
) -> Dict[str, Any]:
    """Generate report based on format."""
    from app.reports.generator import ReportGenerator
    from app.db.repositories import ReportRepository

    async with get_db_session() as db:
        generator = ReportGenerator(db)

        report = await generator.generate(
            scan_id=scan_id,
            format=format,
            options=options
        )

        return {
            "report_id": report.id,
            "format": format,
            "storage_url": report.storage_url,
            "file_size": report.file_size
        }


# =============================================================================
# Webhook Tasks
# =============================================================================


@celery_app.task(
    bind=True,
    name="app.queue.tasks.trigger_webhooks_task",
    max_retries=3,
    retry_backoff=True,
)
def trigger_webhooks_task(
    self,
    tenant_id: str,
    event_type: str,
    payload: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Trigger webhooks for an event.

    Finds all active webhooks for the tenant that listen to this event
    and sends HTTP POST requests.
    """
    logger.info(f"Triggering webhooks", tenant_id=tenant_id, event_type=event_type)

    try:
        result = run_async(_trigger_webhooks(
            tenant_id=tenant_id,
            event_type=event_type,
            payload=payload
        ))
        return result

    except Exception as e:
        logger.error(f"Webhook trigger failed: {e}", tenant_id=tenant_id)
        raise


async def _trigger_webhooks(
    tenant_id: str,
    event_type: str,
    payload: Dict[str, Any]
) -> Dict[str, Any]:
    """Send webhook notifications."""
    import httpx
    import hmac
    import hashlib
    import json

    async with get_db_session() as db:
        webhook_repo = WebhookRepository(db)
        webhooks = await webhook_repo.get_active_for_event(tenant_id, event_type)

        results = []

        async with httpx.AsyncClient(timeout=10.0) as client:
            for webhook in webhooks:
                try:
                    # Create signature
                    body = json.dumps(payload)
                    signature = hmac.new(
                        webhook.secret_hash.encode(),
                        body.encode(),
                        hashlib.sha256
                    ).hexdigest()

                    # Send request
                    response = await client.post(
                        webhook.url,
                        json={
                            "event": event_type,
                            "timestamp": datetime.utcnow().isoformat(),
                            "data": payload
                        },
                        headers={
                            "X-Nexus-Signature": f"sha256={signature}",
                            "X-Nexus-Event": event_type,
                            "Content-Type": "application/json"
                        }
                    )

                    success = 200 <= response.status_code < 300
                    await webhook_repo.update_trigger_status(
                        webhook.id,
                        response.status_code,
                        success
                    )

                    results.append({
                        "webhook_id": webhook.id,
                        "status_code": response.status_code,
                        "success": success
                    })

                except Exception as e:
                    logger.warning(
                        f"Webhook failed: {webhook.id}",
                        error=str(e)
                    )
                    await webhook_repo.update_trigger_status(
                        webhook.id,
                        0,
                        False
                    )
                    results.append({
                        "webhook_id": webhook.id,
                        "error": str(e),
                        "success": False
                    })

        return {
            "event_type": event_type,
            "webhooks_triggered": len(results),
            "results": results
        }


# =============================================================================
# Maintenance Tasks
# =============================================================================


@celery_app.task(
    name="app.queue.tasks.cleanup_old_scans_task",
)
def cleanup_old_scans_task(days: int = 90) -> Dict[str, Any]:
    """
    Clean up old scan data.

    Removes scans older than specified days to manage storage.
    """
    logger.info(f"Starting cleanup of scans older than {days} days")

    try:
        result = run_async(_cleanup_old_scans(days))
        return result

    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
        raise


async def _cleanup_old_scans(days: int) -> Dict[str, Any]:
    """Delete old scans and related data."""
    from sqlalchemy import delete, and_
    from app.db.models import Scan, Finding, ScanEvent

    cutoff = datetime.utcnow() - timedelta(days=days)

    async with get_db_session() as db:
        # Get old scan IDs
        from sqlalchemy import select
        result = await db.execute(
            select(Scan.id).where(Scan.created_at < cutoff)
        )
        old_scan_ids = [row[0] for row in result.all()]

        if not old_scan_ids:
            return {"deleted_scans": 0}

        # Delete related data
        await db.execute(
            delete(Finding).where(Finding.scan_id.in_(old_scan_ids))
        )
        await db.execute(
            delete(ScanEvent).where(ScanEvent.scan_id.in_(old_scan_ids))
        )

        # Delete scans
        deleted = await db.execute(
            delete(Scan).where(Scan.id.in_(old_scan_ids))
        )

        logger.info(
            f"Cleanup completed",
            deleted_scans=deleted.rowcount,
            cutoff_date=cutoff.isoformat()
        )

        return {
            "deleted_scans": deleted.rowcount,
            "cutoff_date": cutoff.isoformat()
        }


# =============================================================================
# Utility Functions
# =============================================================================


def get_task_status(task_id: str) -> Dict[str, Any]:
    """Get status of a Celery task."""
    result = celery_app.AsyncResult(task_id)
    return {
        "task_id": task_id,
        "status": result.status,
        "ready": result.ready(),
        "successful": result.successful() if result.ready() else None,
        "result": result.result if result.ready() else None
    }


def cancel_task(task_id: str) -> bool:
    """Cancel a running Celery task."""
    celery_app.control.revoke(task_id, terminate=True)
    logger.info(f"Cancelled task: {task_id}")
    return True
