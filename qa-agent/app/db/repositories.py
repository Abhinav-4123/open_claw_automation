"""
NEXUS QA Repository Pattern

Data access layer with clean separation from business logic.
Provides CRUD operations and complex queries for all entities.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import select, update, delete, func, and_, or_, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.logging import get_logger
from app.core.exceptions import DatabaseNotFoundError
from .models import (
    Tenant, User, Scan, Finding, ScanEvent, Report,
    Webhook, APICallLog, Journey, ScanStatus, Severity
)

logger = get_logger(__name__)


# =============================================================================
# Base Repository
# =============================================================================


class BaseRepository:
    """Base repository with common CRUD operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def commit(self):
        """Commit the current transaction."""
        await self.session.commit()

    async def refresh(self, obj):
        """Refresh an object from the database."""
        await self.session.refresh(obj)


# =============================================================================
# Tenant Repository
# =============================================================================


class TenantRepository(BaseRepository):
    """Repository for Tenant operations."""

    async def create(
        self,
        name: str,
        slug: str,
        plan: str = "free",
        settings: Optional[Dict] = None
    ) -> Tenant:
        """Create a new tenant."""
        tenant = Tenant(
            name=name,
            slug=slug,
            plan=plan,
            settings=settings or {}
        )
        self.session.add(tenant)
        await self.session.flush()
        await self.session.refresh(tenant)
        logger.info(f"Created tenant: {tenant.id}", tenant_id=tenant.id)
        return tenant

    async def get_by_id(self, tenant_id: str) -> Optional[Tenant]:
        """Get tenant by ID."""
        result = await self.session.execute(
            select(Tenant).where(Tenant.id == tenant_id)
        )
        return result.scalar_one_or_none()

    async def get_by_slug(self, slug: str) -> Optional[Tenant]:
        """Get tenant by slug."""
        result = await self.session.execute(
            select(Tenant).where(Tenant.slug == slug)
        )
        return result.scalar_one_or_none()

    async def get_by_api_key_hash(self, api_key_hash: str) -> Optional[Tenant]:
        """Get tenant by API key hash."""
        result = await self.session.execute(
            select(Tenant).where(Tenant.api_key_hash == api_key_hash)
        )
        return result.scalar_one_or_none()

    async def update(self, tenant_id: str, **kwargs) -> Optional[Tenant]:
        """Update tenant fields."""
        await self.session.execute(
            update(Tenant)
            .where(Tenant.id == tenant_id)
            .values(**kwargs, updated_at=datetime.utcnow())
        )
        return await self.get_by_id(tenant_id)

    async def increment_scan_count(self, tenant_id: str) -> None:
        """Increment monthly scan count."""
        await self.session.execute(
            update(Tenant)
            .where(Tenant.id == tenant_id)
            .values(scan_count_monthly=Tenant.scan_count_monthly + 1)
        )

    async def reset_monthly_counts(self, tenant_id: str) -> None:
        """Reset monthly scan count."""
        await self.session.execute(
            update(Tenant)
            .where(Tenant.id == tenant_id)
            .values(
                scan_count_monthly=0,
                last_reset_at=datetime.utcnow()
            )
        )

    async def check_scan_limit(self, tenant_id: str) -> Tuple[bool, int, int]:
        """
        Check if tenant has reached scan limit.
        Returns: (can_scan, current_count, limit)
        """
        tenant = await self.get_by_id(tenant_id)
        if not tenant:
            return False, 0, 0

        # Check if we need to reset monthly counter
        if tenant.last_reset_at:
            days_since_reset = (datetime.utcnow() - tenant.last_reset_at).days
            if days_since_reset >= 30:
                await self.reset_monthly_counts(tenant_id)
                return True, 0, tenant.scan_limit_monthly

        can_scan = tenant.scan_count_monthly < tenant.scan_limit_monthly
        return can_scan, tenant.scan_count_monthly, tenant.scan_limit_monthly


# =============================================================================
# User Repository
# =============================================================================


class UserRepository(BaseRepository):
    """Repository for User operations."""

    async def create(
        self,
        tenant_id: str,
        email: str,
        name: Optional[str] = None,
        password_hash: Optional[str] = None,
        role: str = "member"
    ) -> User:
        """Create a new user."""
        user = User(
            tenant_id=tenant_id,
            email=email,
            name=name,
            password_hash=password_hash,
            role=role
        )
        self.session.add(user)
        await self.session.flush()
        await self.session.refresh(user)
        logger.info(f"Created user: {user.id}", user_id=user.id, tenant_id=tenant_id)
        return user

    async def get_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        result = await self.session.execute(
            select(User).where(User.id == user_id)
        )
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        result = await self.session.execute(
            select(User).where(User.email == email)
        )
        return result.scalar_one_or_none()

    async def get_by_tenant(
        self,
        tenant_id: str,
        limit: int = 100,
        offset: int = 0
    ) -> List[User]:
        """Get all users for a tenant."""
        result = await self.session.execute(
            select(User)
            .where(User.tenant_id == tenant_id)
            .order_by(desc(User.created_at))
            .limit(limit)
            .offset(offset)
        )
        return list(result.scalars().all())

    async def update(self, user_id: str, **kwargs) -> Optional[User]:
        """Update user fields."""
        await self.session.execute(
            update(User)
            .where(User.id == user_id)
            .values(**kwargs, updated_at=datetime.utcnow())
        )
        return await self.get_by_id(user_id)

    async def update_last_login(self, user_id: str) -> None:
        """Update last login timestamp."""
        await self.session.execute(
            update(User)
            .where(User.id == user_id)
            .values(last_login_at=datetime.utcnow())
        )


# =============================================================================
# Scan Repository
# =============================================================================


class ScanRepository(BaseRepository):
    """Repository for Scan operations."""

    async def create(
        self,
        tenant_id: str,
        url: str,
        scan_type: str = "deep",
        user_id: Optional[str] = None,
        config: Optional[Dict] = None,
        frameworks: Optional[List[str]] = None
    ) -> Scan:
        """Create a new scan."""
        scan = Scan(
            tenant_id=tenant_id,
            user_id=user_id,
            url=url,
            scan_type=scan_type,
            config=config or {},
            frameworks=frameworks or ["owasp_top_10"]
        )
        self.session.add(scan)
        await self.session.flush()
        await self.session.refresh(scan)
        logger.info(f"Created scan: {scan.id}", scan_id=scan.id, url=url)
        return scan

    async def get_by_id(
        self,
        scan_id: str,
        include_findings: bool = False,
        include_events: bool = False
    ) -> Optional[Scan]:
        """Get scan by ID with optional related data."""
        query = select(Scan).where(Scan.id == scan_id)

        if include_findings:
            query = query.options(selectinload(Scan.findings))
        if include_events:
            query = query.options(selectinload(Scan.events))

        result = await self.session.execute(query)
        return result.scalar_one_or_none()

    async def get_by_tenant(
        self,
        tenant_id: str,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[Scan]:
        """Get scans for a tenant with optional filtering."""
        query = select(Scan).where(Scan.tenant_id == tenant_id)

        if status:
            query = query.where(Scan.status == status)

        query = query.order_by(desc(Scan.created_at)).limit(limit).offset(offset)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_running_scans(self, tenant_id: Optional[str] = None) -> List[Scan]:
        """Get all currently running scans."""
        query = select(Scan).where(
            Scan.status.in_([
                ScanStatus.RUNNING.value,
                ScanStatus.INITIALIZING.value,
                ScanStatus.QUEUED.value
            ])
        )

        if tenant_id:
            query = query.where(Scan.tenant_id == tenant_id)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_resumable_scans(self, tenant_id: str) -> List[Scan]:
        """Get scans that can be resumed."""
        result = await self.session.execute(
            select(Scan)
            .where(
                and_(
                    Scan.tenant_id == tenant_id,
                    Scan.checkpoint.isnot(None),
                    Scan.status.in_([
                        ScanStatus.FAILED.value,
                        ScanStatus.TIMEOUT.value,
                        ScanStatus.PAUSED.value
                    ])
                )
            )
            .order_by(desc(Scan.created_at))
        )
        return list(result.scalars().all())

    async def update(self, scan_id: str, **kwargs) -> Optional[Scan]:
        """Update scan fields."""
        await self.session.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(**kwargs)
        )
        return await self.get_by_id(scan_id)

    async def update_status(
        self,
        scan_id: str,
        status: str,
        progress: Optional[int] = None,
        phase: Optional[str] = None,
        error_message: Optional[str] = None
    ) -> None:
        """Update scan status and related fields."""
        values: Dict[str, Any] = {"status": status}

        if progress is not None:
            values["progress"] = progress
        if phase is not None:
            values["phase"] = phase
        if error_message is not None:
            values["error_message"] = error_message

        # Set timestamps based on status
        if status == ScanStatus.RUNNING.value:
            values["started_at"] = datetime.utcnow()
        elif status in [ScanStatus.COMPLETED.value, ScanStatus.FAILED.value,
                        ScanStatus.CANCELLED.value, ScanStatus.TIMEOUT.value]:
            values["completed_at"] = datetime.utcnow()

        await self.session.execute(
            update(Scan).where(Scan.id == scan_id).values(**values)
        )
        logger.info(f"Updated scan status: {scan_id} -> {status}", scan_id=scan_id, status=status)

    async def save_checkpoint(
        self,
        scan_id: str,
        checkpoint_data: Dict,
        phase: str
    ) -> None:
        """Save scan checkpoint for resume capability."""
        await self.session.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(
                checkpoint=checkpoint_data,
                checkpoint_phase=phase,
                checkpoint_at=datetime.utcnow()
            )
        )
        logger.info(f"Saved checkpoint for scan: {scan_id}", scan_id=scan_id, phase=phase)

    async def clear_checkpoint(self, scan_id: str) -> None:
        """Clear scan checkpoint after successful completion."""
        await self.session.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(
                checkpoint=None,
                checkpoint_phase=None,
                checkpoint_at=None
            )
        )

    async def update_results(
        self,
        scan_id: str,
        overall_score: int,
        findings_count: int,
        severity_counts: Dict[str, int],
        framework_scores: Optional[Dict] = None
    ) -> None:
        """Update scan results summary."""
        await self.session.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(
                overall_score=overall_score,
                findings_count=findings_count,
                critical_count=severity_counts.get("critical", 0),
                high_count=severity_counts.get("high", 0),
                medium_count=severity_counts.get("medium", 0),
                low_count=severity_counts.get("low", 0),
                info_count=severity_counts.get("info", 0),
                framework_scores=framework_scores or {}
            )
        )

    async def get_stats(
        self,
        tenant_id: str,
        days: int = 30
    ) -> Dict[str, Any]:
        """Get scan statistics for a tenant."""
        since = datetime.utcnow() - timedelta(days=days)

        # Total scans
        total_result = await self.session.execute(
            select(func.count(Scan.id))
            .where(and_(
                Scan.tenant_id == tenant_id,
                Scan.created_at >= since
            ))
        )
        total_scans = total_result.scalar() or 0

        # Scans by status
        status_result = await self.session.execute(
            select(Scan.status, func.count(Scan.id))
            .where(and_(
                Scan.tenant_id == tenant_id,
                Scan.created_at >= since
            ))
            .group_by(Scan.status)
        )
        status_counts = dict(status_result.all())

        # Average score
        score_result = await self.session.execute(
            select(func.avg(Scan.overall_score))
            .where(and_(
                Scan.tenant_id == tenant_id,
                Scan.overall_score.isnot(None),
                Scan.created_at >= since
            ))
        )
        avg_score = score_result.scalar() or 0

        return {
            "total_scans": total_scans,
            "status_breakdown": status_counts,
            "average_score": round(avg_score, 1),
            "period_days": days
        }

    async def delete(self, scan_id: str) -> bool:
        """Delete a scan and all related data."""
        result = await self.session.execute(
            delete(Scan).where(Scan.id == scan_id)
        )
        return result.rowcount > 0


# =============================================================================
# Finding Repository
# =============================================================================


class FindingRepository(BaseRepository):
    """Repository for Finding operations."""

    async def create(
        self,
        scan_id: str,
        check_id: str,
        category: str,
        title: str,
        severity: str,
        description: Optional[str] = None,
        evidence: Optional[str] = None,
        remediation: Optional[str] = None,
        url: Optional[str] = None,
        parameter: Optional[str] = None,
        method: Optional[str] = None,
        cwe: Optional[str] = None,
        owasp: Optional[str] = None,
        cvss_score: Optional[float] = None
    ) -> Finding:
        """Create a new finding."""
        finding = Finding(
            scan_id=scan_id,
            check_id=check_id,
            category=category,
            title=title,
            severity=severity,
            description=description,
            evidence=evidence,
            remediation=remediation,
            url=url,
            parameter=parameter,
            method=method,
            cwe=cwe,
            owasp=owasp,
            cvss_score=cvss_score
        )
        self.session.add(finding)
        await self.session.flush()
        logger.info(
            f"Created finding: {finding.id}",
            finding_id=finding.id,
            scan_id=scan_id,
            severity=severity
        )
        return finding

    async def create_batch(self, findings_data: List[Dict]) -> List[Finding]:
        """Create multiple findings in a batch."""
        findings = [Finding(**data) for data in findings_data]
        self.session.add_all(findings)
        await self.session.flush()
        logger.info(f"Created {len(findings)} findings in batch")
        return findings

    async def get_by_id(self, finding_id: str) -> Optional[Finding]:
        """Get finding by ID."""
        result = await self.session.execute(
            select(Finding).where(Finding.id == finding_id)
        )
        return result.scalar_one_or_none()

    async def get_by_scan(
        self,
        scan_id: str,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        include_false_positives: bool = False,
        limit: int = 500
    ) -> List[Finding]:
        """Get findings for a scan with optional filtering."""
        query = select(Finding).where(Finding.scan_id == scan_id)

        if severity:
            query = query.where(Finding.severity == severity)
        if category:
            query = query.where(Finding.category == category)
        if not include_false_positives:
            query = query.where(Finding.false_positive == False)

        # Order by severity (critical first)
        severity_order = [
            Severity.CRITICAL.value,
            Severity.HIGH.value,
            Severity.MEDIUM.value,
            Severity.LOW.value,
            Severity.INFO.value
        ]
        query = query.order_by(
            func.array_position(severity_order, Finding.severity)
        ).limit(limit)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_severity_counts(self, scan_id: str) -> Dict[str, int]:
        """Get finding counts by severity for a scan."""
        result = await self.session.execute(
            select(Finding.severity, func.count(Finding.id))
            .where(and_(
                Finding.scan_id == scan_id,
                Finding.false_positive == False
            ))
            .group_by(Finding.severity)
        )
        return dict(result.all())

    async def mark_false_positive(
        self,
        finding_id: str,
        is_false_positive: bool = True
    ) -> Optional[Finding]:
        """Mark a finding as false positive."""
        await self.session.execute(
            update(Finding)
            .where(Finding.id == finding_id)
            .values(false_positive=is_false_positive)
        )
        return await self.get_by_id(finding_id)

    async def mark_resolved(
        self,
        finding_id: str,
        resolved_by: str
    ) -> Optional[Finding]:
        """Mark a finding as resolved."""
        await self.session.execute(
            update(Finding)
            .where(Finding.id == finding_id)
            .values(
                resolved=True,
                resolved_at=datetime.utcnow(),
                resolved_by=resolved_by
            )
        )
        return await self.get_by_id(finding_id)

    async def get_unique_checks(self, scan_id: str) -> List[str]:
        """Get unique check IDs for a scan."""
        result = await self.session.execute(
            select(Finding.check_id)
            .where(Finding.scan_id == scan_id)
            .distinct()
        )
        return [row[0] for row in result.all()]


# =============================================================================
# Scan Event Repository
# =============================================================================


class ScanEventRepository(BaseRepository):
    """Repository for ScanEvent operations."""

    async def create(
        self,
        scan_id: str,
        event_type: str,
        message: Optional[str] = None,
        data: Optional[Dict] = None,
        screenshot_url: Optional[str] = None,
        phase: Optional[str] = None,
        progress: Optional[int] = None
    ) -> ScanEvent:
        """Create a new scan event."""
        event = ScanEvent(
            scan_id=scan_id,
            event_type=event_type,
            message=message,
            data=data or {},
            screenshot_url=screenshot_url,
            phase=phase,
            progress=progress
        )
        self.session.add(event)
        await self.session.flush()
        return event

    async def get_by_scan(
        self,
        scan_id: str,
        event_type: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 100
    ) -> List[ScanEvent]:
        """Get events for a scan."""
        query = select(ScanEvent).where(ScanEvent.scan_id == scan_id)

        if event_type:
            query = query.where(ScanEvent.event_type == event_type)
        if since:
            query = query.where(ScanEvent.created_at > since)

        query = query.order_by(desc(ScanEvent.created_at)).limit(limit)

        result = await self.session.execute(query)
        return list(result.scalars().all())

    async def get_latest(self, scan_id: str) -> Optional[ScanEvent]:
        """Get the latest event for a scan."""
        result = await self.session.execute(
            select(ScanEvent)
            .where(ScanEvent.scan_id == scan_id)
            .order_by(desc(ScanEvent.created_at))
            .limit(1)
        )
        return result.scalar_one_or_none()


# =============================================================================
# Report Repository
# =============================================================================


class ReportRepository(BaseRepository):
    """Repository for Report operations."""

    async def create(
        self,
        scan_id: str,
        format: str,
        storage_url: Optional[str] = None,
        storage_path: Optional[str] = None,
        file_size: Optional[int] = None,
        expires_at: Optional[datetime] = None
    ) -> Report:
        """Create a new report record."""
        report = Report(
            scan_id=scan_id,
            format=format,
            storage_url=storage_url,
            storage_path=storage_path,
            file_size=file_size,
            expires_at=expires_at
        )
        self.session.add(report)
        await self.session.flush()
        await self.session.refresh(report)
        return report

    async def get_by_scan(self, scan_id: str) -> List[Report]:
        """Get all reports for a scan."""
        result = await self.session.execute(
            select(Report)
            .where(Report.scan_id == scan_id)
            .order_by(desc(Report.generated_at))
        )
        return list(result.scalars().all())

    async def get_by_id(self, report_id: str) -> Optional[Report]:
        """Get report by ID."""
        result = await self.session.execute(
            select(Report).where(Report.id == report_id)
        )
        return result.scalar_one_or_none()


# =============================================================================
# Webhook Repository
# =============================================================================


class WebhookRepository(BaseRepository):
    """Repository for Webhook operations."""

    async def create(
        self,
        tenant_id: str,
        name: str,
        url: str,
        secret_hash: str,
        events: List[str]
    ) -> Webhook:
        """Create a new webhook."""
        webhook = Webhook(
            tenant_id=tenant_id,
            name=name,
            url=url,
            secret_hash=secret_hash,
            events=events
        )
        self.session.add(webhook)
        await self.session.flush()
        await self.session.refresh(webhook)
        return webhook

    async def get_by_tenant(self, tenant_id: str) -> List[Webhook]:
        """Get all webhooks for a tenant."""
        result = await self.session.execute(
            select(Webhook)
            .where(Webhook.tenant_id == tenant_id)
            .order_by(desc(Webhook.created_at))
        )
        return list(result.scalars().all())

    async def get_active_for_event(
        self,
        tenant_id: str,
        event_type: str
    ) -> List[Webhook]:
        """Get active webhooks that listen for a specific event."""
        result = await self.session.execute(
            select(Webhook)
            .where(and_(
                Webhook.tenant_id == tenant_id,
                Webhook.is_active == True,
                Webhook.events.contains([event_type])
            ))
        )
        return list(result.scalars().all())

    async def update_trigger_status(
        self,
        webhook_id: str,
        status_code: int,
        success: bool
    ) -> None:
        """Update webhook after trigger attempt."""
        values = {
            "last_triggered_at": datetime.utcnow(),
            "last_status_code": status_code
        }

        if not success:
            values["failure_count"] = Webhook.failure_count + 1
        else:
            values["failure_count"] = 0

        await self.session.execute(
            update(Webhook)
            .where(Webhook.id == webhook_id)
            .values(**values)
        )


# =============================================================================
# API Call Log Repository
# =============================================================================


class APICallLogRepository(BaseRepository):
    """Repository for APICallLog operations."""

    async def create_batch(self, calls_data: List[Dict]) -> int:
        """Create multiple API call logs in a batch."""
        logs = [APICallLog(**data) for data in calls_data]
        self.session.add_all(logs)
        await self.session.flush()
        return len(logs)

    async def get_by_scan(
        self,
        scan_id: str,
        path_filter: Optional[str] = None,
        limit: int = 200
    ) -> List[APICallLog]:
        """Get API calls for a scan."""
        query = select(APICallLog).where(APICallLog.scan_id == scan_id)

        if path_filter:
            query = query.where(APICallLog.path.ilike(f"%{path_filter}%"))

        query = query.order_by(desc(APICallLog.captured_at)).limit(limit)

        result = await self.session.execute(query)
        return list(result.scalars().all())


# =============================================================================
# Journey Repository
# =============================================================================


class JourneyRepository(BaseRepository):
    """Repository for Journey operations."""

    async def create(
        self,
        scan_id: str,
        name: str,
        journey_type: Optional[str] = None,
        description: Optional[str] = None,
        start_url: Optional[str] = None
    ) -> Journey:
        """Create a new journey."""
        journey = Journey(
            scan_id=scan_id,
            name=name,
            journey_type=journey_type,
            description=description,
            start_url=start_url
        )
        self.session.add(journey)
        await self.session.flush()
        await self.session.refresh(journey)
        return journey

    async def get_by_scan(self, scan_id: str) -> List[Journey]:
        """Get all journeys for a scan."""
        result = await self.session.execute(
            select(Journey)
            .where(Journey.scan_id == scan_id)
            .order_by(Journey.created_at)
        )
        return list(result.scalars().all())

    async def update_steps(
        self,
        journey_id: str,
        steps: List[Dict],
        status: Optional[str] = None
    ) -> None:
        """Update journey steps."""
        values = {"steps": steps}
        if status:
            values["status"] = status

        await self.session.execute(
            update(Journey)
            .where(Journey.id == journey_id)
            .values(**values)
        )
