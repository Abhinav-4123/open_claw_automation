"""
NEXUS QA Celery Configuration

Production-ready Celery setup with Redis broker,
task routing, rate limiting, and monitoring.
"""

from celery import Celery
from kombu import Queue, Exchange

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# Create Celery app
celery_app = Celery(
    "nexus_qa",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)


def configure_celery() -> Celery:
    """Configure Celery with production settings."""

    # Task settings
    celery_app.conf.update(
        # Serialization
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",

        # Timezone
        timezone="UTC",
        enable_utc=True,

        # Task execution settings
        task_acks_late=True,  # Acknowledge after task completes
        task_reject_on_worker_lost=True,
        task_track_started=True,

        # Result backend settings
        result_expires=86400,  # Results expire after 24 hours
        result_extended=True,

        # Worker settings
        worker_prefetch_multiplier=1,  # One task at a time per worker
        worker_concurrency=settings.celery_worker_concurrency,
        worker_max_tasks_per_child=100,  # Restart worker after 100 tasks

        # Task time limits
        task_soft_time_limit=settings.scan_timeout_seconds - 60,  # Soft limit
        task_time_limit=settings.scan_timeout_seconds,  # Hard limit

        # Rate limiting
        task_default_rate_limit=settings.celery_task_rate_limit,

        # Retry settings
        task_default_retry_delay=30,
        task_max_retries=3,

        # Queues
        task_queues=(
            Queue("default", Exchange("default"), routing_key="default"),
            Queue("scans", Exchange("scans"), routing_key="scan.#"),
            Queue("reports", Exchange("reports"), routing_key="report.#"),
            Queue("webhooks", Exchange("webhooks"), routing_key="webhook.#"),
            Queue("maintenance", Exchange("maintenance"), routing_key="maintenance.#"),
        ),

        # Task routing
        task_routes={
            "app.queue.tasks.run_scan_task": {"queue": "scans", "routing_key": "scan.run"},
            "app.queue.tasks.resume_scan_task": {"queue": "scans", "routing_key": "scan.resume"},
            "app.queue.tasks.generate_report_task": {"queue": "reports", "routing_key": "report.generate"},
            "app.queue.tasks.trigger_webhooks_task": {"queue": "webhooks", "routing_key": "webhook.trigger"},
            "app.queue.tasks.cleanup_old_scans_task": {"queue": "maintenance", "routing_key": "maintenance.cleanup"},
        },

        # Task annotations for specific tasks
        task_annotations={
            "app.queue.tasks.run_scan_task": {
                "rate_limit": "10/m",  # 10 scans per minute
                "time_limit": settings.scan_timeout_seconds,
            },
            "app.queue.tasks.trigger_webhooks_task": {
                "rate_limit": "100/m",  # 100 webhooks per minute
                "time_limit": 30,
            },
        },

        # Beat scheduler (for periodic tasks)
        beat_schedule={
            "cleanup-old-scans": {
                "task": "app.queue.tasks.cleanup_old_scans_task",
                "schedule": 86400.0,  # Every 24 hours
                "options": {"queue": "maintenance"},
            },
        },
    )

    # Auto-discover tasks
    celery_app.autodiscover_tasks(["app.queue"])

    logger.info(
        "Celery configured",
        broker=settings.celery_broker_url[:30] + "...",
        concurrency=settings.celery_worker_concurrency
    )

    return celery_app


# Celery signals for monitoring
@celery_app.task_prerun.connect
def task_prerun_handler(task_id, task, args, kwargs, **kw):
    """Log when task starts."""
    logger.info(
        f"Task starting: {task.name}",
        task_id=task_id,
        task_name=task.name
    )


@celery_app.task_postrun.connect
def task_postrun_handler(task_id, task, args, kwargs, retval, state, **kw):
    """Log when task completes."""
    logger.info(
        f"Task completed: {task.name}",
        task_id=task_id,
        task_name=task.name,
        state=state
    )


@celery_app.task_failure.connect
def task_failure_handler(task_id, exception, args, kwargs, traceback, einfo, **kw):
    """Log when task fails."""
    logger.error(
        f"Task failed: {exception}",
        task_id=task_id,
        exception_type=type(exception).__name__,
        exc_info=False
    )


# Configure on import
configure_celery()
