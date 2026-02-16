"""
NEXUS QA Structured Logging

Production-ready logging with JSON output, correlation IDs,
and integration with observability tools.
"""

import sys
import json
import logging
import traceback
from datetime import datetime
from typing import Any, Dict, Optional
from contextvars import ContextVar
from functools import wraps
import time

# Context variables for request tracking
correlation_id_var: ContextVar[Optional[str]] = ContextVar("correlation_id", default=None)
request_id_var: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
tenant_id_var: ContextVar[Optional[str]] = ContextVar("tenant_id", default=None)
user_id_var: ContextVar[Optional[str]] = ContextVar("user_id", default=None)
scan_id_var: ContextVar[Optional[str]] = ContextVar("scan_id", default=None)


class JSONFormatter(logging.Formatter):
    """JSON log formatter for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add context variables
        if correlation_id := correlation_id_var.get():
            log_entry["correlation_id"] = correlation_id
        if request_id := request_id_var.get():
            log_entry["request_id"] = request_id
        if tenant_id := tenant_id_var.get():
            log_entry["tenant_id"] = tenant_id
        if user_id := user_id_var.get():
            log_entry["user_id"] = user_id
        if scan_id := scan_id_var.get():
            log_entry["scan_id"] = scan_id

        # Add extra fields
        if hasattr(record, "extra_fields"):
            log_entry.update(record.extra_fields)

        # Add exception info
        if record.exc_info:
            log_entry["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]) if record.exc_info[1] else None,
                "traceback": traceback.format_exception(*record.exc_info),
            }

        return json.dumps(log_entry)


class TextFormatter(logging.Formatter):
    """Human-readable text formatter for development."""

    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
        "RESET": "\033[0m",
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        reset = self.COLORS["RESET"]

        # Build context string
        context_parts = []
        if correlation_id := correlation_id_var.get():
            context_parts.append(f"corr={correlation_id[:8]}")
        if scan_id := scan_id_var.get():
            context_parts.append(f"scan={scan_id[:12]}")

        context_str = f" [{', '.join(context_parts)}]" if context_parts else ""

        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

        # Format main message
        message = f"{timestamp} {color}{record.levelname:8}{reset} {record.name}{context_str}: {record.getMessage()}"

        # Add exception
        if record.exc_info:
            message += "\n" + "".join(traceback.format_exception(*record.exc_info))

        return message


class NexusLogger(logging.Logger):
    """Custom logger with extra field support."""

    def _log_with_extra(
        self,
        level: int,
        msg: str,
        args: tuple,
        exc_info: Any = None,
        extra: Optional[Dict] = None,
        **kwargs
    ):
        if extra is None:
            extra = {}

        # Merge kwargs into extra fields
        extra_fields = {**kwargs}
        extra["extra_fields"] = extra_fields

        super()._log(level, msg, args, exc_info=exc_info, extra=extra)

    def debug(self, msg: str, *args, **kwargs):
        self._log_with_extra(logging.DEBUG, msg, args, **kwargs)

    def info(self, msg: str, *args, **kwargs):
        self._log_with_extra(logging.INFO, msg, args, **kwargs)

    def warning(self, msg: str, *args, **kwargs):
        self._log_with_extra(logging.WARNING, msg, args, **kwargs)

    def error(self, msg: str, *args, exc_info: bool = True, **kwargs):
        self._log_with_extra(logging.ERROR, msg, args, exc_info=exc_info, **kwargs)

    def critical(self, msg: str, *args, exc_info: bool = True, **kwargs):
        self._log_with_extra(logging.CRITICAL, msg, args, exc_info=exc_info, **kwargs)

    def audit(self, action: str, resource: str, **kwargs):
        """Log audit events."""
        self.info(
            f"AUDIT: {action} on {resource}",
            action=action,
            resource=resource,
            audit=True,
            **kwargs
        )

    def metric(self, name: str, value: float, unit: str = "", **tags):
        """Log metrics."""
        self.info(
            f"METRIC: {name}={value}{unit}",
            metric_name=name,
            metric_value=value,
            metric_unit=unit,
            metric_tags=tags,
        )


# Set custom logger class
logging.setLoggerClass(NexusLogger)


def setup_logging(
    level: str = "INFO",
    format: str = "json",
    log_file: Optional[str] = None
) -> None:
    """
    Set up logging configuration.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format: Output format (json, text)
        log_file: Optional file path for logging
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper()))

    # Clear existing handlers
    root_logger.handlers.clear()

    # Choose formatter
    if format == "json":
        formatter = JSONFormatter()
    else:
        formatter = TextFormatter()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(JSONFormatter())  # Always JSON for files
        root_logger.addHandler(file_handler)

    # Suppress noisy loggers
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    logging.getLogger("playwright").setLevel(logging.WARNING)


def get_logger(name: str) -> NexusLogger:
    """Get a logger instance."""
    return logging.getLogger(name)


def set_correlation_id(correlation_id: str) -> None:
    """Set correlation ID for request tracking."""
    correlation_id_var.set(correlation_id)


def set_request_context(
    request_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    user_id: Optional[str] = None,
    scan_id: Optional[str] = None,
) -> None:
    """Set request context for logging."""
    if request_id:
        request_id_var.set(request_id)
    if correlation_id:
        correlation_id_var.set(correlation_id)
    if tenant_id:
        tenant_id_var.set(tenant_id)
    if user_id:
        user_id_var.set(user_id)
    if scan_id:
        scan_id_var.set(scan_id)


def clear_request_context() -> None:
    """Clear request context."""
    request_id_var.set(None)
    correlation_id_var.set(None)
    tenant_id_var.set(None)
    user_id_var.set(None)
    scan_id_var.set(None)


def log_execution_time(logger: Optional[NexusLogger] = None):
    """Decorator to log function execution time."""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            nonlocal logger
            if logger is None:
                logger = get_logger(func.__module__)

            start = time.perf_counter()
            try:
                result = await func(*args, **kwargs)
                elapsed = (time.perf_counter() - start) * 1000
                logger.info(
                    f"{func.__name__} completed",
                    function=func.__name__,
                    duration_ms=round(elapsed, 2),
                    status="success"
                )
                return result
            except Exception as e:
                elapsed = (time.perf_counter() - start) * 1000
                logger.error(
                    f"{func.__name__} failed: {str(e)}",
                    function=func.__name__,
                    duration_ms=round(elapsed, 2),
                    status="error",
                    error_type=type(e).__name__
                )
                raise

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            nonlocal logger
            if logger is None:
                logger = get_logger(func.__module__)

            start = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                elapsed = (time.perf_counter() - start) * 1000
                logger.info(
                    f"{func.__name__} completed",
                    function=func.__name__,
                    duration_ms=round(elapsed, 2),
                    status="success"
                )
                return result
            except Exception as e:
                elapsed = (time.perf_counter() - start) * 1000
                logger.error(
                    f"{func.__name__} failed: {str(e)}",
                    function=func.__name__,
                    duration_ms=round(elapsed, 2),
                    status="error",
                    error_type=type(e).__name__
                )
                raise

        import asyncio
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return sync_wrapper

    return decorator
