"""
NEXUS QA Custom Exceptions

Structured exception hierarchy with error codes, context,
and proper error response formatting.
"""

from typing import Any, Dict, Optional
from enum import Enum


class ErrorCode(str, Enum):
    """Standardized error codes."""

    # General errors (1xxx)
    INTERNAL_ERROR = "E1000"
    VALIDATION_ERROR = "E1001"
    NOT_FOUND = "E1002"
    RATE_LIMITED = "E1003"
    UNAUTHORIZED = "E1004"
    FORBIDDEN = "E1005"
    CONFLICT = "E1006"
    BAD_REQUEST = "E1007"

    # Database errors (2xxx)
    DATABASE_ERROR = "E2000"
    DATABASE_CONNECTION = "E2001"
    DATABASE_TIMEOUT = "E2002"
    DATABASE_INTEGRITY = "E2003"
    DATABASE_NOT_FOUND = "E2004"

    # Scan errors (3xxx)
    SCAN_ERROR = "E3000"
    SCAN_TIMEOUT = "E3001"
    SCAN_FAILED = "E3002"
    SCAN_NOT_FOUND = "E3003"
    SCAN_ALREADY_RUNNING = "E3004"
    SCAN_CANCELLED = "E3005"
    SCAN_INVALID_URL = "E3006"
    SCAN_SSRF_BLOCKED = "E3007"

    # Agent errors (4xxx)
    AGENT_ERROR = "E4000"
    AGENT_TIMEOUT = "E4001"
    AGENT_FAILED = "E4002"
    AGENT_NOT_READY = "E4003"
    AGENT_COMMUNICATION = "E4004"

    # Browser errors (5xxx)
    BROWSER_ERROR = "E5000"
    BROWSER_LAUNCH_FAILED = "E5001"
    BROWSER_NAVIGATION_FAILED = "E5002"
    BROWSER_TIMEOUT = "E5003"
    BROWSER_POOL_EXHAUSTED = "E5004"

    # LLM errors (6xxx)
    LLM_ERROR = "E6000"
    LLM_TIMEOUT = "E6001"
    LLM_RATE_LIMITED = "E6002"
    LLM_INVALID_RESPONSE = "E6003"
    LLM_QUOTA_EXCEEDED = "E6004"

    # Storage errors (7xxx)
    STORAGE_ERROR = "E7000"
    STORAGE_UPLOAD_FAILED = "E7001"
    STORAGE_DOWNLOAD_FAILED = "E7002"
    STORAGE_NOT_FOUND = "E7003"

    # Authentication errors (8xxx)
    AUTH_ERROR = "E8000"
    AUTH_INVALID_TOKEN = "E8001"
    AUTH_EXPIRED_TOKEN = "E8002"
    AUTH_INVALID_API_KEY = "E8003"
    AUTH_SSO_FAILED = "E8004"

    # Integration errors (9xxx)
    INTEGRATION_ERROR = "E9000"
    WEBHOOK_FAILED = "E9001"
    NOTIFICATION_FAILED = "E9002"


class NexusException(Exception):
    """Base exception for all NEXUS QA errors."""

    def __init__(
        self,
        message: str,
        code: ErrorCode = ErrorCode.INTERNAL_ERROR,
        status_code: int = 500,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
        recoverable: bool = False,
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or {}
        self.cause = cause
        self.recoverable = recoverable

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to API response format."""
        response = {
            "error": {
                "code": self.code.value,
                "message": self.message,
                "recoverable": self.recoverable,
            }
        }
        if self.details:
            response["error"]["details"] = self.details
        return response

    def __str__(self) -> str:
        return f"[{self.code.value}] {self.message}"


# =============================================================================
# Database Exceptions
# =============================================================================


class DatabaseError(NexusException):
    """Database operation error."""

    def __init__(
        self,
        message: str = "Database operation failed",
        code: ErrorCode = ErrorCode.DATABASE_ERROR,
        **kwargs
    ):
        super().__init__(message, code=code, status_code=500, **kwargs)


class DatabaseConnectionError(DatabaseError):
    """Database connection error."""

    def __init__(self, message: str = "Failed to connect to database", **kwargs):
        super().__init__(message, code=ErrorCode.DATABASE_CONNECTION, **kwargs)


class DatabaseNotFoundError(DatabaseError):
    """Record not found in database."""

    def __init__(self, resource: str, resource_id: str, **kwargs):
        message = f"{resource} with ID '{resource_id}' not found"
        super().__init__(
            message,
            code=ErrorCode.DATABASE_NOT_FOUND,
            status_code=404,
            details={"resource": resource, "id": resource_id},
            **kwargs
        )


# =============================================================================
# Scan Exceptions
# =============================================================================


class ScanError(NexusException):
    """Scan operation error."""

    def __init__(
        self,
        message: str = "Scan operation failed",
        scan_id: Optional[str] = None,
        code: ErrorCode = ErrorCode.SCAN_ERROR,
        **kwargs
    ):
        details = kwargs.pop("details", {})
        if scan_id:
            details["scan_id"] = scan_id
        super().__init__(message, code=code, status_code=500, details=details, **kwargs)


class ScanTimeoutError(ScanError):
    """Scan timed out."""

    def __init__(
        self,
        scan_id: str,
        timeout_seconds: int,
        phase: Optional[str] = None,
        **kwargs
    ):
        message = f"Scan timed out after {timeout_seconds} seconds"
        if phase:
            message += f" in phase '{phase}'"
        super().__init__(
            message,
            scan_id=scan_id,
            code=ErrorCode.SCAN_TIMEOUT,
            recoverable=True,
            details={"timeout_seconds": timeout_seconds, "phase": phase},
            **kwargs
        )


class ScanNotFoundError(ScanError):
    """Scan not found."""

    def __init__(self, scan_id: str, **kwargs):
        super().__init__(
            f"Scan '{scan_id}' not found",
            scan_id=scan_id,
            code=ErrorCode.SCAN_NOT_FOUND,
            status_code=404,
            **kwargs
        )


class ScanSSRFBlockedError(ScanError):
    """SSRF attack blocked."""

    def __init__(self, url: str, **kwargs):
        super().__init__(
            f"URL blocked: targets internal or restricted resources",
            code=ErrorCode.SCAN_SSRF_BLOCKED,
            status_code=400,
            details={"blocked_url": url[:100]},  # Truncate for safety
            **kwargs
        )


class ScanAlreadyRunningError(ScanError):
    """Scan already in progress."""

    def __init__(self, scan_id: str, **kwargs):
        super().__init__(
            f"Scan '{scan_id}' is already running",
            scan_id=scan_id,
            code=ErrorCode.SCAN_ALREADY_RUNNING,
            status_code=409,
            **kwargs
        )


# =============================================================================
# Agent Exceptions
# =============================================================================


class AgentError(NexusException):
    """Agent operation error."""

    def __init__(
        self,
        message: str = "Agent operation failed",
        agent_name: Optional[str] = None,
        code: ErrorCode = ErrorCode.AGENT_ERROR,
        **kwargs
    ):
        details = kwargs.pop("details", {})
        if agent_name:
            details["agent"] = agent_name
        super().__init__(message, code=code, status_code=500, details=details, **kwargs)


class AgentTimeoutError(AgentError):
    """Agent timed out."""

    def __init__(
        self,
        agent_name: str,
        timeout_seconds: int,
        **kwargs
    ):
        super().__init__(
            f"Agent '{agent_name}' timed out after {timeout_seconds} seconds",
            agent_name=agent_name,
            code=ErrorCode.AGENT_TIMEOUT,
            recoverable=True,
            **kwargs
        )


# =============================================================================
# Browser Exceptions
# =============================================================================


class BrowserError(NexusException):
    """Browser automation error."""

    def __init__(
        self,
        message: str = "Browser operation failed",
        code: ErrorCode = ErrorCode.BROWSER_ERROR,
        **kwargs
    ):
        super().__init__(message, code=code, status_code=500, **kwargs)


class BrowserLaunchError(BrowserError):
    """Failed to launch browser."""

    def __init__(self, reason: str = "Unknown", **kwargs):
        super().__init__(
            f"Failed to launch browser: {reason}",
            code=ErrorCode.BROWSER_LAUNCH_FAILED,
            **kwargs
        )


class BrowserNavigationError(BrowserError):
    """Failed to navigate to URL."""

    def __init__(self, url: str, reason: str = "Unknown", **kwargs):
        super().__init__(
            f"Failed to navigate to URL: {reason}",
            code=ErrorCode.BROWSER_NAVIGATION_FAILED,
            details={"url": url[:200]},
            recoverable=True,
            **kwargs
        )


class BrowserPoolExhaustedError(BrowserError):
    """No available browsers in pool."""

    def __init__(self, **kwargs):
        super().__init__(
            "No available browsers in pool. Try again later.",
            code=ErrorCode.BROWSER_POOL_EXHAUSTED,
            status_code=503,
            recoverable=True,
            **kwargs
        )


# =============================================================================
# LLM Exceptions
# =============================================================================


class LLMError(NexusException):
    """LLM API error."""

    def __init__(
        self,
        message: str = "LLM operation failed",
        provider: Optional[str] = None,
        code: ErrorCode = ErrorCode.LLM_ERROR,
        **kwargs
    ):
        details = kwargs.pop("details", {})
        if provider:
            details["provider"] = provider
        super().__init__(message, code=code, status_code=500, details=details, **kwargs)


class LLMTimeoutError(LLMError):
    """LLM API timed out."""

    def __init__(self, provider: str, **kwargs):
        super().__init__(
            f"LLM API timed out ({provider})",
            provider=provider,
            code=ErrorCode.LLM_TIMEOUT,
            recoverable=True,
            **kwargs
        )


class LLMRateLimitedError(LLMError):
    """LLM API rate limited."""

    def __init__(
        self,
        provider: str,
        retry_after: Optional[int] = None,
        **kwargs
    ):
        message = f"LLM API rate limited ({provider})"
        if retry_after:
            message += f". Retry after {retry_after} seconds."
        super().__init__(
            message,
            provider=provider,
            code=ErrorCode.LLM_RATE_LIMITED,
            recoverable=True,
            details={"retry_after": retry_after},
            **kwargs
        )


# =============================================================================
# Authentication Exceptions
# =============================================================================


class AuthError(NexusException):
    """Authentication/authorization error."""

    def __init__(
        self,
        message: str = "Authentication failed",
        code: ErrorCode = ErrorCode.AUTH_ERROR,
        **kwargs
    ):
        super().__init__(message, code=code, status_code=401, **kwargs)


class InvalidAPIKeyError(AuthError):
    """Invalid API key."""

    def __init__(self, **kwargs):
        super().__init__(
            "Invalid or missing API key",
            code=ErrorCode.AUTH_INVALID_API_KEY,
            **kwargs
        )


class TokenExpiredError(AuthError):
    """Token expired."""

    def __init__(self, **kwargs):
        super().__init__(
            "Authentication token has expired",
            code=ErrorCode.AUTH_EXPIRED_TOKEN,
            **kwargs
        )


# =============================================================================
# Rate Limiting Exceptions
# =============================================================================


class RateLimitError(NexusException):
    """Rate limit exceeded."""

    def __init__(
        self,
        limit: int,
        window: int,
        retry_after: Optional[int] = None,
        **kwargs
    ):
        message = f"Rate limit exceeded ({limit} requests per {window} seconds)"
        super().__init__(
            message,
            code=ErrorCode.RATE_LIMITED,
            status_code=429,
            details={
                "limit": limit,
                "window": window,
                "retry_after": retry_after,
            },
            recoverable=True,
            **kwargs
        )


# =============================================================================
# Validation Exceptions
# =============================================================================


class ValidationError(NexusException):
    """Input validation error."""

    def __init__(
        self,
        message: str = "Validation failed",
        field: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.pop("details", {})
        if field:
            details["field"] = field
        super().__init__(
            message,
            code=ErrorCode.VALIDATION_ERROR,
            status_code=400,
            details=details,
            **kwargs
        )
