"""
NEXUS QA - Base Security Checker
Base class for all security check modules.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import aiohttp
import re
from datetime import datetime

from ...models.security import (
    SecurityCategory,
    SecurityCheck,
    CheckResult,
    CheckStatus,
    CheckType,
    Accuracy,
    Severity
)


@dataclass
class ScanContext:
    """Context information gathered during scanning."""
    url: str
    base_url: str
    html_content: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, Any] = field(default_factory=dict)
    forms: List[Dict] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    meta_tags: Dict[str, str] = field(default_factory=dict)
    response_time: float = 0.0
    status_code: int = 0
    content_type: str = ""
    server_info: str = ""
    tls_info: Dict[str, Any] = field(default_factory=dict)
    api_endpoints: List[str] = field(default_factory=list)
    storage_items: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_https(self) -> bool:
        return self.url.startswith("https://")


class BaseSecurityChecker(ABC):
    """Base class for security check modules."""

    category: SecurityCategory
    category_name: str
    checks: List[SecurityCheck] = []

    def __init__(self):
        self.results: List[CheckResult] = []

    @abstractmethod
    async def run_checks(self, context: ScanContext) -> List[CheckResult]:
        """Run all checks in this category."""
        pass

    def create_result(
        self,
        check: SecurityCheck,
        status: CheckStatus,
        message: str,
        evidence: Optional[str] = None,
        details: Optional[Dict] = None
    ) -> CheckResult:
        """Create a check result with feature flags."""
        return CheckResult(
            check_id=check.id,
            check_name=check.name,
            category=self.category,
            status=status,
            severity=check.severity,
            message=message,
            evidence=evidence,
            remediation=check.remediation if status == CheckStatus.FAIL else None,
            details=details or {},
            timestamp=datetime.now(),
            # Pass through feature flags from check definition
            check_type=check.check_type,
            accuracy=check.accuracy,
            requires_ai=check.requires_ai,
            can_verify=check.can_verify,
            method=check.method
        )

    def pass_check(self, check: SecurityCheck, message: str = "Check passed") -> CheckResult:
        """Create a passing result."""
        return self.create_result(check, CheckStatus.PASS, message)

    def fail_check(
        self,
        check: SecurityCheck,
        message: str,
        evidence: Optional[str] = None,
        details: Optional[Dict] = None
    ) -> CheckResult:
        """Create a failing result."""
        return self.create_result(check, CheckStatus.FAIL, message, evidence, details)

    def warn_check(
        self,
        check: SecurityCheck,
        message: str,
        evidence: Optional[str] = None
    ) -> CheckResult:
        """Create a warning result."""
        return self.create_result(check, CheckStatus.WARN, message, evidence)

    def skip_check(self, check: SecurityCheck, reason: str) -> CheckResult:
        """Create a skipped result."""
        return self.create_result(check, CheckStatus.SKIP, f"Skipped: {reason}")

    # Utility methods for checks

    def find_in_content(self, content: str, patterns: List[str]) -> List[str]:
        """Find patterns in content."""
        matches = []
        for pattern in patterns:
            found = re.findall(pattern, content, re.IGNORECASE)
            matches.extend(found)
        return matches

    def check_header(self, headers: Dict[str, str], header_name: str) -> Optional[str]:
        """Get header value (case-insensitive)."""
        for key, value in headers.items():
            if key.lower() == header_name.lower():
                return value
        return None

    def has_header(self, headers: Dict[str, str], header_name: str) -> bool:
        """Check if header exists."""
        return self.check_header(headers, header_name) is not None

    async def fetch_url(
        self,
        url: str,
        method: str = "GET",
        timeout: int = 10
    ) -> Optional[aiohttp.ClientResponse]:
        """Fetch a URL for testing."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method,
                    url,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False
                ) as response:
                    return response
        except Exception:
            return None

    def extract_sensitive_patterns(self, content: str) -> Dict[str, List[str]]:
        """Extract potentially sensitive data patterns."""
        patterns = {
            'emails': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phones': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_cards': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            'api_keys': r'(?:api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_-]{20,})',
            'jwt_tokens': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
            'aws_keys': r'AKIA[0-9A-Z]{16}',
            'private_keys': r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
        }

        results = {}
        for name, pattern in patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                results[name] = matches[:5]  # Limit to 5 matches

        return results
