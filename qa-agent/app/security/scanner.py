"""
NEXUS QA - Enhanced Security Scanner Orchestrator
Coordinates 80+ security checks across 8 categories.
"""

import asyncio
import aiohttp
from datetime import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse
import json

from .checks import (
    ScanContext,
    DataSecurityChecker,
    CredentialsChecker,
    RateLimitingChecker,
    CacheStorageChecker,
    AuthenticationChecker,
    InjectionChecker,
    InfrastructureChecker,
    BusinessLogicChecker,
)
from ..models.security import (
    SecurityCategory,
    SecurityCheck,
    CheckResult,
    CheckStatus,
    CategoryResult,
    ScanResult,
    Severity,
    Recommendation,
)


@dataclass
class ScanConfig:
    """Configuration for security scan."""
    url: str
    categories: Optional[List[SecurityCategory]] = None  # None = all categories
    timeout: int = 30
    follow_redirects: bool = True
    max_depth: int = 1
    include_subdomains: bool = False
    auth_headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)


class SecurityScanner:
    """
    Enhanced Security Scanner - Orchestrates 80+ security checks.

    Categories:
    1. Data Security (10 checks) - PII, encryption, masking
    2. Credentials & Secrets (10 checks) - tokens, API keys
    3. Rate Limiting (10 checks) - brute force, DDoS
    4. Cache & Storage (10 checks) - localStorage, CDN
    5. Authentication & Authorization (12 checks) - session, RBAC
    6. Injection & Code Execution (12 checks) - SQL, XSS
    7. Infrastructure Security (10 checks) - TLS, headers
    8. Business Logic (8 checks) - workflow, race conditions

    Total: 82 checks
    """

    CHECKERS = {
        SecurityCategory.DATA_SECURITY: DataSecurityChecker,
        SecurityCategory.CREDENTIALS: CredentialsChecker,
        SecurityCategory.RATE_LIMITING: RateLimitingChecker,
        SecurityCategory.CACHE_STORAGE: CacheStorageChecker,
        SecurityCategory.AUTHENTICATION: AuthenticationChecker,
        SecurityCategory.INJECTION: InjectionChecker,
        SecurityCategory.INFRASTRUCTURE: InfrastructureChecker,
        SecurityCategory.BUSINESS_LOGIC: BusinessLogicChecker,
    }

    def __init__(self):
        self.checkers = {
            category: checker_class()
            for category, checker_class in self.CHECKERS.items()
        }
        self._scan_history: List[ScanResult] = []

    @property
    def total_checks(self) -> int:
        """Get total number of available checks."""
        return sum(len(c.checks) for c in self.checkers.values())

    def get_all_checks(self) -> List[SecurityCheck]:
        """Get all available security checks."""
        all_checks = []
        for checker in self.checkers.values():
            all_checks.extend(checker.checks)
        return all_checks

    def get_checks_by_category(self, category: SecurityCategory) -> List[SecurityCheck]:
        """Get checks for a specific category."""
        checker = self.checkers.get(category)
        return checker.checks if checker else []

    def get_categories(self) -> List[Dict[str, Any]]:
        """Get all security categories with metadata."""
        categories = []
        for category, checker in self.checkers.items():
            categories.append({
                "id": category.value,
                "name": checker.category_name,
                "check_count": len(checker.checks),
                "checks": [
                    {
                        "id": c.id,
                        "name": c.name,
                        "severity": c.severity.value,
                        "description": c.description,
                    }
                    for c in checker.checks
                ]
            })
        return categories

    async def fetch_page(
        self,
        url: str,
        config: ScanConfig
    ) -> ScanContext:
        """Fetch page content and build scan context."""
        headers = {
            'User-Agent': 'NEXUS-QA-Scanner/1.0',
            **config.auth_headers
        }

        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=config.timeout)
        ) as session:
            async with session.get(
                url,
                headers=headers,
                cookies=config.cookies,
                allow_redirects=config.follow_redirects,
                ssl=False  # For testing; enable in production
            ) as response:
                html_content = await response.text()

                # Extract cookies from response
                response_cookies = {}
                for cookie in response.cookies.values():
                    response_cookies[cookie.key] = str(cookie)

                # Merge with provided cookies
                all_cookies = {**config.cookies, **response_cookies}

                # Extract links from HTML
                import re
                link_pattern = r'href=["\']([^"\']+)["\']'
                links = re.findall(link_pattern, html_content)

                # Normalize links
                parsed_url = urlparse(url)
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                normalized_links = []
                for link in links:
                    if link.startswith('//'):
                        normalized_links.append(f"{parsed_url.scheme}:{link}")
                    elif link.startswith('/'):
                        normalized_links.append(f"{base_url}{link}")
                    elif link.startswith('http'):
                        normalized_links.append(link)

                return ScanContext(
                    url=str(response.url),
                    base_url=base_url,
                    html_content=html_content,
                    headers=dict(response.headers),
                    cookies=all_cookies,
                    status_code=response.status,
                    links=normalized_links[:100],  # Limit links
                )

    async def run_category(
        self,
        category: SecurityCategory,
        context: ScanContext
    ) -> CategoryResult:
        """Run all checks for a single category."""
        checker = self.checkers.get(category)
        if not checker:
            return CategoryResult(
                category=category,
                category_name="Unknown",
                checks_run=0,
                checks_passed=0,
                checks_failed=0,
                checks_warning=0,
                checks_skipped=0,
                results=[],
                score=0.0
            )

        results = await checker.run_checks(context)

        # Calculate statistics
        passed = sum(1 for r in results if r.status == CheckStatus.PASS)
        failed = sum(1 for r in results if r.status == CheckStatus.FAIL)
        warning = sum(1 for r in results if r.status == CheckStatus.WARN)
        skipped = sum(1 for r in results if r.status == CheckStatus.SKIP)

        # Calculate score (0-100)
        applicable = len(results) - skipped
        if applicable > 0:
            # Weight: PASS=1.0, WARN=0.5, FAIL=0
            score = ((passed * 1.0 + warning * 0.5) / applicable) * 100
        else:
            score = 100.0

        return CategoryResult(
            category=category,
            category_name=checker.category_name,
            checks_run=len(results),
            checks_passed=passed,
            checks_failed=failed,
            checks_warning=warning,
            checks_skipped=skipped,
            results=results,
            score=round(score, 1)
        )

    async def scan(self, config: ScanConfig) -> ScanResult:
        """
        Run a full security scan.

        Args:
            config: Scan configuration

        Returns:
            ScanResult with all category results and recommendations
        """
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        start_time = datetime.now()

        try:
            # Fetch page content
            context = await self.fetch_page(config.url, config)

            # Determine which categories to run
            categories_to_run = config.categories or list(self.CHECKERS.keys())

            # Run all category checks in parallel
            tasks = [
                self.run_category(category, context)
                for category in categories_to_run
            ]
            category_results = await asyncio.gather(*tasks)

            # Calculate overall statistics
            total_passed = sum(r.checks_passed for r in category_results)
            total_failed = sum(r.checks_failed for r in category_results)
            total_warning = sum(r.checks_warning for r in category_results)
            total_skipped = sum(r.checks_skipped for r in category_results)
            total_run = sum(r.checks_run for r in category_results)

            # Calculate overall score
            applicable = total_run - total_skipped
            if applicable > 0:
                overall_score = ((total_passed * 1.0 + total_warning * 0.5) / applicable) * 100
            else:
                overall_score = 100.0

            # Generate recommendations
            recommendations = self._generate_recommendations(category_results)

            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()

            result = ScanResult(
                scan_id=scan_id,
                url=config.url,
                timestamp=start_time,
                duration_seconds=duration,
                overall_score=round(overall_score, 1),
                total_checks=total_run,
                checks_passed=total_passed,
                checks_failed=total_failed,
                checks_warning=total_warning,
                checks_skipped=total_skipped,
                category_results=category_results,
                recommendations=recommendations,
                status="completed"
            )

            self._scan_history.append(result)
            return result

        except aiohttp.ClientError as e:
            return ScanResult(
                scan_id=scan_id,
                url=config.url,
                timestamp=start_time,
                duration_seconds=0,
                overall_score=0,
                total_checks=0,
                checks_passed=0,
                checks_failed=0,
                checks_warning=0,
                checks_skipped=0,
                category_results=[],
                recommendations=[],
                status="error",
                error=f"Connection error: {str(e)}"
            )
        except Exception as e:
            return ScanResult(
                scan_id=scan_id,
                url=config.url,
                timestamp=start_time,
                duration_seconds=0,
                overall_score=0,
                total_checks=0,
                checks_passed=0,
                checks_failed=0,
                checks_warning=0,
                checks_skipped=0,
                category_results=[],
                recommendations=[],
                status="error",
                error=str(e)
            )

    def _generate_recommendations(
        self,
        category_results: List[CategoryResult]
    ) -> List[Recommendation]:
        """Generate prioritized recommendations from scan results."""
        recommendations = []

        for cat_result in category_results:
            for check_result in cat_result.results:
                if check_result.status in [CheckStatus.FAIL, CheckStatus.WARN]:
                    # Determine priority based on severity and status
                    if check_result.status == CheckStatus.FAIL:
                        if check_result.severity == Severity.CRITICAL:
                            priority = "P0"
                        elif check_result.severity == Severity.HIGH:
                            priority = "P1"
                        else:
                            priority = "P2"
                    else:  # WARN
                        if check_result.severity in [Severity.CRITICAL, Severity.HIGH]:
                            priority = "P1"
                        else:
                            priority = "P2"

                    # Build compliance tags from check details
                    compliance_tags = check_result.details.get("compliance", [])

                    recommendations.append(Recommendation(
                        id=f"REC-{check_result.check_id}",
                        check_id=check_result.check_id,
                        title=check_result.check_name,
                        description=check_result.message,
                        priority=priority,
                        category=cat_result.category_name,
                        remediation=check_result.remediation or "Review and address this security issue.",
                        evidence=check_result.evidence,
                        compliance_tags=compliance_tags,
                        resolved=False
                    ))

        # Sort by priority (P0 first)
        priority_order = {"P0": 0, "P1": 1, "P2": 2}
        recommendations.sort(key=lambda r: priority_order.get(r.priority, 3))

        return recommendations

    def get_scan_history(self) -> List[Dict[str, Any]]:
        """Get scan history summary."""
        return [
            {
                "scan_id": scan.scan_id,
                "url": scan.url,
                "timestamp": scan.timestamp.isoformat(),
                "score": scan.overall_score,
                "status": scan.status,
                "checks_passed": scan.checks_passed,
                "checks_failed": scan.checks_failed,
            }
            for scan in self._scan_history
        ]

    def get_scan_by_id(self, scan_id: str) -> Optional[ScanResult]:
        """Get a specific scan result by ID."""
        for scan in self._scan_history:
            if scan.scan_id == scan_id:
                return scan
        return None


# Singleton instance
_scanner_instance: Optional[SecurityScanner] = None


def get_scanner() -> SecurityScanner:
    """Get the singleton scanner instance."""
    global _scanner_instance
    if _scanner_instance is None:
        _scanner_instance = SecurityScanner()
    return _scanner_instance
