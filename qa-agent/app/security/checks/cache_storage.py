"""
NEXUS QA - Cache & Storage Exposure Checks
Category 4: 10 checks for localStorage, CDN cache, browser storage.
"""

from typing import List
import re

from .base import BaseSecurityChecker, ScanContext
from ...models.security import (
    SecurityCategory,
    SecurityCheck,
    CheckResult,
    CheckStatus,
    Severity
)


class CacheStorageChecker(BaseSecurityChecker):
    """Cache & Storage checks - localStorage, CDN, browser cache."""

    category = SecurityCategory.CACHE_STORAGE
    category_name = "Cache & Storage Exposure"

    checks = [
        SecurityCheck(
            id="CS-001",
            name="Browser Cache Control Headers",
            category=SecurityCategory.CACHE_STORAGE,
            description="Checks Cache-Control headers for sensitive pages",
            severity=Severity.MEDIUM,
            remediation="Add Cache-Control: no-store for sensitive pages",
            cwe_id="CWE-525"
        ),
        SecurityCheck(
            id="CS-002",
            name="CDN Cache Configuration",
            category=SecurityCategory.CACHE_STORAGE,
            description="Validates CDN caching doesn't expose sensitive data",
            severity=Severity.MEDIUM,
            remediation="Configure CDN to bypass cache for authenticated content",
            cwe_id="CWE-524"
        ),
        SecurityCheck(
            id="CS-003",
            name="localStorage Sensitive Data",
            category=SecurityCategory.CACHE_STORAGE,
            description="Checks for sensitive data stored in localStorage",
            severity=Severity.HIGH,
            remediation="Avoid storing sensitive data in localStorage, use secure cookies",
            cwe_id="CWE-922"
        ),
        SecurityCheck(
            id="CS-004",
            name="sessionStorage Analysis",
            category=SecurityCategory.CACHE_STORAGE,
            description="Analyzes sessionStorage usage for sensitive data",
            severity=Severity.MEDIUM,
            remediation="Minimize sensitive data in sessionStorage",
            cwe_id="CWE-922"
        ),
        SecurityCheck(
            id="CS-005",
            name="IndexedDB Security",
            category=SecurityCategory.CACHE_STORAGE,
            description="Checks for sensitive data in IndexedDB",
            severity=Severity.MEDIUM,
            remediation="Encrypt sensitive data stored in IndexedDB",
            cwe_id="CWE-922"
        ),
        SecurityCheck(
            id="CS-006",
            name="Service Worker Cache",
            category=SecurityCategory.CACHE_STORAGE,
            description="Analyzes service worker caching strategies",
            severity=Severity.LOW,
            remediation="Ensure service workers don't cache sensitive data",
            cwe_id="CWE-524"
        ),
        SecurityCheck(
            id="CS-007",
            name="Sensitive Page Cache Headers",
            category=SecurityCategory.CACHE_STORAGE,
            description="Validates no-cache for login/payment pages",
            severity=Severity.HIGH,
            remediation="Add no-store, no-cache headers for sensitive pages",
            cwe_id="CWE-525",
            pci_dss="6.5.10"
        ),
        SecurityCheck(
            id="CS-008",
            name="ETag Information Leakage",
            category=SecurityCategory.CACHE_STORAGE,
            description="Checks if ETags leak sensitive information",
            severity=Severity.LOW,
            remediation="Configure ETags to not include inode information",
            cwe_id="CWE-200"
        ),
        SecurityCheck(
            id="CS-009",
            name="Pragma No-Cache Headers",
            category=SecurityCategory.CACHE_STORAGE,
            description="Checks for Pragma: no-cache on sensitive pages",
            severity=Severity.LOW,
            remediation="Add Pragma: no-cache for HTTP/1.0 compatibility",
            cwe_id="CWE-525"
        ),
        SecurityCheck(
            id="CS-010",
            name="Vary Header Configuration",
            category=SecurityCategory.CACHE_STORAGE,
            description="Validates Vary header for proper cache partitioning",
            severity=Severity.LOW,
            remediation="Add Vary: Cookie header for authenticated content",
            cwe_id="CWE-524"
        ),
    ]

    async def run_checks(self, context: ScanContext) -> List[CheckResult]:
        """Run all cache/storage checks."""
        results = []

        results.append(await self._check_cache_control(context))
        results.append(await self._check_cdn_cache(context))
        results.append(await self._check_localstorage_data(context))
        results.append(await self._check_sessionstorage(context))
        results.append(await self._check_indexeddb(context))
        results.append(await self._check_service_worker(context))
        results.append(await self._check_sensitive_page_cache(context))
        results.append(await self._check_etag_leakage(context))
        results.append(await self._check_pragma_header(context))
        results.append(await self._check_vary_header(context))

        return results

    async def _check_cache_control(self, context: ScanContext) -> CheckResult:
        """CS-001: Check Cache-Control headers."""
        check = self.checks[0]

        cache_control = self.check_header(context.headers, 'Cache-Control')

        if cache_control:
            secure_directives = ['no-store', 'no-cache', 'private', 'must-revalidate']
            has_secure = any(d in cache_control.lower() for d in secure_directives)

            if has_secure:
                return self.pass_check(
                    check,
                    f"Cache-Control header configured: {cache_control}"
                )
            else:
                return self.warn_check(
                    check,
                    f"Cache-Control may allow caching: {cache_control}",
                    evidence="Consider adding no-store for sensitive pages"
                )

        return self.warn_check(
            check,
            "No Cache-Control header found",
            evidence="Add Cache-Control: no-store for sensitive content"
        )

    async def _check_cdn_cache(self, context: ScanContext) -> CheckResult:
        """CS-002: Check CDN cache configuration."""
        check = self.checks[1]

        cdn_headers = {
            'CF-Cache-Status': 'Cloudflare',
            'X-Cache': 'Generic CDN',
            'X-Varnish': 'Varnish',
            'X-Fastly-Request-ID': 'Fastly',
            'X-Amz-Cf-Id': 'CloudFront',
        }

        found_cdn = None
        cache_status = None

        for header, cdn in cdn_headers.items():
            value = self.check_header(context.headers, header)
            if value:
                found_cdn = cdn
                cache_status = value
                break

        if found_cdn:
            # Check if it's caching authenticated content
            if cache_status and 'HIT' in str(cache_status).upper():
                # Check if page appears to have authenticated content
                auth_indicators = ['logout', 'my account', 'profile', 'dashboard']
                has_auth = any(ind in context.html_content.lower() for ind in auth_indicators)

                if has_auth:
                    return self.warn_check(
                        check,
                        f"{found_cdn} CDN caching potentially authenticated content",
                        evidence=f"Cache status: {cache_status}"
                    )

            return self.pass_check(
                check,
                f"{found_cdn} CDN detected, cache status: {cache_status}"
            )

        return self.pass_check(check, "No CDN caching detected")

    async def _check_localstorage_data(self, context: ScanContext) -> CheckResult:
        """CS-003: Check for sensitive data in localStorage."""
        check = self.checks[2]

        sensitive_keys = [
            'token', 'auth', 'session', 'password', 'secret',
            'credit', 'card', 'ssn', 'user', 'api_key'
        ]

        # Check JavaScript for localStorage usage with sensitive keys
        localstorage_patterns = [
            rf'localStorage\.(?:set|get)Item\s*\(\s*["\']({"|".join(sensitive_keys)})',
            rf'localStorage\s*\[\s*["\']({"|".join(sensitive_keys)})',
        ]

        found = []
        for pattern in localstorage_patterns:
            matches = re.findall(pattern, context.html_content, re.IGNORECASE)
            found.extend(matches)

        if found:
            return self.fail_check(
                check,
                f"Sensitive data keys in localStorage: {', '.join(set(found))}",
                evidence="Avoid storing sensitive data in localStorage"
            )

        return self.pass_check(check, "No sensitive localStorage keys detected")

    async def _check_sessionstorage(self, context: ScanContext) -> CheckResult:
        """CS-004: Check sessionStorage usage."""
        check = self.checks[3]

        sensitive_keys = ['token', 'auth', 'password', 'secret', 'session']

        session_patterns = [
            rf'sessionStorage\.(?:set|get)Item\s*\(\s*["\']({"|".join(sensitive_keys)})',
        ]

        found = []
        for pattern in session_patterns:
            matches = re.findall(pattern, context.html_content, re.IGNORECASE)
            found.extend(matches)

        if found:
            return self.warn_check(
                check,
                f"Sensitive keys in sessionStorage: {', '.join(set(found))}",
                evidence="Consider using httpOnly cookies instead"
            )

        return self.pass_check(check, "No sensitive sessionStorage usage detected")

    async def _check_indexeddb(self, context: ScanContext) -> CheckResult:
        """CS-005: Check IndexedDB usage."""
        check = self.checks[4]

        indexeddb_patterns = [
            r'indexedDB\.open',
            r'IDBDatabase',
            r'createObjectStore',
        ]

        uses_indexeddb = any(
            re.search(p, context.html_content, re.IGNORECASE)
            for p in indexeddb_patterns
        )

        if uses_indexeddb:
            # Check for encryption indicators
            encryption_patterns = ['crypto', 'encrypt', 'CryptoJS', 'webcrypto']
            has_encryption = any(p in context.html_content.lower() for p in encryption_patterns)

            if has_encryption:
                return self.pass_check(check, "IndexedDB usage with encryption detected")
            else:
                return self.warn_check(
                    check,
                    "IndexedDB usage without obvious encryption",
                    evidence="Consider encrypting sensitive IndexedDB data"
                )

        return self.pass_check(check, "No IndexedDB usage detected")

    async def _check_service_worker(self, context: ScanContext) -> CheckResult:
        """CS-006: Check service worker caching."""
        check = self.checks[5]

        sw_patterns = [
            r'serviceWorker\.register',
            r'navigator\.serviceWorker',
            r'workbox',
        ]

        has_sw = any(
            re.search(p, context.html_content, re.IGNORECASE)
            for p in sw_patterns
        )

        if has_sw:
            return self.warn_check(
                check,
                "Service Worker detected - verify cache strategy",
                evidence="Ensure sensitive data is not cached by SW"
            )

        return self.pass_check(check, "No Service Worker detected")

    async def _check_sensitive_page_cache(self, context: ScanContext) -> CheckResult:
        """CS-007: Check caching on sensitive pages."""
        check = self.checks[6]

        # Determine if this is a sensitive page
        sensitive_indicators = [
            'login', 'signin', 'password', 'payment', 'checkout',
            'credit card', 'account', 'profile', 'settings'
        ]

        is_sensitive = any(ind in context.url.lower() or ind in context.html_content.lower()
                          for ind in sensitive_indicators)

        if not is_sensitive:
            return self.skip_check(check, "Page doesn't appear to be sensitive")

        cache_control = self.check_header(context.headers, 'Cache-Control')
        if cache_control and 'no-store' in cache_control.lower():
            return self.pass_check(check, "Sensitive page has no-store directive")

        return self.fail_check(
            check,
            "Sensitive page missing no-store Cache-Control",
            evidence="Login/payment pages should have Cache-Control: no-store"
        )

    async def _check_etag_leakage(self, context: ScanContext) -> CheckResult:
        """CS-008: Check ETag for information leakage."""
        check = self.checks[7]

        etag = self.check_header(context.headers, 'ETag')

        if etag:
            # Check for inode-style ETag (Apache default with inode)
            # Format: "inode-size-mtime" or similar
            if re.match(r'"[0-9a-f]+-[0-9a-f]+-[0-9a-f]+"', etag, re.IGNORECASE):
                return self.warn_check(
                    check,
                    "ETag may contain inode information",
                    evidence=f"ETag format suggests server info: {etag[:30]}"
                )
            return self.pass_check(check, f"ETag present but appears safe")

        return self.pass_check(check, "No ETag header present")

    async def _check_pragma_header(self, context: ScanContext) -> CheckResult:
        """CS-009: Check Pragma header for HTTP/1.0."""
        check = self.checks[8]

        pragma = self.check_header(context.headers, 'Pragma')
        cache_control = self.check_header(context.headers, 'Cache-Control')

        # If Cache-Control exists, Pragma is redundant but good for compat
        if cache_control and 'no-cache' in cache_control.lower():
            if pragma and 'no-cache' in pragma.lower():
                return self.pass_check(check, "Both Cache-Control and Pragma: no-cache set")
            return self.pass_check(check, "Cache-Control: no-cache set (Pragma optional)")

        if pragma and 'no-cache' in pragma.lower():
            return self.pass_check(check, "Pragma: no-cache set")

        return self.warn_check(
            check,
            "No Pragma: no-cache header for HTTP/1.0 compatibility",
            evidence="Consider adding for older client support"
        )

    async def _check_vary_header(self, context: ScanContext) -> CheckResult:
        """CS-010: Check Vary header for cache partitioning."""
        check = self.checks[9]

        vary = self.check_header(context.headers, 'Vary')

        # Check if page has authenticated content
        auth_indicators = ['logout', 'my account', 'welcome back', 'profile']
        has_auth = any(ind in context.html_content.lower() for ind in auth_indicators)

        if has_auth:
            if vary and 'cookie' in vary.lower():
                return self.pass_check(check, "Vary: Cookie header set for authenticated content")
            return self.warn_check(
                check,
                "Authenticated content without Vary: Cookie header",
                evidence="Add Vary: Cookie to prevent cache poisoning"
            )

        if vary:
            return self.pass_check(check, f"Vary header present: {vary}")

        return self.pass_check(check, "No Vary header needed for public content")
