"""
NEXUS QA - Infrastructure Security Checks
Category 7: 10 checks for TLS, headers, CORS, server configuration.
"""

from typing import List
import re

from .base import BaseSecurityChecker, ScanContext
from ...models.security import (
    SecurityCategory,
    SecurityCheck,
    CheckResult,
    CheckStatus,
    CheckType,
    Accuracy,
    Severity
)


class InfrastructureChecker(BaseSecurityChecker):
    """Infrastructure Security checks - TLS, headers, CORS, server config."""

    category = SecurityCategory.INFRASTRUCTURE
    category_name = "Infrastructure Security"

    checks = [
        SecurityCheck(
            id="IF-001",
            name="TLS/SSL Configuration",
            category=SecurityCategory.INFRASTRUCTURE,
            description="Validates TLS version and cipher configuration",
            severity=Severity.HIGH,
            remediation="Use TLS 1.2+ with strong cipher suites",
            cwe_id="CWE-326",
            pci_dss="4.1",
            check_type=CheckType.DETERMINISTIC,
            accuracy=Accuracy.MEDIUM,  # Only checks HTTPS, not TLS version
            method="protocol",
            can_verify=False  # Would need SSL handshake inspection
        ),
        SecurityCheck(
            id="IF-002",
            name="HTTP Strict Transport Security (HSTS)",
            category=SecurityCategory.INFRASTRUCTURE,
            description="Checks for HSTS header configuration",
            severity=Severity.HIGH,
            remediation="Add Strict-Transport-Security header with max-age >= 31536000",
            cwe_id="CWE-319",
            owasp_id="A02:2021",
            check_type=CheckType.DETERMINISTIC,
            accuracy=Accuracy.HIGH,
            method="header"
        ),
        SecurityCheck(
            id="IF-003",
            name="Content Security Policy (CSP)",
            category=SecurityCategory.INFRASTRUCTURE,
            description="Validates Content-Security-Policy header",
            severity=Severity.HIGH,
            remediation="Implement strict CSP with no unsafe-inline/eval",
            cwe_id="CWE-1021",
            owasp_id="A05:2021",
            check_type=CheckType.DETERMINISTIC,
            accuracy=Accuracy.HIGH,
            method="header"
        ),
        SecurityCheck(
            id="IF-004",
            name="X-Content-Type-Options",
            category=SecurityCategory.INFRASTRUCTURE,
            description="Checks for X-Content-Type-Options: nosniff",
            severity=Severity.MEDIUM,
            remediation="Add X-Content-Type-Options: nosniff header",
            cwe_id="CWE-16",
            check_type=CheckType.DETERMINISTIC,
            accuracy=Accuracy.HIGH,
            method="header"
        ),
        SecurityCheck(
            id="IF-005",
            name="X-Frame-Options / Frame Ancestors",
            category=SecurityCategory.INFRASTRUCTURE,
            description="Checks for clickjacking protection",
            severity=Severity.MEDIUM,
            remediation="Add X-Frame-Options: DENY or CSP frame-ancestors",
            cwe_id="CWE-1021",
            owasp_id="A05:2021",
            check_type=CheckType.DETERMINISTIC,
            accuracy=Accuracy.HIGH,
            method="header"
        ),
        SecurityCheck(
            id="IF-006",
            name="CORS Configuration",
            category=SecurityCategory.INFRASTRUCTURE,
            description="Validates Cross-Origin Resource Sharing settings",
            severity=Severity.HIGH,
            remediation="Avoid wildcard (*) origins, whitelist specific domains",
            cwe_id="CWE-942",
            owasp_id="A05:2021",
            check_type=CheckType.DETERMINISTIC,
            accuracy=Accuracy.HIGH,
            method="header"
        ),
        SecurityCheck(
            id="IF-007",
            name="Server Information Disclosure",
            category=SecurityCategory.INFRASTRUCTURE,
            description="Checks for server version information leakage",
            severity=Severity.LOW,
            remediation="Remove Server, X-Powered-By headers",
            cwe_id="CWE-200",
            check_type=CheckType.DETERMINISTIC,
            accuracy=Accuracy.HIGH,
            method="header"
        ),
        SecurityCheck(
            id="IF-008",
            name="Referrer Policy",
            category=SecurityCategory.INFRASTRUCTURE,
            description="Validates Referrer-Policy header configuration",
            severity=Severity.LOW,
            remediation="Set Referrer-Policy: strict-origin-when-cross-origin",
            cwe_id="CWE-200",
            check_type=CheckType.DETERMINISTIC,
            accuracy=Accuracy.HIGH,
            method="header"
        ),
        SecurityCheck(
            id="IF-009",
            name="Permissions Policy",
            category=SecurityCategory.INFRASTRUCTURE,
            description="Checks for Permissions-Policy header",
            severity=Severity.LOW,
            remediation="Implement Permissions-Policy to restrict browser features",
            cwe_id="CWE-16",
            check_type=CheckType.DETERMINISTIC,
            accuracy=Accuracy.HIGH,
            method="header"
        ),
        SecurityCheck(
            id="IF-010",
            name="Certificate Validity",
            category=SecurityCategory.INFRASTRUCTURE,
            description="Validates SSL certificate status",
            severity=Severity.CRITICAL,
            remediation="Ensure valid certificate from trusted CA",
            cwe_id="CWE-295",
            pci_dss="4.1",
            check_type=CheckType.DETERMINISTIC,
            accuracy=Accuracy.MEDIUM,  # Only checks HTTPS works
            method="protocol",
            can_verify=False  # Would need full cert inspection
        ),
    ]

    async def run_checks(self, context: ScanContext) -> List[CheckResult]:
        """Run all infrastructure checks."""
        results = []

        results.append(await self._check_tls_config(context))
        results.append(await self._check_hsts(context))
        results.append(await self._check_csp(context))
        results.append(await self._check_content_type_options(context))
        results.append(await self._check_frame_options(context))
        results.append(await self._check_cors(context))
        results.append(await self._check_server_disclosure(context))
        results.append(await self._check_referrer_policy(context))
        results.append(await self._check_permissions_policy(context))
        results.append(await self._check_certificate(context))

        return results

    async def _check_tls_config(self, context: ScanContext) -> CheckResult:
        """IF-001: Check TLS/SSL configuration."""
        check = self.checks[0]

        if not context.is_https:
            return self.fail_check(
                check,
                "Site not using HTTPS",
                evidence="All traffic should be encrypted with TLS 1.2+"
            )

        # Check for TLS version indicators in headers or response
        # Note: Full TLS analysis would require SSL handshake inspection
        return self.pass_check(check, "HTTPS enabled - verify TLS 1.2+ server-side")

    async def _check_hsts(self, context: ScanContext) -> CheckResult:
        """IF-002: Check HSTS header."""
        check = self.checks[1]

        hsts = self.check_header(context.headers, 'Strict-Transport-Security')

        if not hsts:
            if context.is_https:
                return self.fail_check(
                    check,
                    "HTTPS enabled but HSTS header missing",
                    evidence="Add Strict-Transport-Security header"
                )
            return self.skip_check(check, "Not HTTPS - HSTS not applicable")

        # Parse HSTS directives
        max_age_match = re.search(r'max-age=(\d+)', hsts, re.IGNORECASE)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:  # Less than 1 year
                return self.warn_check(
                    check,
                    f"HSTS max-age too short: {max_age} seconds",
                    evidence="Recommend max-age >= 31536000 (1 year)"
                )

        has_subdomains = 'includesubdomains' in hsts.lower()
        has_preload = 'preload' in hsts.lower()

        if has_subdomains and has_preload:
            return self.pass_check(check, "HSTS configured with includeSubDomains and preload")
        elif has_subdomains:
            return self.pass_check(check, "HSTS configured with includeSubDomains")
        else:
            return self.warn_check(
                check,
                "HSTS present but missing includeSubDomains",
                evidence="Consider adding includeSubDomains directive"
            )

    async def _check_csp(self, context: ScanContext) -> CheckResult:
        """IF-003: Check Content Security Policy."""
        check = self.checks[2]

        csp = self.check_header(context.headers, 'Content-Security-Policy')
        csp_ro = self.check_header(context.headers, 'Content-Security-Policy-Report-Only')

        if not csp and not csp_ro:
            return self.fail_check(
                check,
                "No Content-Security-Policy header",
                evidence="Implement CSP to prevent XSS attacks"
            )

        policy = csp or csp_ro
        issues = []

        # Check for weak directives
        if "'unsafe-inline'" in policy:
            issues.append("unsafe-inline allows inline scripts")
        if "'unsafe-eval'" in policy:
            issues.append("unsafe-eval allows eval()")
        if "default-src *" in policy or "script-src *" in policy:
            issues.append("Wildcard source allows any origin")

        # Check for missing directives
        important_directives = ['default-src', 'script-src', 'object-src']
        missing = [d for d in important_directives if d not in policy]
        if missing:
            issues.append(f"Missing directives: {', '.join(missing)}")

        if issues:
            is_report_only = csp_ro and not csp
            if is_report_only:
                return self.warn_check(
                    check,
                    "CSP in report-only mode with issues",
                    evidence="; ".join(issues[:2])
                )
            return self.warn_check(
                check,
                f"CSP has weaknesses: {len(issues)} issue(s)",
                evidence="; ".join(issues[:2])
            )

        return self.pass_check(check, "CSP configured properly")

    async def _check_content_type_options(self, context: ScanContext) -> CheckResult:
        """IF-004: Check X-Content-Type-Options header."""
        check = self.checks[3]

        xcto = self.check_header(context.headers, 'X-Content-Type-Options')

        if not xcto:
            return self.fail_check(
                check,
                "X-Content-Type-Options header missing",
                evidence="Add X-Content-Type-Options: nosniff"
            )

        if 'nosniff' not in xcto.lower():
            return self.fail_check(
                check,
                f"Invalid X-Content-Type-Options: {xcto}",
                evidence="Should be 'nosniff'"
            )

        return self.pass_check(check, "X-Content-Type-Options: nosniff configured")

    async def _check_frame_options(self, context: ScanContext) -> CheckResult:
        """IF-005: Check clickjacking protection."""
        check = self.checks[4]

        xfo = self.check_header(context.headers, 'X-Frame-Options')
        csp = self.check_header(context.headers, 'Content-Security-Policy')

        # Check CSP frame-ancestors first (more modern)
        if csp and 'frame-ancestors' in csp:
            if "'none'" in csp or "'self'" in csp:
                return self.pass_check(check, "CSP frame-ancestors configured")
            return self.warn_check(
                check,
                "CSP frame-ancestors may be too permissive",
                evidence="Review frame-ancestors directive"
            )

        # Fall back to X-Frame-Options
        if not xfo:
            return self.fail_check(
                check,
                "No clickjacking protection (X-Frame-Options or CSP frame-ancestors)",
                evidence="Add X-Frame-Options: DENY or CSP frame-ancestors"
            )

        xfo_upper = xfo.upper()
        if 'DENY' in xfo_upper:
            return self.pass_check(check, "X-Frame-Options: DENY configured")
        elif 'SAMEORIGIN' in xfo_upper:
            return self.pass_check(check, "X-Frame-Options: SAMEORIGIN configured")
        else:
            return self.warn_check(
                check,
                f"Unusual X-Frame-Options value: {xfo}",
                evidence="Use DENY or SAMEORIGIN"
            )

    async def _check_cors(self, context: ScanContext) -> CheckResult:
        """IF-006: Check CORS configuration."""
        check = self.checks[5]

        acao = self.check_header(context.headers, 'Access-Control-Allow-Origin')
        acac = self.check_header(context.headers, 'Access-Control-Allow-Credentials')

        if not acao:
            return self.pass_check(check, "No CORS headers - same-origin policy applies")

        issues = []

        # Check for wildcard with credentials
        if acao == '*':
            if acac and acac.lower() == 'true':
                return self.fail_check(
                    check,
                    "CORS wildcard with credentials enabled",
                    evidence="This allows any site to make credentialed requests"
                )
            issues.append("Wildcard origin allows any site")

        # Check for null origin
        if acao.lower() == 'null':
            issues.append("Null origin can be exploited via sandboxed iframes")

        # Check for reflected origin (would need request comparison)
        # This is a simplified check

        if issues:
            return self.warn_check(
                check,
                f"CORS configuration concerns: {', '.join(issues)}",
                evidence="Review CORS whitelist policy"
            )

        return self.pass_check(check, f"CORS configured for: {acao}")

    async def _check_server_disclosure(self, context: ScanContext) -> CheckResult:
        """IF-007: Check for server information disclosure."""
        check = self.checks[6]

        disclosure_headers = {
            'Server': 'Server version',
            'X-Powered-By': 'Framework/language',
            'X-AspNet-Version': 'ASP.NET version',
            'X-AspNetMvc-Version': 'MVC version',
        }

        found = []
        for header, desc in disclosure_headers.items():
            value = self.check_header(context.headers, header)
            if value:
                # Check if version info is included
                if re.search(r'\d+\.\d+', value):
                    found.append(f"{header}: {value}")

        if found:
            return self.warn_check(
                check,
                f"Server information disclosed: {len(found)} header(s)",
                evidence="; ".join(found[:2])
            )

        return self.pass_check(check, "No server version disclosure detected")

    async def _check_referrer_policy(self, context: ScanContext) -> CheckResult:
        """IF-008: Check Referrer-Policy header."""
        check = self.checks[7]

        rp = self.check_header(context.headers, 'Referrer-Policy')

        if not rp:
            # Check meta tag fallback
            meta_rp = re.search(
                r'<meta[^>]*name=["\']referrer["\'][^>]*content=["\']([^"\']+)["\']',
                context.html_content,
                re.IGNORECASE
            )
            if meta_rp:
                rp = meta_rp.group(1)
            else:
                return self.warn_check(
                    check,
                    "No Referrer-Policy header",
                    evidence="Add Referrer-Policy: strict-origin-when-cross-origin"
                )

        # Evaluate policy strength
        secure_policies = [
            'no-referrer',
            'same-origin',
            'strict-origin',
            'strict-origin-when-cross-origin'
        ]

        if any(p in rp.lower() for p in secure_policies):
            return self.pass_check(check, f"Referrer-Policy configured: {rp}")

        if 'unsafe-url' in rp.lower():
            return self.fail_check(
                check,
                "Referrer-Policy: unsafe-url leaks full URL",
                evidence="Use strict-origin-when-cross-origin instead"
            )

        return self.warn_check(
            check,
            f"Referrer-Policy may leak information: {rp}",
            evidence="Consider stricter policy"
        )

    async def _check_permissions_policy(self, context: ScanContext) -> CheckResult:
        """IF-009: Check Permissions-Policy header."""
        check = self.checks[8]

        pp = self.check_header(context.headers, 'Permissions-Policy')
        fp = self.check_header(context.headers, 'Feature-Policy')  # Legacy

        if not pp and not fp:
            return self.warn_check(
                check,
                "No Permissions-Policy header",
                evidence="Consider restricting browser features"
            )

        policy = pp or fp

        # Check for restrictive settings
        restricted_features = [
            'geolocation', 'camera', 'microphone', 'payment'
        ]

        restricted = []
        for feature in restricted_features:
            if feature in policy.lower() and ('()' in policy or "'none'" in policy):
                restricted.append(feature)

        if restricted:
            return self.pass_check(
                check,
                f"Permissions restricted for: {', '.join(restricted)}"
            )

        return self.pass_check(check, "Permissions-Policy header present")

    async def _check_certificate(self, context: ScanContext) -> CheckResult:
        """IF-010: Check SSL certificate validity."""
        check = self.checks[9]

        if not context.is_https:
            return self.fail_check(
                check,
                "Site not using HTTPS",
                evidence="No certificate to validate"
            )

        # Note: Full certificate validation would require SSL handshake
        # This is a basic check based on successful HTTPS connection
        return self.pass_check(
            check,
            "HTTPS connection successful - certificate accepted by browser"
        )
