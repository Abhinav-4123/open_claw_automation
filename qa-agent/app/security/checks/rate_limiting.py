"""
NEXUS QA - Rate Limiting & Abuse Prevention Checks
Category 3: 10 checks for brute force, DDoS, spam prevention.
"""

from typing import List
import asyncio
import aiohttp
import time

from .base import BaseSecurityChecker, ScanContext
from ...models.security import (
    SecurityCategory,
    SecurityCheck,
    CheckResult,
    CheckStatus,
    Severity
)


class RateLimitingChecker(BaseSecurityChecker):
    """Rate Limiting checks - brute force, DDoS, abuse prevention."""

    category = SecurityCategory.RATE_LIMITING
    category_name = "Rate Limiting & Abuse Prevention"

    checks = [
        SecurityCheck(
            id="RL-001",
            name="Login Brute Force Protection",
            category=SecurityCategory.RATE_LIMITING,
            description="Tests if login endpoint has rate limiting",
            severity=Severity.HIGH,
            remediation="Implement rate limiting: max 5 attempts per minute per IP",
            cwe_id="CWE-307",
            owasp_id="A07:2021"
        ),
        SecurityCheck(
            id="RL-002",
            name="API Rate Limiting Headers",
            category=SecurityCategory.RATE_LIMITING,
            description="Checks for rate limit headers in API responses",
            severity=Severity.MEDIUM,
            remediation="Add X-RateLimit-Limit, X-RateLimit-Remaining headers",
            cwe_id="CWE-770"
        ),
        SecurityCheck(
            id="RL-003",
            name="Registration Spam Prevention",
            category=SecurityCategory.RATE_LIMITING,
            description="Tests if signup has anti-spam measures",
            severity=Severity.MEDIUM,
            remediation="Implement CAPTCHA and rate limiting on registration",
            cwe_id="CWE-799"
        ),
        SecurityCheck(
            id="RL-004",
            name="Password Reset Flood Protection",
            category=SecurityCategory.RATE_LIMITING,
            description="Checks rate limiting on password reset endpoint",
            severity=Severity.MEDIUM,
            remediation="Limit password reset requests to 3 per hour per email",
            cwe_id="CWE-770"
        ),
        SecurityCheck(
            id="RL-005",
            name="Search/Query Rate Limiting",
            category=SecurityCategory.RATE_LIMITING,
            description="Validates rate limiting on search/query endpoints",
            severity=Severity.LOW,
            remediation="Implement rate limiting on expensive operations",
            cwe_id="CWE-400"
        ),
        SecurityCheck(
            id="RL-006",
            name="File Upload Rate Limiting",
            category=SecurityCategory.RATE_LIMITING,
            description="Checks rate limiting on file upload endpoints",
            severity=Severity.MEDIUM,
            remediation="Limit uploads to prevent storage abuse",
            cwe_id="CWE-400"
        ),
        SecurityCheck(
            id="RL-007",
            name="Account Enumeration Prevention",
            category=SecurityCategory.RATE_LIMITING,
            description="Tests if user enumeration is prevented via rate limiting",
            severity=Severity.MEDIUM,
            remediation="Return generic messages and rate limit login/signup",
            cwe_id="CWE-204",
            owasp_id="A07:2021"
        ),
        SecurityCheck(
            id="RL-008",
            name="CAPTCHA Implementation",
            category=SecurityCategory.RATE_LIMITING,
            description="Checks for CAPTCHA on sensitive forms",
            severity=Severity.LOW,
            remediation="Implement reCAPTCHA or hCaptcha on forms",
            cwe_id="CWE-799"
        ),
        SecurityCheck(
            id="RL-009",
            name="IP-Based Blocking Headers",
            category=SecurityCategory.RATE_LIMITING,
            description="Checks for IP blocking/WAF indicators",
            severity=Severity.LOW,
            remediation="Implement IP-based blocking for repeated abuse",
            cwe_id="CWE-770"
        ),
        SecurityCheck(
            id="RL-010",
            name="DDoS Protection Headers",
            category=SecurityCategory.RATE_LIMITING,
            description="Checks for CDN/DDoS protection indicators",
            severity=Severity.MEDIUM,
            remediation="Use Cloudflare, AWS Shield, or similar DDoS protection",
            cwe_id="CWE-400"
        ),
    ]

    async def run_checks(self, context: ScanContext) -> List[CheckResult]:
        """Run all rate limiting checks."""
        results = []

        results.append(await self._check_login_rate_limit(context))
        results.append(await self._check_rate_limit_headers(context))
        results.append(await self._check_registration_spam(context))
        results.append(await self._check_password_reset_limit(context))
        results.append(await self._check_search_rate_limit(context))
        results.append(await self._check_upload_rate_limit(context))
        results.append(await self._check_enumeration_prevention(context))
        results.append(await self._check_captcha(context))
        results.append(await self._check_ip_blocking(context))
        results.append(await self._check_ddos_protection(context))

        return results

    async def _check_login_rate_limit(self, context: ScanContext) -> CheckResult:
        """RL-001: Test login brute force protection."""
        check = self.checks[0]

        # Look for login forms
        login_patterns = [
            r'<form[^>]*(?:login|signin|auth)[^>]*>',
            r'action=["\'][^"\']*(?:login|signin|auth)',
            r'type=["\']password["\']',
        ]

        has_login = any(
            self.find_in_content(context.html_content, [p])
            for p in login_patterns
        )

        if not has_login:
            return self.skip_check(check, "No login form detected")

        # Check for rate limit indicators in response
        rate_limit_indicators = [
            'rate limit', 'too many', 'try again', 'locked',
            'X-RateLimit', 'Retry-After'
        ]

        headers_str = str(context.headers).lower()
        if any(ind.lower() in headers_str or ind.lower() in context.html_content.lower()
               for ind in rate_limit_indicators):
            return self.pass_check(check, "Rate limiting indicators found")

        return self.warn_check(
            check,
            "Login form found but no rate limiting indicators detected",
            evidence="Consider implementing brute force protection"
        )

    async def _check_rate_limit_headers(self, context: ScanContext) -> CheckResult:
        """RL-002: Check for rate limit headers."""
        check = self.checks[1]

        rate_headers = [
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
            'X-RateLimit-Reset',
            'RateLimit-Limit',
            'RateLimit-Remaining',
            'Retry-After',
        ]

        found_headers = []
        for header in rate_headers:
            if self.has_header(context.headers, header):
                found_headers.append(header)

        if found_headers:
            return self.pass_check(
                check,
                f"Rate limit headers found: {', '.join(found_headers)}"
            )

        return self.warn_check(
            check,
            "No rate limit headers detected in response",
            evidence="Consider adding X-RateLimit-* headers"
        )

    async def _check_registration_spam(self, context: ScanContext) -> CheckResult:
        """RL-003: Check registration spam prevention."""
        check = self.checks[2]

        # Look for registration forms
        signup_patterns = [
            r'<form[^>]*(?:register|signup|create.*account)[^>]*>',
            r'action=["\'][^"\']*(?:register|signup)',
        ]

        has_signup = any(
            self.find_in_content(context.html_content, [p])
            for p in signup_patterns
        )

        if not has_signup:
            return self.skip_check(check, "No registration form detected")

        # Check for CAPTCHA or rate limiting
        captcha_patterns = [
            'recaptcha', 'hcaptcha', 'captcha', 'turnstile',
            'g-recaptcha', 'cf-turnstile'
        ]

        has_captcha = any(p in context.html_content.lower() for p in captcha_patterns)

        if has_captcha:
            return self.pass_check(check, "Registration form has CAPTCHA protection")

        return self.warn_check(
            check,
            "Registration form without visible CAPTCHA",
            evidence="Consider adding CAPTCHA to prevent spam registrations"
        )

    async def _check_password_reset_limit(self, context: ScanContext) -> CheckResult:
        """RL-004: Check password reset flood protection."""
        check = self.checks[3]

        # Look for password reset
        reset_patterns = [
            r'forgot.*password', r'reset.*password', r'recover.*account',
            r'password.*recovery', r'reset.*link'
        ]

        has_reset = any(
            self.find_in_content(context.html_content, [p])
            for p in reset_patterns
        )

        if not has_reset:
            return self.skip_check(check, "No password reset form detected")

        # Without actually testing, we can only warn
        return self.warn_check(
            check,
            "Password reset form found - ensure rate limiting is implemented",
            evidence="Verify max 3 reset requests per hour per email"
        )

    async def _check_search_rate_limit(self, context: ScanContext) -> CheckResult:
        """RL-005: Check search/query rate limiting."""
        check = self.checks[4]

        # Look for search functionality
        search_patterns = [
            r'<input[^>]*(?:search|query|q=)[^>]*>',
            r'<form[^>]*(?:search)[^>]*>',
            r'type=["\']search["\']',
        ]

        has_search = any(
            self.find_in_content(context.html_content, [p])
            for p in search_patterns
        )

        if not has_search:
            return self.skip_check(check, "No search functionality detected")

        return self.warn_check(
            check,
            "Search functionality found - ensure rate limiting on queries",
            evidence="Expensive search operations should be rate limited"
        )

    async def _check_upload_rate_limit(self, context: ScanContext) -> CheckResult:
        """RL-006: Check file upload rate limiting."""
        check = self.checks[5]

        # Look for file upload
        upload_patterns = [
            r'type=["\']file["\']',
            r'enctype=["\']multipart/form-data["\']',
            r'dropzone',
        ]

        has_upload = any(
            self.find_in_content(context.html_content, [p])
            for p in upload_patterns
        )

        if not has_upload:
            return self.skip_check(check, "No file upload functionality detected")

        return self.warn_check(
            check,
            "File upload found - ensure rate limiting to prevent abuse",
            evidence="Implement upload limits per user/IP"
        )

    async def _check_enumeration_prevention(self, context: ScanContext) -> CheckResult:
        """RL-007: Check account enumeration prevention."""
        check = self.checks[6]

        # Look for user-specific error messages
        enum_patterns = [
            r'user\s+not\s+found',
            r'email\s+(?:not\s+)?(?:found|registered|exists)',
            r'username\s+(?:not\s+)?(?:available|taken|exists)',
            r'no\s+account\s+(?:found|exists)',
        ]

        for pattern in enum_patterns:
            if self.find_in_content(context.html_content, [pattern]):
                return self.fail_check(
                    check,
                    "Potential account enumeration via error messages",
                    evidence=f"Specific user existence message pattern found"
                )

        return self.pass_check(check, "No obvious enumeration vectors detected")

    async def _check_captcha(self, context: ScanContext) -> CheckResult:
        """RL-008: Check for CAPTCHA implementation."""
        check = self.checks[7]

        captcha_indicators = [
            'recaptcha', 'hcaptcha', 'captcha', 'turnstile',
            'g-recaptcha-response', 'h-captcha-response',
            'cf-turnstile-response', 'captcha-token'
        ]

        found = []
        content_lower = context.html_content.lower()
        for indicator in captcha_indicators:
            if indicator in content_lower:
                found.append(indicator)

        if found:
            return self.pass_check(
                check,
                f"CAPTCHA implementation detected: {found[0]}"
            )

        # Check for forms that might need CAPTCHA
        has_forms = '<form' in context.html_content.lower()
        if has_forms:
            return self.warn_check(
                check,
                "Forms found without visible CAPTCHA protection",
                evidence="Consider adding CAPTCHA to prevent automated abuse"
            )

        return self.pass_check(check, "No forms requiring CAPTCHA detected")

    async def _check_ip_blocking(self, context: ScanContext) -> CheckResult:
        """RL-009: Check for IP blocking indicators."""
        check = self.checks[8]

        # Check for WAF/blocking headers
        waf_headers = [
            'X-WAF-', 'X-Firewall', 'X-Blocked',
            'CF-RAY', 'X-Sucuri', 'X-CDN'
        ]

        found_waf = []
        for header in waf_headers:
            for h in context.headers:
                if header.lower() in h.lower():
                    found_waf.append(h)

        if found_waf:
            return self.pass_check(
                check,
                f"WAF/blocking indicators found: {found_waf[0]}"
            )

        return self.warn_check(
            check,
            "No WAF or IP blocking headers detected",
            evidence="Consider implementing IP-based blocking for abuse"
        )

    async def _check_ddos_protection(self, context: ScanContext) -> CheckResult:
        """RL-010: Check for DDoS protection."""
        check = self.checks[9]

        # Check for CDN/DDoS protection indicators
        ddos_indicators = {
            'Cloudflare': ['cf-ray', 'cf-cache-status', '__cfduid'],
            'AWS CloudFront': ['x-amz-cf-', 'via.*cloudfront'],
            'Akamai': ['x-akamai', 'akamai'],
            'Fastly': ['x-fastly', 'fastly'],
            'Imperva/Incapsula': ['x-iinfo', 'incap_ses'],
        }

        found_protection = []
        headers_lower = {k.lower(): v for k, v in context.headers.items()}
        content_lower = context.html_content.lower()

        for provider, indicators in ddos_indicators.items():
            for ind in indicators:
                if any(ind in h for h in headers_lower) or ind in content_lower:
                    found_protection.append(provider)
                    break

        if found_protection:
            return self.pass_check(
                check,
                f"DDoS protection detected: {', '.join(set(found_protection))}"
            )

        return self.warn_check(
            check,
            "No DDoS protection indicators detected",
            evidence="Consider using Cloudflare, AWS Shield, or similar"
        )
