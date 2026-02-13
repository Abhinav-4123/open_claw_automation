"""
NEXUS QA - Credentials & Secrets Checks
Category 2: 10 checks for token storage, API keys, secrets exposure.
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


class CredentialsChecker(BaseSecurityChecker):
    """Credentials & Secrets checks - tokens, API keys, passwords."""

    category = SecurityCategory.CREDENTIALS
    category_name = "Credentials & Secrets"

    checks = [
        SecurityCheck(
            id="CR-001",
            name="JWT Token in URL Parameters",
            category=SecurityCategory.CREDENTIALS,
            description="Checks for JWT tokens exposed in URL parameters",
            severity=Severity.HIGH,
            remediation="Pass JWT tokens in Authorization header, not URL parameters",
            cwe_id="CWE-598",
            owasp_id="A02:2021"
        ),
        SecurityCheck(
            id="CR-002",
            name="API Keys in Client-Side Code",
            category=SecurityCategory.CREDENTIALS,
            description="Detects API keys exposed in JavaScript or HTML",
            severity=Severity.CRITICAL,
            remediation="Move API keys to backend, use environment variables",
            cwe_id="CWE-798"
        ),
        SecurityCheck(
            id="CR-003",
            name="Hardcoded Secrets Detection",
            category=SecurityCategory.CREDENTIALS,
            description="Scans for hardcoded passwords, tokens, or secrets",
            severity=Severity.CRITICAL,
            remediation="Use secrets management (Vault, AWS Secrets Manager)",
            cwe_id="CWE-798",
            iso27001="A.9.4.3"
        ),
        SecurityCheck(
            id="CR-004",
            name="Password in GET Request",
            category=SecurityCategory.CREDENTIALS,
            description="Checks if passwords are sent via GET parameters",
            severity=Severity.HIGH,
            remediation="Always use POST for authentication, never GET",
            cwe_id="CWE-598"
        ),
        SecurityCheck(
            id="CR-005",
            name="Token Storage in localStorage",
            category=SecurityCategory.CREDENTIALS,
            description="Checks for sensitive tokens stored in localStorage",
            severity=Severity.MEDIUM,
            remediation="Use httpOnly cookies for session tokens instead of localStorage",
            cwe_id="CWE-922"
        ),
        SecurityCheck(
            id="CR-006",
            name="Session Token Security",
            category=SecurityCategory.CREDENTIALS,
            description="Validates session token security attributes",
            severity=Severity.HIGH,
            remediation="Use Secure, HttpOnly, SameSite attributes on session cookies",
            cwe_id="CWE-614",
            owasp_id="A07:2021"
        ),
        SecurityCheck(
            id="CR-007",
            name="OAuth Token Exposure",
            category=SecurityCategory.CREDENTIALS,
            description="Checks for OAuth tokens in URLs or responses",
            severity=Severity.HIGH,
            remediation="Never expose OAuth tokens in URLs, use secure token storage",
            cwe_id="CWE-522"
        ),
        SecurityCheck(
            id="CR-008",
            name="Cloud Provider Keys (AWS/GCP/Azure)",
            category=SecurityCategory.CREDENTIALS,
            description="Detects exposed cloud provider credentials",
            severity=Severity.CRITICAL,
            remediation="Rotate exposed keys immediately, use IAM roles instead",
            cwe_id="CWE-798"
        ),
        SecurityCheck(
            id="CR-009",
            name="Database Connection String Exposure",
            category=SecurityCategory.CREDENTIALS,
            description="Checks for exposed database connection strings",
            severity=Severity.CRITICAL,
            remediation="Never expose connection strings, use environment variables",
            cwe_id="CWE-798"
        ),
        SecurityCheck(
            id="CR-010",
            name="Private Key Exposure",
            category=SecurityCategory.CREDENTIALS,
            description="Detects private keys in responses or source",
            severity=Severity.CRITICAL,
            remediation="Never expose private keys, store securely server-side",
            cwe_id="CWE-321"
        ),
    ]

    async def run_checks(self, context: ScanContext) -> List[CheckResult]:
        """Run all credentials checks."""
        results = []

        results.append(await self._check_jwt_in_url(context))
        results.append(await self._check_api_keys_in_client(context))
        results.append(await self._check_hardcoded_secrets(context))
        results.append(await self._check_password_in_get(context))
        results.append(await self._check_localstorage_tokens(context))
        results.append(await self._check_session_token_security(context))
        results.append(await self._check_oauth_exposure(context))
        results.append(await self._check_cloud_keys(context))
        results.append(await self._check_db_connection_strings(context))
        results.append(await self._check_private_keys(context))

        return results

    async def _check_jwt_in_url(self, context: ScanContext) -> CheckResult:
        """CR-001: Check for JWT tokens in URL."""
        check = self.checks[0]
        jwt_pattern = r'[?&](?:token|jwt|access_token|auth)=eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'

        if re.search(jwt_pattern, context.url, re.IGNORECASE):
            return self.fail_check(
                check,
                "JWT token found in URL parameters",
                evidence="Token exposed in URL query string"
            )

        # Check links in content
        links_with_jwt = [l for l in context.links if re.search(jwt_pattern, l, re.IGNORECASE)]
        if links_with_jwt:
            return self.fail_check(
                check,
                f"JWT tokens found in {len(links_with_jwt)} URL(s)",
                evidence="Links contain JWT tokens in parameters"
            )

        return self.pass_check(check, "No JWT tokens found in URLs")

    async def _check_api_keys_in_client(self, context: ScanContext) -> CheckResult:
        """CR-002: Check for API keys in client-side code."""
        check = self.checks[1]

        api_key_patterns = [
            r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            r'(?:secret[_-]?key|secretkey)\s*[=:]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            r'(?:auth[_-]?token|authtoken)\s*[=:]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
        ]

        found_keys = []
        for pattern in api_key_patterns:
            matches = re.findall(pattern, context.html_content, re.IGNORECASE)
            found_keys.extend(matches)

        if found_keys:
            return self.fail_check(
                check,
                f"Potential API keys found in client-side code: {len(found_keys)}",
                evidence="API key patterns detected in HTML/JS"
            )
        return self.pass_check(check, "No API keys detected in client-side code")

    async def _check_hardcoded_secrets(self, context: ScanContext) -> CheckResult:
        """CR-003: Check for hardcoded secrets."""
        check = self.checks[2]

        secret_patterns = [
            r'password\s*[=:]\s*["\']([^"\']{8,})["\']',
            r'secret\s*[=:]\s*["\']([^"\']{16,})["\']',
            r'private[_-]?key\s*[=:]\s*["\']([^"\']+)["\']',
            r'credentials\s*[=:]\s*\{[^}]+\}',
        ]

        findings = []
        for pattern in secret_patterns:
            if re.search(pattern, context.html_content, re.IGNORECASE):
                findings.append(pattern.split(r'\s')[0])

        if findings:
            return self.fail_check(
                check,
                f"Potential hardcoded secrets detected",
                evidence=f"Secret-like patterns: {findings[:3]}"
            )
        return self.pass_check(check, "No obvious hardcoded secrets found")

    async def _check_password_in_get(self, context: ScanContext) -> CheckResult:
        """CR-004: Check for passwords in GET requests."""
        check = self.checks[3]

        # Check forms for GET method with password fields
        password_get_form = re.search(
            r'<form[^>]*method=["\']?get["\']?[^>]*>.*?type=["\']password["\'].*?</form>',
            context.html_content,
            re.IGNORECASE | re.DOTALL
        )

        if password_get_form:
            return self.fail_check(
                check,
                "Password field in form using GET method",
                evidence="Form with password field uses GET instead of POST"
            )

        # Check URL for password parameters
        if re.search(r'[?&](?:password|passwd|pwd)=', context.url, re.IGNORECASE):
            return self.fail_check(
                check,
                "Password found in URL parameters",
                evidence="Password transmitted via GET request"
            )

        return self.pass_check(check, "No passwords in GET requests detected")

    async def _check_localstorage_tokens(self, context: ScanContext) -> CheckResult:
        """CR-005: Check for token storage in localStorage."""
        check = self.checks[4]

        localstorage_patterns = [
            r'localStorage\.setItem\s*\(\s*["\'](?:token|jwt|auth|session)',
            r'localStorage\s*\[\s*["\'](?:token|jwt|auth|session)',
            r'window\.localStorage.*(?:token|jwt|auth)',
        ]

        found = False
        for pattern in localstorage_patterns:
            if re.search(pattern, context.html_content, re.IGNORECASE):
                found = True
                break

        if found:
            return self.warn_check(
                check,
                "Token storage in localStorage detected",
                evidence="JavaScript stores auth tokens in localStorage"
            )
        return self.pass_check(check, "No localStorage token storage detected")

    async def _check_session_token_security(self, context: ScanContext) -> CheckResult:
        """CR-006: Check session token security attributes."""
        check = self.checks[5]

        issues = []
        for name, cookie in context.cookies.items():
            if any(x in name.lower() for x in ['session', 'token', 'auth', 'sid']):
                cookie_str = str(cookie).lower() if isinstance(cookie, dict) else str(cookie).lower()

                if 'httponly' not in cookie_str:
                    issues.append(f"{name}: missing HttpOnly")
                if 'secure' not in cookie_str and context.is_https:
                    issues.append(f"{name}: missing Secure flag")
                if 'samesite' not in cookie_str:
                    issues.append(f"{name}: missing SameSite")

        if issues:
            return self.fail_check(
                check,
                f"Session cookie security issues: {len(issues)}",
                evidence="; ".join(issues[:3])
            )
        return self.pass_check(check, "Session cookies have proper security attributes")

    async def _check_oauth_exposure(self, context: ScanContext) -> CheckResult:
        """CR-007: Check for OAuth token exposure."""
        check = self.checks[6]

        oauth_patterns = [
            r'access_token=([a-zA-Z0-9_-]{20,})',
            r'oauth_token=([a-zA-Z0-9_-]{20,})',
            r'bearer\s+([a-zA-Z0-9_-]{20,})',
        ]

        found = []
        for pattern in oauth_patterns:
            matches = re.findall(pattern, context.url + context.html_content, re.IGNORECASE)
            found.extend(matches)

        if found:
            return self.fail_check(
                check,
                f"OAuth tokens potentially exposed: {len(found)}",
                evidence="OAuth token patterns found"
            )
        return self.pass_check(check, "No OAuth token exposure detected")

    async def _check_cloud_keys(self, context: ScanContext) -> CheckResult:
        """CR-008: Check for cloud provider keys."""
        check = self.checks[7]

        cloud_patterns = {
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret Key': r'(?:aws)?_?(?:secret)?_?(?:access)?_?key["\s:=]+["\']?([A-Za-z0-9/+=]{40})',
            'GCP API Key': r'AIza[0-9A-Za-z_-]{35}',
            'Azure Key': r'(?:AccountKey|SharedAccessKey)["\s:=]+["\']?([A-Za-z0-9+/=]{44,})',
        }

        found = []
        for name, pattern in cloud_patterns.items():
            if re.search(pattern, context.html_content):
                found.append(name)

        if found:
            return self.fail_check(
                check,
                f"Cloud provider credentials detected: {', '.join(found)}",
                evidence="CRITICAL: Rotate these keys immediately!"
            )
        return self.pass_check(check, "No cloud provider keys detected")

    async def _check_db_connection_strings(self, context: ScanContext) -> CheckResult:
        """CR-009: Check for database connection strings."""
        check = self.checks[8]

        db_patterns = [
            r'(?:mongodb|postgres|mysql|mssql|redis)://[^\s<>"\']+',
            r'(?:Server|Data Source)=[^;]+;.*(?:Password|Pwd)=[^;]+',
            r'(?:connection[_-]?string|db[_-]?url)\s*[=:]\s*["\'][^"\']+["\']',
        ]

        for pattern in db_patterns:
            if re.search(pattern, context.html_content, re.IGNORECASE):
                return self.fail_check(
                    check,
                    "Database connection string detected in response",
                    evidence="Connection string pattern found"
                )
        return self.pass_check(check, "No database connection strings exposed")

    async def _check_private_keys(self, context: ScanContext) -> CheckResult:
        """CR-010: Check for private key exposure."""
        check = self.checks[9]

        key_patterns = [
            r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            r'privateKey\s*[=:]\s*["\'][^"\']{50,}',
        ]

        for pattern in key_patterns:
            if re.search(pattern, context.html_content, re.IGNORECASE):
                return self.fail_check(
                    check,
                    "Private key detected in response",
                    evidence="CRITICAL: Private key exposed!"
                )
        return self.pass_check(check, "No private keys detected")
