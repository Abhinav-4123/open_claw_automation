"""
NEXUS QA - Authentication & Authorization Checks
Category 5: 12 checks for session, RBAC, IDOR, privilege escalation.
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


class AuthenticationChecker(BaseSecurityChecker):
    """Authentication & Authorization checks."""

    category = SecurityCategory.AUTHENTICATION
    category_name = "Authentication & Authorization"

    checks = [
        SecurityCheck(
            id="AU-001",
            name="Session Fixation Prevention",
            category=SecurityCategory.AUTHENTICATION,
            description="Checks if session ID changes after login",
            severity=Severity.HIGH,
            remediation="Regenerate session ID after successful authentication",
            cwe_id="CWE-384",
            owasp_id="A07:2021"
        ),
        SecurityCheck(
            id="AU-002",
            name="Session Hijacking Prevention",
            category=SecurityCategory.AUTHENTICATION,
            description="Validates session token security measures",
            severity=Severity.HIGH,
            remediation="Use Secure, HttpOnly cookies and implement session binding",
            cwe_id="CWE-614"
        ),
        SecurityCheck(
            id="AU-003",
            name="Cookie Security Flags",
            category=SecurityCategory.AUTHENTICATION,
            description="Checks Secure, HttpOnly, SameSite cookie flags",
            severity=Severity.HIGH,
            remediation="Set Secure, HttpOnly, SameSite=Strict on auth cookies",
            cwe_id="CWE-614",
            owasp_id="A07:2021"
        ),
        SecurityCheck(
            id="AU-004",
            name="RBAC Implementation",
            category=SecurityCategory.AUTHENTICATION,
            description="Checks for role-based access control indicators",
            severity=Severity.MEDIUM,
            remediation="Implement proper RBAC with least privilege principle",
            cwe_id="CWE-285",
            owasp_id="A01:2021"
        ),
        SecurityCheck(
            id="AU-005",
            name="Privilege Escalation Vectors",
            category=SecurityCategory.AUTHENTICATION,
            description="Identifies potential privilege escalation paths",
            severity=Severity.CRITICAL,
            remediation="Validate permissions server-side for all operations",
            cwe_id="CWE-269",
            owasp_id="A01:2021"
        ),
        SecurityCheck(
            id="AU-006",
            name="IDOR Vulnerability Indicators",
            category=SecurityCategory.AUTHENTICATION,
            description="Checks for Insecure Direct Object References",
            severity=Severity.HIGH,
            remediation="Implement authorization checks for all object access",
            cwe_id="CWE-639",
            owasp_id="A01:2021"
        ),
        SecurityCheck(
            id="AU-007",
            name="JWT Algorithm Validation",
            category=SecurityCategory.AUTHENTICATION,
            description="Validates JWT implementation security",
            severity=Severity.CRITICAL,
            remediation="Enforce RS256/ES256, reject 'none' algorithm",
            cwe_id="CWE-327"
        ),
        SecurityCheck(
            id="AU-008",
            name="Token Expiration Configuration",
            category=SecurityCategory.AUTHENTICATION,
            description="Checks if tokens have reasonable expiration",
            severity=Severity.MEDIUM,
            remediation="Set appropriate token expiration (15min-24h)",
            cwe_id="CWE-613"
        ),
        SecurityCheck(
            id="AU-009",
            name="Password Policy Enforcement",
            category=SecurityCategory.AUTHENTICATION,
            description="Validates password complexity requirements",
            severity=Severity.MEDIUM,
            remediation="Enforce min 12 chars, complexity, breach checking",
            cwe_id="CWE-521",
            owasp_id="A07:2021"
        ),
        SecurityCheck(
            id="AU-010",
            name="MFA Implementation Check",
            category=SecurityCategory.AUTHENTICATION,
            description="Checks for multi-factor authentication support",
            severity=Severity.MEDIUM,
            remediation="Implement TOTP or WebAuthn for MFA",
            cwe_id="CWE-308"
        ),
        SecurityCheck(
            id="AU-011",
            name="Account Lockout Policy",
            category=SecurityCategory.AUTHENTICATION,
            description="Validates account lockout after failed attempts",
            severity=Severity.MEDIUM,
            remediation="Lock account after 5 failed attempts for 15 minutes",
            cwe_id="CWE-307"
        ),
        SecurityCheck(
            id="AU-012",
            name="Logout Token Invalidation",
            category=SecurityCategory.AUTHENTICATION,
            description="Checks if tokens are invalidated on logout",
            severity=Severity.MEDIUM,
            remediation="Invalidate all tokens server-side on logout",
            cwe_id="CWE-613"
        ),
    ]

    async def run_checks(self, context: ScanContext) -> List[CheckResult]:
        """Run all authentication checks."""
        results = []

        results.append(await self._check_session_fixation(context))
        results.append(await self._check_session_hijacking(context))
        results.append(await self._check_cookie_flags(context))
        results.append(await self._check_rbac(context))
        results.append(await self._check_privilege_escalation(context))
        results.append(await self._check_idor(context))
        results.append(await self._check_jwt_algorithm(context))
        results.append(await self._check_token_expiration(context))
        results.append(await self._check_password_policy(context))
        results.append(await self._check_mfa(context))
        results.append(await self._check_account_lockout(context))
        results.append(await self._check_logout_invalidation(context))

        return results

    async def _check_session_fixation(self, context: ScanContext) -> CheckResult:
        """AU-001: Check session fixation prevention."""
        check = self.checks[0]

        # Look for session regeneration indicators
        regen_patterns = [
            'session_regenerate', 'regenerateId', 'rotate.*session',
            'new.*session.*id', r'session\.create'
        ]

        has_regen = any(
            re.search(p, context.html_content, re.IGNORECASE)
            for p in regen_patterns
        )

        # Check if there's a login form
        has_login = 'type="password"' in context.html_content.lower()

        if has_login:
            return self.warn_check(
                check,
                "Login form detected - verify session ID regeneration after login",
                evidence="Ensure session ID changes after successful authentication"
            )

        return self.pass_check(check, "No login form - session fixation check N/A")

    async def _check_session_hijacking(self, context: ScanContext) -> CheckResult:
        """AU-002: Check session hijacking prevention."""
        check = self.checks[1]

        issues = []

        # Check for session cookies
        session_cookies = [
            name for name in context.cookies
            if any(x in name.lower() for x in ['session', 'sid', 'auth', 'token'])
        ]

        if not session_cookies:
            return self.skip_check(check, "No session cookies detected")

        # Check for binding indicators
        if not context.is_https:
            issues.append("Not using HTTPS")

        # Check for IP/UA binding in headers
        binding_headers = ['X-Session-Bound', 'X-Client-IP']
        has_binding = any(self.has_header(context.headers, h) for h in binding_headers)

        if not has_binding:
            issues.append("No session binding indicators")

        if issues:
            return self.warn_check(
                check,
                f"Session hijacking concerns: {', '.join(issues)}",
                evidence="Consider IP/UA binding and HTTPS enforcement"
            )

        return self.pass_check(check, "Session hijacking protections in place")

    async def _check_cookie_flags(self, context: ScanContext) -> CheckResult:
        """AU-003: Check cookie security flags."""
        check = self.checks[2]

        issues = []
        secure_cookies = 0

        for name, cookie in context.cookies.items():
            cookie_str = str(cookie).lower()

            is_auth_cookie = any(
                x in name.lower() for x in ['session', 'auth', 'token', 'sid', 'jwt']
            )

            if is_auth_cookie:
                if 'httponly' not in cookie_str:
                    issues.append(f"{name}: missing HttpOnly")
                if context.is_https and 'secure' not in cookie_str:
                    issues.append(f"{name}: missing Secure")
                if 'samesite' not in cookie_str:
                    issues.append(f"{name}: missing SameSite")
                else:
                    secure_cookies += 1

        if issues:
            return self.fail_check(
                check,
                f"Cookie security issues: {len(issues)}",
                evidence="; ".join(issues[:5])
            )

        if secure_cookies > 0:
            return self.pass_check(check, f"{secure_cookies} auth cookies properly secured")

        return self.skip_check(check, "No auth cookies to analyze")

    async def _check_rbac(self, context: ScanContext) -> CheckResult:
        """AU-004: Check RBAC implementation indicators."""
        check = self.checks[3]

        rbac_patterns = [
            'role', 'permission', 'admin', 'user.*level',
            'access.*control', 'authorize', 'can_access'
        ]

        found = []
        for pattern in rbac_patterns:
            if re.search(pattern, context.html_content, re.IGNORECASE):
                found.append(pattern)

        if found:
            return self.pass_check(
                check,
                f"RBAC indicators found: {', '.join(found[:3])}"
            )

        return self.warn_check(
            check,
            "No obvious RBAC implementation detected",
            evidence="Ensure server-side authorization is implemented"
        )

    async def _check_privilege_escalation(self, context: ScanContext) -> CheckResult:
        """AU-005: Check for privilege escalation vectors."""
        check = self.checks[4]

        # Look for admin/elevated privilege indicators
        priv_patterns = [
            r'isAdmin\s*[=:]\s*(true|1)',
            r'role\s*[=:]\s*["\']admin["\']',
            r'admin\s*[=:]\s*true',
            r'privilege.*level',
        ]

        found = []
        for pattern in priv_patterns:
            if re.search(pattern, context.html_content, re.IGNORECASE):
                found.append(pattern.split(r'\s')[0])

        if found:
            return self.warn_check(
                check,
                "Privilege indicators in client-side code",
                evidence="Ensure authorization is validated server-side"
            )

        return self.pass_check(check, "No obvious client-side privilege escalation vectors")

    async def _check_idor(self, context: ScanContext) -> CheckResult:
        """AU-006: Check for IDOR indicators."""
        check = self.checks[5]

        # Look for sequential IDs in URLs
        idor_patterns = [
            r'/user/\d+',
            r'/account/\d+',
            r'/order/\d+',
            r'/document/\d+',
            r'\?id=\d+',
            r'\?user_id=\d+',
        ]

        found = []
        all_links = context.links + [context.url]

        for link in all_links:
            for pattern in idor_patterns:
                if re.search(pattern, link, re.IGNORECASE):
                    found.append(pattern)
                    break

        if found:
            return self.warn_check(
                check,
                f"Sequential ID patterns found in URLs: {len(found)}",
                evidence="Verify authorization checks for object access"
            )

        return self.pass_check(check, "No obvious IDOR patterns detected")

    async def _check_jwt_algorithm(self, context: ScanContext) -> CheckResult:
        """AU-007: Check JWT algorithm security."""
        check = self.checks[6]

        # Look for JWT tokens
        jwt_pattern = r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'
        jwts = re.findall(jwt_pattern, context.html_content)

        if not jwts:
            return self.skip_check(check, "No JWT tokens found")

        # Decode header to check algorithm (just base64)
        import base64
        for jwt in jwts[:3]:
            try:
                header = jwt.split('.')[0]
                # Add padding
                header += '=' * (4 - len(header) % 4)
                decoded = base64.urlsafe_b64decode(header).decode('utf-8')

                if '"alg":"none"' in decoded or '"alg":"None"' in decoded:
                    return self.fail_check(
                        check,
                        "JWT with 'none' algorithm detected",
                        evidence="CRITICAL: Algorithm 'none' allows unsigned tokens"
                    )

                if '"alg":"HS256"' in decoded:
                    return self.warn_check(
                        check,
                        "JWT using HS256 symmetric algorithm",
                        evidence="Consider RS256/ES256 for better security"
                    )
            except Exception:
                continue

        return self.pass_check(check, "JWT algorithm appears secure")

    async def _check_token_expiration(self, context: ScanContext) -> CheckResult:
        """AU-008: Check token expiration."""
        check = self.checks[7]

        # Look for expiration configuration
        exp_patterns = [
            r'expires?[_-]?in\s*[=:]\s*(\d+)',
            r'token[_-]?expir\w*\s*[=:]\s*(\d+)',
            r'max[_-]?age\s*[=:]\s*(\d+)',
        ]

        for pattern in exp_patterns:
            match = re.search(pattern, context.html_content, re.IGNORECASE)
            if match:
                try:
                    value = int(match.group(1))
                    # If value seems like seconds
                    if value > 86400 * 7:  # More than 7 days in seconds
                        return self.warn_check(
                            check,
                            f"Token expiration seems too long: {value}",
                            evidence="Consider shorter token lifetime"
                        )
                except ValueError:
                    pass

        return self.pass_check(check, "Token expiration appears reasonable or not exposed")

    async def _check_password_policy(self, context: ScanContext) -> CheckResult:
        """AU-009: Check password policy indicators."""
        check = self.checks[8]

        # Look for password fields
        if 'type="password"' not in context.html_content.lower():
            return self.skip_check(check, "No password fields found")

        # Look for policy indicators
        policy_patterns = [
            r'password.*(?:must|should|require)',
            r'(?:minimum|min).*(?:\d+).*character',
            r'password.*strength',
            r'(?:uppercase|lowercase|number|special)',
        ]

        found = []
        for pattern in policy_patterns:
            if re.search(pattern, context.html_content, re.IGNORECASE):
                found.append(pattern.split(r'\s')[0])

        if found:
            return self.pass_check(check, "Password policy indicators found")

        return self.warn_check(
            check,
            "No visible password policy indicators",
            evidence="Ensure server-side password validation"
        )

    async def _check_mfa(self, context: ScanContext) -> CheckResult:
        """AU-010: Check for MFA implementation."""
        check = self.checks[9]

        mfa_patterns = [
            '2fa', 'two.*factor', 'multi.*factor', 'mfa',
            'authenticator', 'totp', 'otp', 'verification.*code',
            'security.*code', 'webauthn', 'fido'
        ]

        found = []
        for pattern in mfa_patterns:
            if re.search(pattern, context.html_content, re.IGNORECASE):
                found.append(pattern)

        if found:
            return self.pass_check(check, f"MFA indicators found: {found[0]}")

        return self.warn_check(
            check,
            "No MFA implementation detected",
            evidence="Consider implementing TOTP or WebAuthn"
        )

    async def _check_account_lockout(self, context: ScanContext) -> CheckResult:
        """AU-011: Check account lockout policy."""
        check = self.checks[10]

        lockout_patterns = [
            'account.*locked', 'too.*many.*attempts',
            'try.*again.*later', 'locked.*out',
            'maximum.*attempts', 'exceeded.*attempts'
        ]

        for pattern in lockout_patterns:
            if re.search(pattern, context.html_content, re.IGNORECASE):
                return self.pass_check(check, "Account lockout indicators found")

        has_login = 'type="password"' in context.html_content.lower()
        if has_login:
            return self.warn_check(
                check,
                "Login form without visible lockout policy",
                evidence="Implement account lockout after failed attempts"
            )

        return self.skip_check(check, "No login form detected")

    async def _check_logout_invalidation(self, context: ScanContext) -> CheckResult:
        """AU-012: Check logout token invalidation."""
        check = self.checks[11]

        logout_patterns = ['logout', 'sign.*out', 'log.*out']

        has_logout = any(
            re.search(p, context.html_content, re.IGNORECASE)
            for p in logout_patterns
        )

        if has_logout:
            return self.warn_check(
                check,
                "Logout functionality found - verify token invalidation",
                evidence="Ensure tokens are invalidated server-side on logout"
            )

        return self.skip_check(check, "No logout functionality detected")
