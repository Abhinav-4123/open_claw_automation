"""
NEXUS QA - Business Logic Security Checks
Category 8: 8 checks for workflow bypass, race conditions, logic flaws.
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


class BusinessLogicChecker(BaseSecurityChecker):
    """Business Logic Security checks - workflow, race conditions, logic flaws."""

    category = SecurityCategory.BUSINESS_LOGIC
    category_name = "Business Logic Security"

    checks = [
        SecurityCheck(
            id="BL-001",
            name="Workflow Bypass Detection",
            category=SecurityCategory.BUSINESS_LOGIC,
            description="Checks for multi-step workflow bypass vulnerabilities",
            severity=Severity.HIGH,
            remediation="Enforce step sequence server-side, validate state transitions",
            cwe_id="CWE-841",
            owasp_id="A04:2021"
        ),
        SecurityCheck(
            id="BL-002",
            name="Price/Quantity Manipulation",
            category=SecurityCategory.BUSINESS_LOGIC,
            description="Checks for price or quantity manipulation in e-commerce",
            severity=Severity.CRITICAL,
            remediation="Validate prices server-side, never trust client values",
            cwe_id="CWE-20",
            pci_dss="6.5.1"
        ),
        SecurityCheck(
            id="BL-003",
            name="Race Condition Indicators",
            category=SecurityCategory.BUSINESS_LOGIC,
            description="Detects potential race condition vulnerabilities",
            severity=Severity.HIGH,
            remediation="Implement proper locking, use database transactions",
            cwe_id="CWE-362"
        ),
        SecurityCheck(
            id="BL-004",
            name="Insufficient Anti-Automation",
            category=SecurityCategory.BUSINESS_LOGIC,
            description="Checks for protection against automated attacks",
            severity=Severity.MEDIUM,
            remediation="Implement CAPTCHA, rate limiting, and bot detection",
            cwe_id="CWE-799"
        ),
        SecurityCheck(
            id="BL-005",
            name="Mass Assignment Vulnerability",
            category=SecurityCategory.BUSINESS_LOGIC,
            description="Checks for mass assignment/parameter pollution risks",
            severity=Severity.HIGH,
            remediation="Whitelist allowed parameters, use DTOs",
            cwe_id="CWE-915",
            owasp_id="A04:2021"
        ),
        SecurityCheck(
            id="BL-006",
            name="Insecure Direct Object Reference (Functional)",
            category=SecurityCategory.BUSINESS_LOGIC,
            description="Checks for functional-level IDOR vulnerabilities",
            severity=Severity.HIGH,
            remediation="Implement function-level access control checks",
            cwe_id="CWE-639",
            owasp_id="A01:2021"
        ),
        SecurityCheck(
            id="BL-007",
            name="Missing Transaction Integrity",
            category=SecurityCategory.BUSINESS_LOGIC,
            description="Checks for transaction integrity validation",
            severity=Severity.HIGH,
            remediation="Implement idempotency keys, validate transaction state",
            cwe_id="CWE-367"
        ),
        SecurityCheck(
            id="BL-008",
            name="Trust Boundary Violation",
            category=SecurityCategory.BUSINESS_LOGIC,
            description="Checks for trust boundary violations",
            severity=Severity.MEDIUM,
            remediation="Never trust client-side validation, re-validate server-side",
            cwe_id="CWE-501"
        ),
    ]

    async def run_checks(self, context: ScanContext) -> List[CheckResult]:
        """Run all business logic checks."""
        results = []

        results.append(await self._check_workflow_bypass(context))
        results.append(await self._check_price_manipulation(context))
        results.append(await self._check_race_conditions(context))
        results.append(await self._check_anti_automation(context))
        results.append(await self._check_mass_assignment(context))
        results.append(await self._check_functional_idor(context))
        results.append(await self._check_transaction_integrity(context))
        results.append(await self._check_trust_boundary(context))

        return results

    async def _check_workflow_bypass(self, context: ScanContext) -> CheckResult:
        """BL-001: Check for workflow bypass vulnerabilities."""
        check = self.checks[0]

        # Look for multi-step workflow indicators
        workflow_patterns = [
            r'step\s*[=:]\s*["\']?\d+',
            r'stage\s*[=:]\s*["\']?\d+',
            r'phase\s*[=:]\s*["\']?\w+',
            r'wizard[-_]?step',
            r'checkout[-_]?step',
            r'registration[-_]?step',
        ]

        found_workflows = []
        for pattern in workflow_patterns:
            if re.search(pattern, context.html_content, re.IGNORECASE):
                found_workflows.append(pattern.split(r'\s')[0])

        # Check URL for step parameters
        url_step = re.search(r'[?&](step|stage|phase)=(\d+)', context.url, re.IGNORECASE)

        if url_step or found_workflows:
            # Check for hidden fields that control workflow
            hidden_steps = re.findall(
                r'<input[^>]*type=["\']hidden["\'][^>]*name=["\'](?:step|stage|phase)["\'][^>]*>',
                context.html_content,
                re.IGNORECASE
            )

            if hidden_steps:
                return self.warn_check(
                    check,
                    "Multi-step workflow with client-controllable step indicator",
                    evidence="Hidden fields control workflow - verify server-side validation"
                )

            return self.warn_check(
                check,
                "Multi-step workflow detected",
                evidence="Verify step sequence is enforced server-side"
            )

        return self.pass_check(check, "No obvious workflow bypass vectors detected")

    async def _check_price_manipulation(self, context: ScanContext) -> CheckResult:
        """BL-002: Check for price/quantity manipulation."""
        check = self.checks[1]

        # Look for e-commerce indicators
        ecommerce_patterns = [
            r'<input[^>]*name=["\'](?:price|amount|total|quantity|qty)["\'][^>]*>',
            r'price\s*[=:]\s*[\d.]+',
            r'data-price\s*=\s*["\'][\d.]+["\']',
            r'total[_-]?amount',
            r'order[_-]?total',
        ]

        found_price_fields = []
        for pattern in ecommerce_patterns:
            if re.search(pattern, context.html_content, re.IGNORECASE):
                found_price_fields.append(pattern.split(r'\s')[0])

        if found_price_fields:
            # Check for hidden price fields (very risky)
            hidden_prices = re.findall(
                r'<input[^>]*type=["\']hidden["\'][^>]*(?:name|id)=["\'](?:price|amount|total)["\'][^>]*value=["\']([^"\']+)["\']',
                context.html_content,
                re.IGNORECASE
            )

            if hidden_prices:
                return self.fail_check(
                    check,
                    "Price values in hidden form fields",
                    evidence="Client-controllable price - CRITICAL security risk"
                )

            # Check for editable price inputs
            editable_prices = re.findall(
                r'<input[^>]*(?:name|id)=["\'](?:price|amount)["\'][^>]*(?!type=["\']hidden)',
                context.html_content,
                re.IGNORECASE
            )

            if editable_prices:
                return self.warn_check(
                    check,
                    "Editable price/amount fields detected",
                    evidence="Verify server-side price validation"
                )

        return self.pass_check(check, "No price manipulation vectors detected")

    async def _check_race_conditions(self, context: ScanContext) -> CheckResult:
        """BL-003: Check for race condition indicators."""
        check = self.checks[2]

        # Look for operations that could be race-prone
        race_prone_patterns = [
            r'balance', r'credits?', r'points?', r'inventory',
            r'stock', r'available', r'quantity', r'limit',
            r'coupon', r'voucher', r'redeem', r'transfer',
        ]

        found_sensitive = []
        content_lower = context.html_content.lower()

        for pattern in race_prone_patterns:
            if pattern in content_lower:
                found_sensitive.append(pattern)

        # Check for AJAX calls that modify state
        ajax_patterns = [
            r'fetch\s*\([^)]*(?:POST|PUT|DELETE)',
            r'\.ajax\s*\([^)]*type\s*:\s*["\'](?:POST|PUT|DELETE)',
            r'axios\.(?:post|put|delete)',
        ]

        has_state_changes = any(
            re.search(p, context.html_content, re.IGNORECASE)
            for p in ajax_patterns
        )

        if found_sensitive and has_state_changes:
            return self.warn_check(
                check,
                f"State-modifying operations on sensitive data: {found_sensitive[:3]}",
                evidence="Review for TOCTOU race conditions"
            )

        if found_sensitive:
            return self.warn_check(
                check,
                f"Sensitive operations detected: {found_sensitive[:3]}",
                evidence="Ensure atomic operations and proper locking"
            )

        return self.pass_check(check, "No obvious race condition indicators")

    async def _check_anti_automation(self, context: ScanContext) -> CheckResult:
        """BL-004: Check for anti-automation measures."""
        check = self.checks[3]

        # Look for anti-automation indicators
        automation_protection = {
            'captcha': ['recaptcha', 'hcaptcha', 'captcha', 'turnstile'],
            'csrf': ['csrf', '_token', 'authenticity_token'],
            'honeypot': ['honeypot', 'hp_field', 'trap'],
            'rate_limit': ['rate-limit', 'throttle', 'x-ratelimit'],
        }

        found_protection = []
        content_lower = context.html_content.lower()
        headers_lower = {k.lower(): v for k, v in context.headers.items()}

        for protection_type, patterns in automation_protection.items():
            for pattern in patterns:
                if pattern in content_lower or pattern in str(headers_lower):
                    found_protection.append(protection_type)
                    break

        # Check for forms that might need protection
        forms = re.findall(r'<form[^>]*>', context.html_content, re.IGNORECASE)
        has_forms = len(forms) > 0

        if has_forms and not found_protection:
            return self.warn_check(
                check,
                "Forms found without visible anti-automation protection",
                evidence="Consider adding CAPTCHA, CSRF tokens, rate limiting"
            )

        if found_protection:
            return self.pass_check(
                check,
                f"Anti-automation measures found: {', '.join(set(found_protection))}"
            )

        return self.pass_check(check, "No forms requiring anti-automation detected")

    async def _check_mass_assignment(self, context: ScanContext) -> CheckResult:
        """BL-005: Check for mass assignment vulnerability indicators."""
        check = self.checks[4]

        # Look for forms with many hidden fields
        hidden_fields = re.findall(
            r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\']',
            context.html_content,
            re.IGNORECASE
        )

        # Look for sensitive hidden fields that shouldn't be client-controllable
        sensitive_fields = [
            'role', 'is_admin', 'admin', 'privilege', 'permission',
            'user_id', 'account_id', 'status', 'verified', 'approved'
        ]

        dangerous_fields = [
            f for f in hidden_fields
            if any(s in f.lower() for s in sensitive_fields)
        ]

        if dangerous_fields:
            return self.fail_check(
                check,
                f"Sensitive fields in hidden inputs: {dangerous_fields[:3]}",
                evidence="These fields could be manipulated for privilege escalation"
            )

        # Check for forms that POST all fields
        if len(hidden_fields) > 10:
            return self.warn_check(
                check,
                f"Many hidden fields detected ({len(hidden_fields)})",
                evidence="Review for mass assignment vulnerabilities"
            )

        return self.pass_check(check, "No mass assignment indicators detected")

    async def _check_functional_idor(self, context: ScanContext) -> CheckResult:
        """BL-006: Check for functional-level IDOR."""
        check = self.checks[5]

        # Look for function/action parameters
        function_patterns = [
            r'[?&]action=([^&]+)',
            r'[?&]method=([^&]+)',
            r'[?&]function=([^&]+)',
            r'[?&]cmd=([^&]+)',
            r'[?&]op=([^&]+)',
        ]

        found_functions = []
        for pattern in function_patterns:
            matches = re.findall(pattern, context.url, re.IGNORECASE)
            found_functions.extend(matches)

            for link in context.links:
                matches = re.findall(pattern, link, re.IGNORECASE)
                found_functions.extend(matches)

        # Look for admin/privileged function indicators
        privileged_functions = [
            'delete', 'remove', 'admin', 'manage', 'config',
            'export', 'import', 'backup', 'restore', 'modify'
        ]

        dangerous_functions = [
            f for f in found_functions
            if any(p in f.lower() for p in privileged_functions)
        ]

        if dangerous_functions:
            return self.warn_check(
                check,
                f"Privileged functions in URL: {dangerous_functions[:3]}",
                evidence="Verify function-level authorization checks"
            )

        if found_functions:
            return self.warn_check(
                check,
                f"Function parameters in URLs: {found_functions[:3]}",
                evidence="Ensure proper authorization for each function"
            )

        return self.pass_check(check, "No functional IDOR indicators detected")

    async def _check_transaction_integrity(self, context: ScanContext) -> CheckResult:
        """BL-007: Check for transaction integrity measures."""
        check = self.checks[6]

        # Look for transaction/payment indicators
        transaction_patterns = [
            'payment', 'checkout', 'purchase', 'transaction',
            'transfer', 'withdraw', 'deposit', 'order'
        ]

        has_transactions = any(
            p in context.html_content.lower() or p in context.url.lower()
            for p in transaction_patterns
        )

        if not has_transactions:
            return self.skip_check(check, "No transaction functionality detected")

        # Look for integrity measures
        integrity_patterns = [
            r'idempotency[-_]?key',
            r'transaction[-_]?id',
            r'request[-_]?id',
            r'nonce',
            r'signature',
            r'checksum',
            r'hmac',
        ]

        found_integrity = []
        for pattern in integrity_patterns:
            if re.search(pattern, context.html_content, re.IGNORECASE):
                found_integrity.append(pattern.replace(r'[-_]?', '-'))

        if found_integrity:
            return self.pass_check(
                check,
                f"Transaction integrity measures found: {', '.join(found_integrity[:3])}"
            )

        return self.warn_check(
            check,
            "Transaction functionality without visible integrity measures",
            evidence="Consider adding idempotency keys, checksums"
        )

    async def _check_trust_boundary(self, context: ScanContext) -> CheckResult:
        """BL-008: Check for trust boundary violations."""
        check = self.checks[7]

        # Look for client-side validation only
        client_validation = [
            r'onsubmit\s*=\s*["\'][^"\']*(?:validate|check)',
            r'required\s*(?:=\s*["\']true["\'])?',
            r'pattern\s*=\s*["\'][^"\']+["\']',
            r'minlength|maxlength|min=|max=',
        ]

        has_client_validation = any(
            re.search(p, context.html_content, re.IGNORECASE)
            for p in client_validation
        )

        # Check for forms that rely on JavaScript validation
        js_validation = re.findall(
            r'\.addEventListener\s*\(\s*["\']submit["\']',
            context.html_content,
            re.IGNORECASE
        )

        # Look for hidden fields with calculated values
        calculated_fields = re.findall(
            r'<input[^>]*(?:id|name)=["\'](?:total|sum|calculated|computed)["\'][^>]*>',
            context.html_content,
            re.IGNORECASE
        )

        issues = []

        if calculated_fields:
            issues.append("Client-calculated values in form fields")

        if has_client_validation and not js_validation:
            # HTML5 validation only - could be bypassed
            issues.append("HTML5 validation can be bypassed")

        if issues:
            return self.warn_check(
                check,
                f"Trust boundary concerns: {'; '.join(issues)}",
                evidence="Ensure all validation is repeated server-side"
            )

        return self.pass_check(check, "No obvious trust boundary violations")
