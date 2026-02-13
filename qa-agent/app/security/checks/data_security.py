"""
NEXUS QA - Data Security Checks
Category 1: 10 checks for PII, encryption, data masking.
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


class DataSecurityChecker(BaseSecurityChecker):
    """Data Security checks - PII detection, encryption, masking."""

    category = SecurityCategory.DATA_SECURITY
    category_name = "Data Security"

    checks = [
        SecurityCheck(
            id="DS-001",
            name="PII Detection in Responses",
            category=SecurityCategory.DATA_SECURITY,
            description="Detects personally identifiable information in API responses",
            severity=Severity.HIGH,
            remediation="Implement data masking and ensure PII is not exposed in responses",
            cwe_id="CWE-359",
            gdpr_article="Article 5"
        ),
        SecurityCheck(
            id="DS-002",
            name="SSN/National ID Exposure",
            category=SecurityCategory.DATA_SECURITY,
            description="Checks for exposed Social Security Numbers or national IDs",
            severity=Severity.CRITICAL,
            remediation="Never expose full SSN/national IDs. Use masking (XXX-XX-1234)",
            cwe_id="CWE-359",
            pci_dss="3.4"
        ),
        SecurityCheck(
            id="DS-003",
            name="Credit Card Data Exposure",
            category=SecurityCategory.DATA_SECURITY,
            description="Detects credit card numbers in responses or logs",
            severity=Severity.CRITICAL,
            remediation="Mask credit card numbers, only show last 4 digits",
            cwe_id="CWE-311",
            pci_dss="3.4"
        ),
        SecurityCheck(
            id="DS-004",
            name="Email Address Harvesting",
            category=SecurityCategory.DATA_SECURITY,
            description="Checks for bulk email exposure that could enable harvesting",
            severity=Severity.MEDIUM,
            remediation="Limit email exposure, implement pagination and rate limiting",
            cwe_id="CWE-359",
            gdpr_article="Article 5"
        ),
        SecurityCheck(
            id="DS-005",
            name="Phone Number Exposure",
            category=SecurityCategory.DATA_SECURITY,
            description="Detects exposed phone numbers without masking",
            severity=Severity.MEDIUM,
            remediation="Mask phone numbers (XXX-XXX-1234) in public responses",
            cwe_id="CWE-359"
        ),
        SecurityCheck(
            id="DS-006",
            name="Address/Location Data Leaks",
            category=SecurityCategory.DATA_SECURITY,
            description="Checks for exposed physical addresses or precise locations",
            severity=Severity.MEDIUM,
            remediation="Avoid exposing precise addresses without user consent",
            gdpr_article="Article 9"
        ),
        SecurityCheck(
            id="DS-007",
            name="Health Data Exposure (HIPAA)",
            category=SecurityCategory.DATA_SECURITY,
            description="Detects protected health information in responses",
            severity=Severity.CRITICAL,
            remediation="Ensure PHI is encrypted and access-controlled per HIPAA",
            cwe_id="CWE-359"
        ),
        SecurityCheck(
            id="DS-008",
            name="Encryption at Rest Indicators",
            category=SecurityCategory.DATA_SECURITY,
            description="Checks for indicators that data encryption is in use",
            severity=Severity.HIGH,
            remediation="Implement AES-256 encryption for sensitive data at rest",
            iso27001="A.10.1.1"
        ),
        SecurityCheck(
            id="DS-009",
            name="Data Masking in UI",
            category=SecurityCategory.DATA_SECURITY,
            description="Verifies sensitive data is masked in user interface",
            severity=Severity.MEDIUM,
            remediation="Implement client-side masking for sensitive fields",
            cwe_id="CWE-359"
        ),
        SecurityCheck(
            id="DS-010",
            name="Response Filtering/Sanitization",
            category=SecurityCategory.DATA_SECURITY,
            description="Checks that responses don't contain unnecessary sensitive data",
            severity=Severity.MEDIUM,
            remediation="Implement response filtering to only return required fields",
            owasp_id="A01:2021"
        ),
    ]

    async def run_checks(self, context: ScanContext) -> List[CheckResult]:
        """Run all data security checks."""
        results = []

        # DS-001: PII Detection
        results.append(await self._check_pii_exposure(context))

        # DS-002: SSN Exposure
        results.append(await self._check_ssn_exposure(context))

        # DS-003: Credit Card Exposure
        results.append(await self._check_credit_card_exposure(context))

        # DS-004: Email Harvesting
        results.append(await self._check_email_exposure(context))

        # DS-005: Phone Number Exposure
        results.append(await self._check_phone_exposure(context))

        # DS-006: Address Exposure
        results.append(await self._check_address_exposure(context))

        # DS-007: Health Data (HIPAA)
        results.append(await self._check_health_data(context))

        # DS-008: Encryption Indicators
        results.append(await self._check_encryption_indicators(context))

        # DS-009: Data Masking
        results.append(await self._check_data_masking(context))

        # DS-010: Response Filtering
        results.append(await self._check_response_filtering(context))

        return results

    async def _check_pii_exposure(self, context: ScanContext) -> CheckResult:
        """DS-001: Check for PII in responses."""
        check = self.checks[0]
        sensitive = self.extract_sensitive_patterns(context.html_content)

        pii_found = []
        if sensitive.get('emails'):
            pii_found.append(f"Emails: {len(sensitive['emails'])} found")
        if sensitive.get('phones'):
            pii_found.append(f"Phone numbers: {len(sensitive['phones'])} found")

        if pii_found:
            return self.fail_check(
                check,
                f"PII detected in response: {', '.join(pii_found)}",
                evidence=str(pii_found)
            )
        return self.pass_check(check, "No obvious PII detected in response")

    async def _check_ssn_exposure(self, context: ScanContext) -> CheckResult:
        """DS-002: Check for SSN exposure."""
        check = self.checks[1]
        ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
        matches = re.findall(ssn_pattern, context.html_content)

        if matches:
            return self.fail_check(
                check,
                f"Potential SSN detected: {len(matches)} instance(s)",
                evidence=f"Pattern matches found: {matches[:3]}"
            )
        return self.pass_check(check, "No SSN patterns detected")

    async def _check_credit_card_exposure(self, context: ScanContext) -> CheckResult:
        """DS-003: Check for credit card numbers."""
        check = self.checks[2]
        cc_patterns = [
            r'\b4[0-9]{12}(?:[0-9]{3})?\b',  # Visa
            r'\b5[1-5][0-9]{14}\b',  # Mastercard
            r'\b3[47][0-9]{13}\b',  # Amex
            r'\b(?:\d{4}[-\s]?){3}\d{4}\b',  # Generic
        ]

        all_matches = []
        for pattern in cc_patterns:
            matches = re.findall(pattern, context.html_content)
            all_matches.extend(matches)

        if all_matches:
            return self.fail_check(
                check,
                f"Potential credit card numbers detected: {len(all_matches)}",
                evidence="Card number patterns found (redacted)"
            )
        return self.pass_check(check, "No credit card patterns detected")

    async def _check_email_exposure(self, context: ScanContext) -> CheckResult:
        """DS-004: Check for bulk email exposure."""
        check = self.checks[3]
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, context.html_content)

        # Filter out common non-PII emails
        filtered = [e for e in emails if not any(
            x in e.lower() for x in ['example.com', 'test.com', 'noreply', 'support@']
        )]

        if len(filtered) > 5:
            return self.warn_check(
                check,
                f"Multiple email addresses exposed: {len(filtered)}",
                evidence=f"Sample: {filtered[:3]}"
            )
        return self.pass_check(check, f"Email exposure within acceptable limits ({len(filtered)})")

    async def _check_phone_exposure(self, context: ScanContext) -> CheckResult:
        """DS-005: Check for phone number exposure."""
        check = self.checks[4]
        phone_patterns = [
            r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',
            r'\b\(\d{3}\)\s?\d{3}[-.\s]?\d{4}\b',
            r'\+1[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',
        ]

        all_matches = []
        for pattern in phone_patterns:
            matches = re.findall(pattern, context.html_content)
            all_matches.extend(matches)

        if len(all_matches) > 3:
            return self.warn_check(
                check,
                f"Multiple phone numbers exposed: {len(all_matches)}",
                evidence=f"Found {len(all_matches)} phone patterns"
            )
        return self.pass_check(check, "Phone number exposure within limits")

    async def _check_address_exposure(self, context: ScanContext) -> CheckResult:
        """DS-006: Check for address/location exposure."""
        check = self.checks[5]
        # Look for US address patterns
        address_pattern = r'\d+\s+[\w\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct)\b'
        matches = re.findall(address_pattern, context.html_content, re.IGNORECASE)

        # Look for coordinates
        coord_pattern = r'-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}'
        coords = re.findall(coord_pattern, context.html_content)

        if matches or coords:
            evidence = []
            if matches:
                evidence.append(f"Addresses: {len(matches)}")
            if coords:
                evidence.append(f"Coordinates: {len(coords)}")
            return self.warn_check(
                check,
                f"Location data detected: {', '.join(evidence)}",
                evidence=str(evidence)
            )
        return self.pass_check(check, "No obvious location data exposure")

    async def _check_health_data(self, context: ScanContext) -> CheckResult:
        """DS-007: Check for health/medical data (HIPAA)."""
        check = self.checks[6]
        health_keywords = [
            'diagnosis', 'prescription', 'medical record', 'patient id',
            'health insurance', 'medicare', 'medicaid', 'icd-10', 'cpt code',
            'blood type', 'allergy', 'medication', 'treatment plan'
        ]

        found = []
        content_lower = context.html_content.lower()
        for keyword in health_keywords:
            if keyword in content_lower:
                found.append(keyword)

        if found:
            return self.warn_check(
                check,
                f"Potential health-related data keywords detected: {len(found)}",
                evidence=f"Keywords: {found[:5]}"
            )
        return self.pass_check(check, "No obvious health data indicators")

    async def _check_encryption_indicators(self, context: ScanContext) -> CheckResult:
        """DS-008: Check for encryption indicators."""
        check = self.checks[7]

        # Check for HTTPS
        if not context.is_https:
            return self.fail_check(
                check,
                "Site not using HTTPS - data in transit not encrypted",
                evidence=f"URL: {context.url}"
            )

        # Check for secure headers
        hsts = self.check_header(context.headers, 'Strict-Transport-Security')
        if hsts:
            return self.pass_check(check, "HTTPS enabled with HSTS header")

        return self.warn_check(
            check,
            "HTTPS enabled but HSTS header missing",
            evidence="Consider adding Strict-Transport-Security header"
        )

    async def _check_data_masking(self, context: ScanContext) -> CheckResult:
        """DS-009: Check for data masking in UI."""
        check = self.checks[8]

        # Look for masked patterns (XXX-XX-XXXX, ****1234, etc.)
        masked_patterns = [
            r'[X*]{3,}[-\s]?[X*]{2,}[-\s]?\d{4}',  # SSN masking
            r'[*]{4,}\d{4}',  # Card masking
            r'[*•●]{4,}',  # General masking
        ]

        masked_found = False
        for pattern in masked_patterns:
            if re.search(pattern, context.html_content):
                masked_found = True
                break

        # Also check for password fields with type="password"
        password_fields = re.findall(r'type=["\']password["\']', context.html_content, re.IGNORECASE)

        if masked_found or password_fields:
            return self.pass_check(check, "Data masking indicators found in UI")
        return self.warn_check(
            check,
            "No obvious data masking detected - verify sensitive fields are masked",
            evidence="Check password and sensitive data fields"
        )

    async def _check_response_filtering(self, context: ScanContext) -> CheckResult:
        """DS-010: Check response filtering/sanitization."""
        check = self.checks[9]

        # Look for signs of over-exposure (debug info, stack traces, etc.)
        debug_patterns = [
            r'stack\s*trace',
            r'debug\s*=\s*true',
            r'__debug__',
            r'traceback',
            r'exception\s+in',
            r'error\s+at\s+line',
        ]

        debug_found = []
        for pattern in debug_patterns:
            if re.search(pattern, context.html_content, re.IGNORECASE):
                debug_found.append(pattern)

        if debug_found:
            return self.fail_check(
                check,
                "Debug/error information detected in response",
                evidence=f"Patterns found: {debug_found[:3]}"
            )
        return self.pass_check(check, "No debug information leakage detected")
