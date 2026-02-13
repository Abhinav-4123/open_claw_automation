"""
NEXUS QA - Injection & Code Execution Checks
Category 6: 12 checks for SQL, XSS, SSTI, command injection.
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


class InjectionChecker(BaseSecurityChecker):
    """Injection & Code Execution checks - SQL, XSS, SSTI, command injection."""

    category = SecurityCategory.INJECTION
    category_name = "Injection & Code Execution"

    checks = [
        SecurityCheck(
            id="IN-001",
            name="Reflected XSS Detection",
            category=SecurityCategory.INJECTION,
            description="Checks for reflected XSS vulnerabilities",
            severity=Severity.HIGH,
            remediation="Implement output encoding and Content Security Policy",
            cwe_id="CWE-79",
            owasp_id="A03:2021"
        ),
        SecurityCheck(
            id="IN-002",
            name="Stored XSS Indicators",
            category=SecurityCategory.INJECTION,
            description="Checks for stored XSS vulnerability indicators",
            severity=Severity.CRITICAL,
            remediation="Sanitize user input, use contextual output encoding",
            cwe_id="CWE-79",
            owasp_id="A03:2021"
        ),
        SecurityCheck(
            id="IN-003",
            name="DOM-based XSS Patterns",
            category=SecurityCategory.INJECTION,
            description="Detects DOM-based XSS vulnerability patterns",
            severity=Severity.HIGH,
            remediation="Avoid innerHTML, use textContent or DOMPurify",
            cwe_id="CWE-79"
        ),
        SecurityCheck(
            id="IN-004",
            name="SQL Injection Indicators",
            category=SecurityCategory.INJECTION,
            description="Checks for SQL injection vulnerability indicators",
            severity=Severity.CRITICAL,
            remediation="Use parameterized queries, never concatenate SQL",
            cwe_id="CWE-89",
            owasp_id="A03:2021"
        ),
        SecurityCheck(
            id="IN-005",
            name="NoSQL Injection Patterns",
            category=SecurityCategory.INJECTION,
            description="Detects NoSQL injection vulnerability patterns",
            severity=Severity.HIGH,
            remediation="Validate input types, avoid $where operators",
            cwe_id="CWE-943"
        ),
        SecurityCheck(
            id="IN-006",
            name="SSTI (Server-Side Template Injection)",
            category=SecurityCategory.INJECTION,
            description="Checks for template injection vulnerabilities",
            severity=Severity.CRITICAL,
            remediation="Use sandboxed templates, avoid user input in templates",
            cwe_id="CWE-1336"
        ),
        SecurityCheck(
            id="IN-007",
            name="Command Injection Patterns",
            category=SecurityCategory.INJECTION,
            description="Detects OS command injection vulnerabilities",
            severity=Severity.CRITICAL,
            remediation="Avoid shell commands, use safe APIs with validation",
            cwe_id="CWE-78",
            owasp_id="A03:2021"
        ),
        SecurityCheck(
            id="IN-008",
            name="LDAP Injection Detection",
            category=SecurityCategory.INJECTION,
            description="Checks for LDAP injection vulnerabilities",
            severity=Severity.HIGH,
            remediation="Escape special LDAP characters in user input",
            cwe_id="CWE-90"
        ),
        SecurityCheck(
            id="IN-009",
            name="XML/XXE Injection",
            category=SecurityCategory.INJECTION,
            description="Checks for XML External Entity vulnerabilities",
            severity=Severity.HIGH,
            remediation="Disable external entity processing, use JSON",
            cwe_id="CWE-611",
            owasp_id="A05:2021"
        ),
        SecurityCheck(
            id="IN-010",
            name="Header Injection",
            category=SecurityCategory.INJECTION,
            description="Checks for HTTP header injection vulnerabilities",
            severity=Severity.MEDIUM,
            remediation="Validate and sanitize header values",
            cwe_id="CWE-113"
        ),
        SecurityCheck(
            id="IN-011",
            name="Path Traversal Detection",
            category=SecurityCategory.INJECTION,
            description="Checks for path traversal vulnerabilities",
            severity=Severity.HIGH,
            remediation="Validate file paths, use allowlist approach",
            cwe_id="CWE-22",
            owasp_id="A01:2021"
        ),
        SecurityCheck(
            id="IN-012",
            name="CRLF Injection",
            category=SecurityCategory.INJECTION,
            description="Checks for CRLF injection vulnerabilities",
            severity=Severity.MEDIUM,
            remediation="Strip CR/LF characters from user input",
            cwe_id="CWE-93"
        ),
    ]

    async def run_checks(self, context: ScanContext) -> List[CheckResult]:
        """Run all injection checks."""
        results = []

        results.append(await self._check_reflected_xss(context))
        results.append(await self._check_stored_xss(context))
        results.append(await self._check_dom_xss(context))
        results.append(await self._check_sql_injection(context))
        results.append(await self._check_nosql_injection(context))
        results.append(await self._check_ssti(context))
        results.append(await self._check_command_injection(context))
        results.append(await self._check_ldap_injection(context))
        results.append(await self._check_xxe(context))
        results.append(await self._check_header_injection(context))
        results.append(await self._check_path_traversal(context))
        results.append(await self._check_crlf_injection(context))

        return results

    async def _check_reflected_xss(self, context: ScanContext) -> CheckResult:
        """IN-001: Check for reflected XSS."""
        check = self.checks[0]

        # Look for URL parameters reflected in response
        url_params = re.findall(r'[?&]([^=]+)=([^&]+)', context.url)
        reflected = []

        for param, value in url_params:
            if len(value) > 3 and value in context.html_content:
                reflected.append(param)

        # Check for dangerous patterns in reflected content
        if reflected:
            # Check if reflected values are in dangerous contexts
            dangerous_contexts = [
                rf'<script[^>]*>{re.escape(value)}',
                rf'on\w+\s*=\s*["\'][^"\']*{re.escape(value)}',
                rf'javascript:[^"\']*{re.escape(value)}',
            ]

            for param, value in url_params:
                for pattern in dangerous_contexts:
                    if re.search(pattern, context.html_content, re.IGNORECASE):
                        return self.fail_check(
                            check,
                            f"Potential reflected XSS: parameter '{param}' in dangerous context",
                            evidence="URL parameter reflected without encoding"
                        )

            return self.warn_check(
                check,
                f"URL parameters reflected in response: {', '.join(reflected[:3])}",
                evidence="Verify output encoding for reflected values"
            )

        return self.pass_check(check, "No reflected XSS patterns detected")

    async def _check_stored_xss(self, context: ScanContext) -> CheckResult:
        """IN-002: Check for stored XSS indicators."""
        check = self.checks[1]

        # Look for user-generated content areas without sanitization
        ugc_patterns = [
            r'<div[^>]*(?:class|id)=["\'][^"\']*(?:comment|post|message|review)[^"\']*["\'][^>]*>',
            r'<textarea[^>]*>.*</textarea>',
            r'contenteditable\s*=\s*["\']true["\']',
        ]

        has_ugc = any(
            re.search(p, context.html_content, re.IGNORECASE)
            for p in ugc_patterns
        )

        if has_ugc:
            # Check for sanitization indicators
            sanitization_patterns = [
                'DOMPurify', 'sanitize', 'xss-filters', 'escape',
                'htmlEntities', 'textContent'
            ]

            has_sanitization = any(
                p.lower() in context.html_content.lower()
                for p in sanitization_patterns
            )

            if not has_sanitization:
                return self.warn_check(
                    check,
                    "User-generated content area without visible sanitization",
                    evidence="Ensure server-side sanitization is implemented"
                )

        return self.pass_check(check, "No stored XSS indicators detected")

    async def _check_dom_xss(self, context: ScanContext) -> CheckResult:
        """IN-003: Check for DOM-based XSS patterns."""
        check = self.checks[2]

        # Dangerous sinks
        dom_xss_sinks = [
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',
            r'document\.write\s*\(',
            r'document\.writeln\s*\(',
            r'eval\s*\(',
            r'setTimeout\s*\([^,]*\+',
            r'setInterval\s*\([^,]*\+',
            r'new\s+Function\s*\(',
        ]

        # Dangerous sources
        dom_xss_sources = [
            r'location\.(?:hash|search|href)',
            r'document\.URL',
            r'document\.referrer',
            r'window\.name',
        ]

        found_sinks = []
        found_sources = []

        for pattern in dom_xss_sinks:
            if re.search(pattern, context.html_content, re.IGNORECASE):
                found_sinks.append(pattern.split(r'\.')[0])

        for pattern in dom_xss_sources:
            if re.search(pattern, context.html_content, re.IGNORECASE):
                found_sources.append(pattern.split(r'\.')[0])

        if found_sinks and found_sources:
            return self.fail_check(
                check,
                "DOM XSS pattern: dangerous sources flow to sinks",
                evidence=f"Sources: {found_sources[:2]}, Sinks: {found_sinks[:2]}"
            )

        if found_sinks:
            return self.warn_check(
                check,
                f"Dangerous DOM sinks found: {', '.join(set(found_sinks))}",
                evidence="Review for potential DOM XSS vulnerabilities"
            )

        return self.pass_check(check, "No DOM XSS patterns detected")

    async def _check_sql_injection(self, context: ScanContext) -> CheckResult:
        """IN-004: Check for SQL injection indicators."""
        check = self.checks[3]

        # SQL error messages that indicate vulnerability
        sql_errors = [
            r'SQL syntax.*MySQL',
            r'Warning.*mysql_',
            r'PostgreSQL.*ERROR',
            r'ORA-\d{5}',
            r'Microsoft SQL.*Server',
            r'ODBC.*Driver',
            r'SQLite.*error',
            r'Unclosed quotation mark',
            r'quoted string not properly terminated',
        ]

        for pattern in sql_errors:
            if re.search(pattern, context.html_content, re.IGNORECASE):
                return self.fail_check(
                    check,
                    "SQL error message exposed in response",
                    evidence="Database error messages visible - potential SQL injection"
                )

        # Check URL for SQL injection patterns
        sqli_url_patterns = [
            r'[?&]\w+=[^&]*(?:\'|"|;|--|\bOR\b|\bAND\b|\bUNION\b)',
        ]

        for pattern in sqli_url_patterns:
            if re.search(pattern, context.url, re.IGNORECASE):
                return self.warn_check(
                    check,
                    "SQL injection payload patterns in URL",
                    evidence="URL contains SQL-like syntax"
                )

        return self.pass_check(check, "No SQL injection indicators detected")

    async def _check_nosql_injection(self, context: ScanContext) -> CheckResult:
        """IN-005: Check for NoSQL injection patterns."""
        check = self.checks[4]

        # NoSQL injection patterns
        nosql_patterns = [
            r'\$where',
            r'\$regex',
            r'\$gt\b',
            r'\$lt\b',
            r'\$ne\b',
            r'\$in\b',
            r'{".*":.*{"\$',
        ]

        found = []
        for pattern in nosql_patterns:
            if re.search(pattern, context.html_content, re.IGNORECASE):
                found.append(pattern.replace('\\', ''))

        if found:
            return self.warn_check(
                check,
                f"NoSQL operator patterns found in response: {found[:3]}",
                evidence="Review for potential NoSQL injection"
            )

        # Check for MongoDB error messages
        mongo_errors = [
            r'MongoError',
            r'MongoDB.*exception',
            r'bson.*error',
        ]

        for pattern in mongo_errors:
            if re.search(pattern, context.html_content, re.IGNORECASE):
                return self.fail_check(
                    check,
                    "MongoDB error message exposed",
                    evidence="Database error indicates potential injection"
                )

        return self.pass_check(check, "No NoSQL injection patterns detected")

    async def _check_ssti(self, context: ScanContext) -> CheckResult:
        """IN-006: Check for SSTI vulnerabilities."""
        check = self.checks[5]

        # Template syntax patterns that might indicate SSTI
        template_patterns = [
            r'\{\{.*\}\}',  # Jinja2, Angular, Vue
            r'\{%.*%\}',    # Jinja2
            r'<%.*%>',      # EJS, ERB
            r'\$\{.*\}',    # JavaScript template literals
            r'#\{.*\}',     # Ruby interpolation
        ]

        # Check if template markers contain user-controllable data
        url_params = re.findall(r'[?&]([^=]+)=([^&]+)', context.url)

        for param, value in url_params:
            if len(value) > 2:
                for pattern in template_patterns:
                    # Check if param value appears within template syntax
                    full_pattern = pattern.replace('.*', f'[^}}]*{re.escape(value)}[^}}]*')
                    if re.search(full_pattern, context.html_content):
                        return self.fail_check(
                            check,
                            f"User input '{param}' may be rendered in template",
                            evidence="Potential SSTI vulnerability"
                        )

        return self.pass_check(check, "No SSTI patterns detected")

    async def _check_command_injection(self, context: ScanContext) -> CheckResult:
        """IN-007: Check for command injection patterns."""
        check = self.checks[6]

        # Command injection patterns in URLs
        cmd_patterns = [
            r'[;&|`$]',
            r'\bexec\b',
            r'\bsystem\b',
            r'\bshell\b',
            r'/bin/',
            r'cmd\.exe',
            r'powershell',
        ]

        # Check URL parameters
        url_params = re.findall(r'[?&]\w+=([^&]+)', context.url)
        for value in url_params:
            for pattern in cmd_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    return self.warn_check(
                        check,
                        "Command injection characters in URL parameters",
                        evidence=f"Special characters detected: {value[:30]}"
                    )

        # Check for error messages indicating command execution
        cmd_errors = [
            r'sh:.*not found',
            r'command not found',
            r'/bin/sh',
            r'subprocess',
            r'child_process',
        ]

        for pattern in cmd_errors:
            if re.search(pattern, context.html_content, re.IGNORECASE):
                return self.fail_check(
                    check,
                    "Command execution error exposed",
                    evidence="System command error in response"
                )

        return self.pass_check(check, "No command injection patterns detected")

    async def _check_ldap_injection(self, context: ScanContext) -> CheckResult:
        """IN-008: Check for LDAP injection."""
        check = self.checks[7]

        # LDAP injection patterns
        ldap_patterns = [
            r'\(\|',
            r'\(&',
            r'\)\)',
            r'\*\)',
            r'objectClass=\*',
        ]

        # Check URL parameters
        for pattern in ldap_patterns:
            if re.search(pattern, context.url):
                return self.warn_check(
                    check,
                    "LDAP special characters in URL",
                    evidence="Potential LDAP injection vector"
                )

        # Check for LDAP error messages
        ldap_errors = [
            r'LDAP.*error',
            r'javax\.naming',
            r'LDAPException',
        ]

        for pattern in ldap_errors:
            if re.search(pattern, context.html_content, re.IGNORECASE):
                return self.fail_check(
                    check,
                    "LDAP error message exposed",
                    evidence="LDAP error indicates potential injection"
                )

        return self.pass_check(check, "No LDAP injection patterns detected")

    async def _check_xxe(self, context: ScanContext) -> CheckResult:
        """IN-009: Check for XXE vulnerabilities."""
        check = self.checks[8]

        # Check for XML content type
        content_type = self.check_header(context.headers, 'Content-Type')
        accepts_xml = content_type and 'xml' in content_type.lower()

        # Check for XML processing indicators
        xml_patterns = [
            r'<!DOCTYPE',
            r'<!ENTITY',
            r'<\?xml',
            r'SYSTEM\s+"file:',
            r'SYSTEM\s+"http:',
        ]

        found_xml = False
        for pattern in xml_patterns:
            if re.search(pattern, context.html_content, re.IGNORECASE):
                found_xml = True
                if 'ENTITY' in pattern or 'SYSTEM' in pattern:
                    return self.fail_check(
                        check,
                        "External entity declaration in response",
                        evidence="XXE vulnerability indicator"
                    )

        # Check for XML processing features
        upload_xml = re.search(
            r'accept=["\'][^"\']*(?:xml|application/xml)',
            context.html_content,
            re.IGNORECASE
        )

        if upload_xml:
            return self.warn_check(
                check,
                "Application accepts XML uploads",
                evidence="Verify XML parser disables external entities"
            )

        return self.pass_check(check, "No XXE vulnerability indicators detected")

    async def _check_header_injection(self, context: ScanContext) -> CheckResult:
        """IN-010: Check for header injection."""
        check = self.checks[9]

        # Check URL parameters for CRLF characters
        url_encoded_crlf = ['%0d', '%0a', '%0D', '%0A']

        for crlf in url_encoded_crlf:
            if crlf in context.url:
                return self.warn_check(
                    check,
                    "URL-encoded CRLF in URL parameters",
                    evidence="Potential header injection vector"
                )

        # Check response headers for injection indicators
        header_patterns = [
            r'Set-Cookie:.*\n.*Set-Cookie:',  # Multiple cookies injected
        ]

        headers_str = str(context.headers)
        for pattern in header_patterns:
            if re.search(pattern, headers_str, re.IGNORECASE):
                return self.warn_check(
                    check,
                    "Unusual header patterns detected",
                    evidence="Review for header injection"
                )

        return self.pass_check(check, "No header injection indicators detected")

    async def _check_path_traversal(self, context: ScanContext) -> CheckResult:
        """IN-011: Check for path traversal."""
        check = self.checks[10]

        # Path traversal patterns
        traversal_patterns = [
            r'\.\./\.\.',
            r'\.\.\\\.\.\\',
            r'%2e%2e%2f',
            r'%2e%2e/',
            r'\.\.%2f',
            r'%2e%2e%5c',
            r'/etc/passwd',
            r'/etc/shadow',
            r'c:\\windows',
            r'c:/windows',
        ]

        # Check URL
        for pattern in traversal_patterns:
            if re.search(pattern, context.url, re.IGNORECASE):
                return self.fail_check(
                    check,
                    "Path traversal pattern in URL",
                    evidence=f"Traversal attempt detected"
                )

        # Check links
        for link in context.links:
            for pattern in traversal_patterns:
                if re.search(pattern, link, re.IGNORECASE):
                    return self.warn_check(
                        check,
                        "Path traversal pattern in page links",
                        evidence="Review file path handling"
                    )

        # Check for file content indicators
        file_disclosure = [
            r'root:.*:0:0:',  # /etc/passwd content
            r'\[boot loader\]',  # Windows boot.ini
        ]

        for pattern in file_disclosure:
            if re.search(pattern, context.html_content):
                return self.fail_check(
                    check,
                    "System file content exposed",
                    evidence="Path traversal exploitation successful"
                )

        return self.pass_check(check, "No path traversal patterns detected")

    async def _check_crlf_injection(self, context: ScanContext) -> CheckResult:
        """IN-012: Check for CRLF injection."""
        check = self.checks[11]

        # CRLF patterns
        crlf_patterns = [
            '%0d%0a',
            '%0D%0A',
            '\\r\\n',
            '\r\n',
        ]

        # Check URL for CRLF
        for pattern in crlf_patterns:
            if pattern in context.url:
                return self.warn_check(
                    check,
                    "CRLF characters in URL",
                    evidence="Potential CRLF injection vector"
                )

        # Check if response shows signs of CRLF injection
        # (e.g., injected headers appearing in body)
        injected_header_patterns = [
            r'HTTP/\d\.\d\s+\d{3}',  # HTTP status in body
            r'Content-Type:.*\n.*<html',  # Headers in HTML
        ]

        for pattern in injected_header_patterns:
            if re.search(pattern, context.html_content, re.IGNORECASE):
                return self.fail_check(
                    check,
                    "HTTP headers appearing in response body",
                    evidence="Possible CRLF injection exploitation"
                )

        return self.pass_check(check, "No CRLF injection patterns detected")
