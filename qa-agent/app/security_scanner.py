"""
Security Scanner - OWASP, VAPT, and Compliance Framework Scanning
Provides automated security testing aligned with industry standards
"""
import os
import re
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Framework(str, Enum):
    OWASP_TOP_10 = "owasp_top_10"
    VAPT = "vapt"
    ISO_27001 = "iso_27001"
    SOC_2 = "soc_2"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"


@dataclass
class Vulnerability:
    id: str
    title: str
    description: str
    severity: Severity
    framework: Framework
    category: str
    evidence: str
    recommendation: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None


@dataclass
class SecurityScanResult:
    scan_id: str
    target_url: str
    started_at: str
    completed_at: str
    overall_score: int
    vulnerabilities: List[Vulnerability]
    framework_scores: Dict[str, int]
    summary: Dict[str, Any]


class SecurityScanner:
    """
    AI-powered security scanner supporting multiple frameworks:
    - OWASP Top 10
    - VAPT (Vulnerability Assessment & Penetration Testing)
    - ISO 27001
    - SOC 2
    - PCI DSS
    - GDPR
    """

    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.checks_performed = 0
        self.checks_passed = 0

    async def scan(
        self,
        url: str,
        page_content: str,
        headers: Dict[str, str],
        cookies: List[Dict],
        forms: List[Dict],
        frameworks: List[Framework] = None
    ) -> SecurityScanResult:
        """
        Perform a comprehensive security scan
        """
        if frameworks is None:
            frameworks = list(Framework)

        scan_id = f"sec_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        started_at = datetime.now().isoformat()

        self.vulnerabilities = []
        self.checks_performed = 0
        self.checks_passed = 0

        # Run framework-specific checks
        if Framework.OWASP_TOP_10 in frameworks:
            await self._check_owasp_top_10(url, page_content, headers, cookies, forms)

        if Framework.VAPT in frameworks:
            await self._check_vapt(url, page_content, headers)

        if Framework.ISO_27001 in frameworks:
            await self._check_iso_27001(headers)

        if Framework.SOC_2 in frameworks:
            await self._check_soc_2(headers, cookies)

        if Framework.PCI_DSS in frameworks:
            await self._check_pci_dss(url, page_content, forms)

        if Framework.GDPR in frameworks:
            await self._check_gdpr(page_content, cookies)

        completed_at = datetime.now().isoformat()

        # Calculate scores
        framework_scores = self._calculate_framework_scores()
        overall_score = self._calculate_overall_score(framework_scores)

        return SecurityScanResult(
            scan_id=scan_id,
            target_url=url,
            started_at=started_at,
            completed_at=completed_at,
            overall_score=overall_score,
            vulnerabilities=self.vulnerabilities,
            framework_scores=framework_scores,
            summary=self._generate_summary()
        )

    async def _check_owasp_top_10(
        self,
        url: str,
        content: str,
        headers: Dict[str, str],
        cookies: List[Dict],
        forms: List[Dict]
    ):
        """OWASP Top 10 2021 checks"""

        # A01:2021 - Broken Access Control
        self._check("OWASP-A01", "Broken Access Control Check", Framework.OWASP_TOP_10)
        if self._check_cors_misconfiguration(headers):
            self._add_vulnerability(
                id="OWASP-A01-001",
                title="Permissive CORS Policy",
                description="The application has a permissive CORS policy that may allow unauthorized access",
                severity=Severity.HIGH,
                framework=Framework.OWASP_TOP_10,
                category="A01:2021 - Broken Access Control",
                evidence=f"Access-Control-Allow-Origin: {headers.get('access-control-allow-origin', '*')}",
                recommendation="Configure CORS to only allow trusted origins",
                cwe_id="CWE-346"
            )

        # A02:2021 - Cryptographic Failures
        self._check("OWASP-A02", "Cryptographic Failures Check", Framework.OWASP_TOP_10)
        if not url.startswith("https://"):
            self._add_vulnerability(
                id="OWASP-A02-001",
                title="Missing HTTPS",
                description="The application is not using HTTPS encryption",
                severity=Severity.CRITICAL,
                framework=Framework.OWASP_TOP_10,
                category="A02:2021 - Cryptographic Failures",
                evidence=f"URL: {url}",
                recommendation="Implement HTTPS with a valid SSL/TLS certificate",
                cwe_id="CWE-319"
            )

        if not headers.get("strict-transport-security"):
            self._add_vulnerability(
                id="OWASP-A02-002",
                title="Missing HSTS Header",
                description="HTTP Strict Transport Security header is not set",
                severity=Severity.MEDIUM,
                framework=Framework.OWASP_TOP_10,
                category="A02:2021 - Cryptographic Failures",
                evidence="Missing Strict-Transport-Security header",
                recommendation="Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                cwe_id="CWE-523"
            )

        # A03:2021 - Injection
        self._check("OWASP-A03", "Injection Vulnerability Check", Framework.OWASP_TOP_10)
        injection_patterns = [
            r"eval\s*\(",
            r"document\.write\s*\(",
            r"innerHTML\s*=",
            r"\$\{.*\}",  # Template literals that might be vulnerable
        ]
        for pattern in injection_patterns:
            if re.search(pattern, content):
                self._add_vulnerability(
                    id="OWASP-A03-001",
                    title="Potential Injection Point",
                    description="Code pattern that may be vulnerable to injection attacks detected",
                    severity=Severity.MEDIUM,
                    framework=Framework.OWASP_TOP_10,
                    category="A03:2021 - Injection",
                    evidence=f"Pattern found: {pattern}",
                    recommendation="Review and sanitize all dynamic code execution",
                    cwe_id="CWE-94"
                )
                break

        # A04:2021 - Insecure Design
        self._check("OWASP-A04", "Insecure Design Check", Framework.OWASP_TOP_10)

        # A05:2021 - Security Misconfiguration
        self._check("OWASP-A05", "Security Misconfiguration Check", Framework.OWASP_TOP_10)
        security_headers = {
            "x-content-type-options": ("Missing X-Content-Type-Options", Severity.LOW),
            "x-frame-options": ("Missing X-Frame-Options", Severity.MEDIUM),
            "x-xss-protection": ("Missing X-XSS-Protection", Severity.LOW),
            "content-security-policy": ("Missing Content-Security-Policy", Severity.MEDIUM),
        }

        for header, (title, severity) in security_headers.items():
            if not headers.get(header):
                self._add_vulnerability(
                    id=f"OWASP-A05-{header}",
                    title=title,
                    description=f"Security header {header} is not configured",
                    severity=severity,
                    framework=Framework.OWASP_TOP_10,
                    category="A05:2021 - Security Misconfiguration",
                    evidence=f"Missing header: {header}",
                    recommendation=f"Add the {header} security header",
                    cwe_id="CWE-16"
                )

        # A06:2021 - Vulnerable and Outdated Components
        self._check("OWASP-A06", "Vulnerable Components Check", Framework.OWASP_TOP_10)
        outdated_libs = [
            (r"jquery[/-]1\.", "jQuery 1.x", "Upgrade to jQuery 3.x or later"),
            (r"bootstrap[/-][12]\.", "Bootstrap 1.x/2.x", "Upgrade to Bootstrap 5.x"),
            (r"angular[/-]1\.", "AngularJS 1.x", "Migrate to Angular 2+"),
        ]
        for pattern, lib_name, recommendation in outdated_libs:
            if re.search(pattern, content, re.IGNORECASE):
                self._add_vulnerability(
                    id="OWASP-A06-001",
                    title=f"Outdated Library: {lib_name}",
                    description=f"An outdated version of {lib_name} was detected",
                    severity=Severity.MEDIUM,
                    framework=Framework.OWASP_TOP_10,
                    category="A06:2021 - Vulnerable and Outdated Components",
                    evidence=f"Detected: {lib_name}",
                    recommendation=recommendation,
                    cwe_id="CWE-1104"
                )

        # A07:2021 - Identification and Authentication Failures
        self._check("OWASP-A07", "Authentication Check", Framework.OWASP_TOP_10)
        for form in forms:
            if "password" in str(form).lower():
                if not form.get("autocomplete") == "off":
                    self._add_vulnerability(
                        id="OWASP-A07-001",
                        title="Password Autocomplete Enabled",
                        description="Password field allows browser autocomplete",
                        severity=Severity.LOW,
                        framework=Framework.OWASP_TOP_10,
                        category="A07:2021 - Identification and Authentication Failures",
                        evidence="Password input without autocomplete='off'",
                        recommendation="Add autocomplete='off' to password fields",
                        cwe_id="CWE-522"
                    )

        # Check for insecure cookies
        for cookie in cookies:
            if not cookie.get("secure"):
                self._add_vulnerability(
                    id="OWASP-A07-002",
                    title="Insecure Cookie",
                    description=f"Cookie '{cookie.get('name')}' is not marked as Secure",
                    severity=Severity.MEDIUM,
                    framework=Framework.OWASP_TOP_10,
                    category="A07:2021 - Identification and Authentication Failures",
                    evidence=f"Cookie: {cookie.get('name')}",
                    recommendation="Set the Secure flag on all cookies",
                    cwe_id="CWE-614"
                )
            if not cookie.get("httpOnly"):
                self._add_vulnerability(
                    id="OWASP-A07-003",
                    title="Cookie Missing HttpOnly",
                    description=f"Cookie '{cookie.get('name')}' is accessible via JavaScript",
                    severity=Severity.MEDIUM,
                    framework=Framework.OWASP_TOP_10,
                    category="A07:2021 - Identification and Authentication Failures",
                    evidence=f"Cookie: {cookie.get('name')}",
                    recommendation="Set the HttpOnly flag on session cookies",
                    cwe_id="CWE-1004"
                )

        # A08:2021 - Software and Data Integrity Failures
        self._check("OWASP-A08", "Integrity Failures Check", Framework.OWASP_TOP_10)

        # A09:2021 - Security Logging and Monitoring Failures
        self._check("OWASP-A09", "Logging Check", Framework.OWASP_TOP_10)

        # A10:2021 - Server-Side Request Forgery
        self._check("OWASP-A10", "SSRF Check", Framework.OWASP_TOP_10)

    async def _check_vapt(self, url: str, content: str, headers: Dict[str, str]):
        """Vulnerability Assessment and Penetration Testing checks"""

        # Information Disclosure
        self._check("VAPT-INFO", "Information Disclosure Check", Framework.VAPT)
        info_patterns = [
            (r"<!--.*?(password|secret|api[_-]?key|token).*?-->", "Sensitive data in HTML comments"),
            (r"console\.(log|debug|info)\s*\([^)]*?(password|secret|token)", "Debug logs with sensitive data"),
            (r"(error|exception|stack\s*trace)", "Error information disclosure"),
        ]
        for pattern, title in info_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                self._add_vulnerability(
                    id="VAPT-INFO-001",
                    title=title,
                    description="Sensitive information may be exposed in the response",
                    severity=Severity.MEDIUM,
                    framework=Framework.VAPT,
                    category="Information Disclosure",
                    evidence=f"Pattern matched: {pattern[:30]}...",
                    recommendation="Remove sensitive information from client-side code",
                    cwe_id="CWE-200"
                )

        # Server Header Disclosure
        server_header = headers.get("server", "")
        if server_header and any(v in server_header.lower() for v in ["apache", "nginx", "iis"]):
            self._add_vulnerability(
                id="VAPT-INFO-002",
                title="Server Version Disclosure",
                description="Server header reveals version information",
                severity=Severity.LOW,
                framework=Framework.VAPT,
                category="Information Disclosure",
                evidence=f"Server: {server_header}",
                recommendation="Remove or obfuscate server version headers",
                cwe_id="CWE-200"
            )

        # X-Powered-By Header
        if headers.get("x-powered-by"):
            self._add_vulnerability(
                id="VAPT-INFO-003",
                title="Technology Stack Disclosure",
                description="X-Powered-By header reveals technology stack",
                severity=Severity.LOW,
                framework=Framework.VAPT,
                category="Information Disclosure",
                evidence=f"X-Powered-By: {headers.get('x-powered-by')}",
                recommendation="Remove X-Powered-By header",
                cwe_id="CWE-200"
            )

    async def _check_iso_27001(self, headers: Dict[str, str]):
        """ISO 27001 Information Security checks"""

        self._check("ISO-A5", "Access Control Policy Check", Framework.ISO_27001)
        self._check("ISO-A8", "Asset Management Check", Framework.ISO_27001)
        self._check("ISO-A9", "Access Control Check", Framework.ISO_27001)
        self._check("ISO-A10", "Cryptography Check", Framework.ISO_27001)

        # Check for security headers (A.14 System Security)
        if not headers.get("content-security-policy"):
            self._add_vulnerability(
                id="ISO-A14-001",
                title="Missing Content Security Policy",
                description="No CSP header found, which is required for system security",
                severity=Severity.MEDIUM,
                framework=Framework.ISO_27001,
                category="A.14 System Acquisition, Development and Maintenance",
                evidence="Missing Content-Security-Policy header",
                recommendation="Implement a Content Security Policy",
                cwe_id="CWE-1021"
            )

    async def _check_soc_2(self, headers: Dict[str, str], cookies: List[Dict]):
        """SOC 2 Trust Service Criteria checks"""

        # CC6: Logical and Physical Access Controls
        self._check("SOC2-CC6", "Access Control Check", Framework.SOC_2)

        # CC7: System Operations
        self._check("SOC2-CC7", "System Operations Check", Framework.SOC_2)

        # Check session management
        session_cookies = [c for c in cookies if "session" in c.get("name", "").lower()]
        for cookie in session_cookies:
            if not cookie.get("sameSite"):
                self._add_vulnerability(
                    id="SOC2-CC6-001",
                    title="Session Cookie Missing SameSite",
                    description="Session cookie does not have SameSite attribute",
                    severity=Severity.MEDIUM,
                    framework=Framework.SOC_2,
                    category="CC6 - Logical and Physical Access Controls",
                    evidence=f"Cookie: {cookie.get('name')}",
                    recommendation="Set SameSite=Strict or SameSite=Lax on session cookies",
                    cwe_id="CWE-1275"
                )

    async def _check_pci_dss(self, url: str, content: str, forms: List[Dict]):
        """PCI DSS Payment Security checks"""

        # Requirement 4: Encrypt transmission of cardholder data
        self._check("PCI-R4", "Encryption Check", Framework.PCI_DSS)
        if not url.startswith("https://"):
            self._add_vulnerability(
                id="PCI-R4-001",
                title="Unencrypted Data Transmission",
                description="Payment data may be transmitted without encryption",
                severity=Severity.CRITICAL,
                framework=Framework.PCI_DSS,
                category="Requirement 4: Encrypt Transmission",
                evidence=f"Non-HTTPS URL: {url}",
                recommendation="Use HTTPS for all payment-related pages",
                cwe_id="CWE-319"
            )

        # Requirement 6: Develop secure systems
        self._check("PCI-R6", "Secure Development Check", Framework.PCI_DSS)

        # Check for credit card patterns in page (should not be stored/displayed fully)
        cc_pattern = r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"
        if re.search(cc_pattern, content):
            self._add_vulnerability(
                id="PCI-R3-001",
                title="Credit Card Number Exposure",
                description="Possible credit card number found in page content",
                severity=Severity.CRITICAL,
                framework=Framework.PCI_DSS,
                category="Requirement 3: Protect Stored Cardholder Data",
                evidence="Credit card pattern detected in response",
                recommendation="Never display full credit card numbers; mask all but last 4 digits",
                cwe_id="CWE-312"
            )

    async def _check_gdpr(self, content: str, cookies: List[Dict]):
        """GDPR Data Protection checks"""

        # Article 7: Consent
        self._check("GDPR-A7", "Consent Check", Framework.GDPR)
        consent_patterns = [
            r"cookie\s*(policy|consent|banner)",
            r"privacy\s*(policy|notice)",
            r"gdpr",
            r"data\s*protection"
        ]
        has_consent_mechanism = any(re.search(p, content, re.IGNORECASE) for p in consent_patterns)
        if not has_consent_mechanism and len(cookies) > 0:
            self._add_vulnerability(
                id="GDPR-A7-001",
                title="Missing Cookie Consent",
                description="Cookies are set without apparent consent mechanism",
                severity=Severity.MEDIUM,
                framework=Framework.GDPR,
                category="Article 7: Conditions for Consent",
                evidence=f"Found {len(cookies)} cookies without visible consent banner",
                recommendation="Implement a cookie consent banner for GDPR compliance",
                cwe_id="CWE-359"
            )

        # Article 13/14: Information to be provided
        self._check("GDPR-A13", "Privacy Notice Check", Framework.GDPR)

    def _check(self, check_id: str, check_name: str, framework: Framework):
        """Record a security check being performed"""
        self.checks_performed += 1

    def _add_vulnerability(self, **kwargs):
        """Add a vulnerability finding"""
        vuln = Vulnerability(**kwargs)
        self.vulnerabilities.append(vuln)

    def _check_cors_misconfiguration(self, headers: Dict[str, str]) -> bool:
        """Check for CORS misconfiguration"""
        cors_origin = headers.get("access-control-allow-origin", "")
        cors_credentials = headers.get("access-control-allow-credentials", "")

        if cors_origin == "*":
            return True
        if cors_credentials.lower() == "true" and cors_origin == "*":
            return True
        return False

    def _calculate_framework_scores(self) -> Dict[str, int]:
        """Calculate score for each framework"""
        scores = {}
        for framework in Framework:
            framework_vulns = [v for v in self.vulnerabilities if v.framework == framework]

            # Deduct points based on severity
            deductions = {
                Severity.CRITICAL: 25,
                Severity.HIGH: 15,
                Severity.MEDIUM: 8,
                Severity.LOW: 3,
                Severity.INFO: 1
            }

            score = 100
            for vuln in framework_vulns:
                score -= deductions.get(vuln.severity, 0)

            scores[framework.value] = max(0, score)

        return scores

    def _calculate_overall_score(self, framework_scores: Dict[str, int]) -> int:
        """Calculate overall security score"""
        if not framework_scores:
            return 100
        return round(sum(framework_scores.values()) / len(framework_scores))

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate scan summary"""
        severity_counts = {s.value: 0 for s in Severity}
        for vuln in self.vulnerabilities:
            severity_counts[vuln.severity.value] += 1

        return {
            "total_vulnerabilities": len(self.vulnerabilities),
            "by_severity": severity_counts,
            "checks_performed": self.checks_performed,
            "critical_issues": severity_counts.get("critical", 0),
            "high_issues": severity_counts.get("high", 0),
            "needs_attention": severity_counts.get("critical", 0) + severity_counts.get("high", 0) > 0
        }


def generate_security_report(result: SecurityScanResult) -> str:
    """Generate a markdown security report"""
    report = f"""# Security Scan Report

## Overview

| | |
|---|---|
| **Scan ID** | `{result.scan_id}` |
| **Target** | {result.target_url} |
| **Started** | {result.started_at} |
| **Completed** | {result.completed_at} |
| **Overall Score** | **{result.overall_score}/100** |

## Executive Summary

Total vulnerabilities found: **{result.summary['total_vulnerabilities']}**

| Severity | Count |
|----------|-------|
| Critical | {result.summary['by_severity']['critical']} |
| High | {result.summary['by_severity']['high']} |
| Medium | {result.summary['by_severity']['medium']} |
| Low | {result.summary['by_severity']['low']} |
| Info | {result.summary['by_severity']['info']} |

## Framework Compliance Scores

| Framework | Score |
|-----------|-------|
"""
    for framework, score in result.framework_scores.items():
        status = "PASS" if score >= 80 else "WARN" if score >= 60 else "FAIL"
        report += f"| {framework.replace('_', ' ').title()} | {score}% ({status}) |\n"

    report += "\n## Vulnerabilities\n\n"

    if not result.vulnerabilities:
        report += "No vulnerabilities found.\n"
    else:
        # Group by severity
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            vulns = [v for v in result.vulnerabilities if v.severity == severity]
            if vulns:
                report += f"### {severity.value.upper()} ({len(vulns)})\n\n"
                for vuln in vulns:
                    report += f"""#### {vuln.title}

- **ID**: {vuln.id}
- **Category**: {vuln.category}
- **CWE**: {vuln.cwe_id or 'N/A'}
- **Description**: {vuln.description}
- **Evidence**: `{vuln.evidence}`
- **Recommendation**: {vuln.recommendation}

---

"""

    report += f"""
## Recommendations

"""
    if result.summary['critical_issues'] > 0:
        report += "### Immediate Action Required\n"
        report += "Critical vulnerabilities were found. Address these immediately:\n\n"
        for vuln in result.vulnerabilities:
            if vuln.severity == Severity.CRITICAL:
                report += f"- **{vuln.title}**: {vuln.recommendation}\n"
        report += "\n"

    if result.summary['high_issues'] > 0:
        report += "### High Priority\n"
        report += "High severity issues should be addressed soon:\n\n"
        for vuln in result.vulnerabilities:
            if vuln.severity == Severity.HIGH:
                report += f"- **{vuln.title}**: {vuln.recommendation}\n"
        report += "\n"

    report += """
---

*Report generated by TestGuard AI Security Scanner*
"""
    return report
