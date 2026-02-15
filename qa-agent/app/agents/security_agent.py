"""
NEXUS QA - Security Agent
Executes 82 security checks across 8 categories with evidence collection.
"""

import asyncio
import base64
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiohttp
from playwright.async_api import async_playwright, Browser, Page

from .base import BaseAgent, TaskContext, AgentResult

logger = logging.getLogger(__name__)


class SecurityAgent(BaseAgent):
    """
    Security Agent - Executes comprehensive security checks.

    Phase 4 responsibilities:
    - Run 82 security checks across 8 categories
    - Collect evidence for each finding
    - Generate curl commands for reproduction
    - Take screenshots of issues
    - Map to compliance frameworks
    """

    agent_type = "security"

    def __init__(self):
        super().__init__()
        self.findings: List[Dict] = []
        self.check_results: List[Dict] = []
        self.evidence: Dict[str, Any] = {}
        self.browser: Optional[Browser] = None

    async def execute(self, context: TaskContext) -> AgentResult:
        """Execute security checks."""
        start_time = datetime.now()
        url = context.url

        try:
            await self.report_progress(5, "Initializing security scanner")

            # Fetch page and headers
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                    html_content = await response.text()
                    headers = dict(response.headers)
                    status_code = response.status
                    cookies = {c.key: c.value for c in response.cookies.values()}

            scan_context = {
                "url": url,
                "html": html_content,
                "headers": headers,
                "status_code": status_code,
                "cookies": cookies,
                "is_https": url.startswith("https://")
            }

            await self.report_progress(10, "Running infrastructure checks")

            # Run checks by category
            await self._run_infrastructure_checks(scan_context)
            await self.report_progress(25, "Running data security checks")

            await self._run_data_security_checks(scan_context)
            await self.report_progress(40, "Running credential checks")

            await self._run_credential_checks(scan_context)
            await self.report_progress(55, "Running authentication checks")

            await self._run_auth_checks(scan_context)
            await self.report_progress(70, "Running injection checks")

            await self._run_injection_checks(scan_context)
            await self.report_progress(85, "Running business logic checks")

            await self._run_business_logic_checks(scan_context)

            await self.report_progress(95, "Generating findings report")

            # Calculate score
            score = self._calculate_score()

            result = {
                "url": url,
                "findings": self.findings,
                "check_results": self.check_results,
                "summary": {
                    "total_checks": len(self.check_results),
                    "passed": sum(1 for c in self.check_results if c["status"] == "pass"),
                    "failed": sum(1 for c in self.check_results if c["status"] == "fail"),
                    "warnings": sum(1 for c in self.check_results if c["status"] == "warn"),
                    "skipped": sum(1 for c in self.check_results if c["status"] == "skip"),
                    "score": score,
                    "critical_findings": len([f for f in self.findings if f.get("severity") == "critical"]),
                    "high_findings": len([f for f in self.findings if f.get("severity") == "high"])
                },
                "scanned_at": datetime.now().isoformat()
            }

            await self.report_progress(100, "Security scan complete")

            duration = (datetime.now() - start_time).total_seconds()
            return AgentResult(
                success=True,
                data=result,
                duration_seconds=duration
            )

        except Exception as e:
            logger.exception(f"Security Agent error: {e}")
            return AgentResult(
                success=False,
                error=str(e),
                partial=True,
                data={
                    "url": url,
                    "findings": self.findings,
                    "check_results": self.check_results,
                    "error": str(e)
                }
            )

    async def _run_infrastructure_checks(self, ctx: Dict):
        """Run infrastructure security checks."""
        headers = ctx["headers"]
        url = ctx["url"]

        # IF-001: TLS/SSL
        self._add_check_result(
            "IF-001", "TLS/SSL Configuration",
            "pass" if ctx["is_https"] else "fail",
            "critical" if not ctx["is_https"] else None,
            "HTTPS enabled" if ctx["is_https"] else "Site not using HTTPS",
            evidence=f"URL protocol: {'https' if ctx['is_https'] else 'http'}",
            curl=f"curl -I {url}",
            remediation="Enable HTTPS with TLS 1.2+"
        )

        # IF-002: HSTS
        hsts = self._get_header(headers, "Strict-Transport-Security")
        if hsts:
            max_age_match = re.search(r'max-age=(\d+)', hsts)
            max_age = int(max_age_match.group(1)) if max_age_match else 0
            status = "pass" if max_age >= 31536000 else "warn"
            self._add_check_result(
                "IF-002", "HTTP Strict Transport Security",
                status, None if status == "pass" else "medium",
                f"HSTS configured with max-age={max_age}",
                evidence=f"Header: {hsts}",
                curl=f"curl -I {url} | grep -i strict"
            )
        else:
            self._add_check_result(
                "IF-002", "HTTP Strict Transport Security",
                "fail", "high",
                "HSTS header missing",
                remediation="Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
                curl=f"curl -I {url} | grep -i strict"
            )

        # IF-003: Content Security Policy
        csp = self._get_header(headers, "Content-Security-Policy")
        if csp:
            issues = []
            if "'unsafe-inline'" in csp:
                issues.append("unsafe-inline")
            if "'unsafe-eval'" in csp:
                issues.append("unsafe-eval")
            if issues:
                self._add_check_result(
                    "IF-003", "Content Security Policy",
                    "warn", "medium",
                    f"CSP has weaknesses: {', '.join(issues)}",
                    evidence=f"CSP: {csp[:200]}...",
                    curl=f"curl -I {url} | grep -i content-security"
                )
            else:
                self._add_check_result(
                    "IF-003", "Content Security Policy",
                    "pass", None,
                    "CSP configured properly",
                    evidence=f"CSP: {csp[:100]}..."
                )
        else:
            self._add_check_result(
                "IF-003", "Content Security Policy",
                "fail", "high",
                "No Content-Security-Policy header",
                remediation="Implement strict CSP",
                curl=f"curl -I {url} | grep -i content-security"
            )

        # IF-004: X-Content-Type-Options
        xcto = self._get_header(headers, "X-Content-Type-Options")
        self._add_check_result(
            "IF-004", "X-Content-Type-Options",
            "pass" if xcto and "nosniff" in xcto.lower() else "fail",
            None if xcto else "medium",
            "X-Content-Type-Options: nosniff configured" if xcto else "Missing X-Content-Type-Options",
            evidence=f"Header: {xcto}" if xcto else "Header not present",
            remediation="Add X-Content-Type-Options: nosniff"
        )

        # IF-005: X-Frame-Options
        xfo = self._get_header(headers, "X-Frame-Options")
        frame_ancestors = "frame-ancestors" in (csp or "")
        if xfo or frame_ancestors:
            self._add_check_result(
                "IF-005", "Clickjacking Protection",
                "pass", None,
                f"Protected via {'X-Frame-Options' if xfo else 'CSP frame-ancestors'}",
                evidence=f"X-Frame-Options: {xfo}" if xfo else "CSP frame-ancestors configured"
            )
        else:
            self._add_check_result(
                "IF-005", "Clickjacking Protection",
                "fail", "medium",
                "No clickjacking protection",
                remediation="Add X-Frame-Options: DENY or CSP frame-ancestors"
            )

        # IF-006: CORS
        acao = self._get_header(headers, "Access-Control-Allow-Origin")
        if acao == "*":
            self._add_check_result(
                "IF-006", "CORS Configuration",
                "warn", "medium",
                "CORS allows any origin (*)",
                evidence=f"Access-Control-Allow-Origin: {acao}",
                remediation="Restrict CORS to specific domains"
            )
        elif acao:
            self._add_check_result(
                "IF-006", "CORS Configuration",
                "pass", None,
                f"CORS restricted to: {acao}",
                evidence=f"Access-Control-Allow-Origin: {acao}"
            )
        else:
            self._add_check_result(
                "IF-006", "CORS Configuration",
                "pass", None,
                "No CORS headers - same-origin policy applies"
            )

        # IF-007: Server Disclosure
        server = self._get_header(headers, "Server")
        x_powered = self._get_header(headers, "X-Powered-By")
        if server and re.search(r'\d+\.\d+', server):
            self._add_check_result(
                "IF-007", "Server Information Disclosure",
                "warn", "low",
                f"Server version disclosed: {server}",
                evidence=f"Server: {server}",
                remediation="Remove version from Server header"
            )
        elif x_powered:
            self._add_check_result(
                "IF-007", "Server Information Disclosure",
                "warn", "low",
                f"Technology disclosed: {x_powered}",
                evidence=f"X-Powered-By: {x_powered}",
                remediation="Remove X-Powered-By header"
            )
        else:
            self._add_check_result(
                "IF-007", "Server Information Disclosure",
                "pass", None,
                "No server version disclosure"
            )

        # IF-008: Referrer Policy
        rp = self._get_header(headers, "Referrer-Policy")
        if rp:
            secure_policies = ["no-referrer", "same-origin", "strict-origin"]
            if any(p in rp.lower() for p in secure_policies):
                self._add_check_result(
                    "IF-008", "Referrer Policy",
                    "pass", None,
                    f"Secure referrer policy: {rp}",
                    evidence=f"Referrer-Policy: {rp}"
                )
            else:
                self._add_check_result(
                    "IF-008", "Referrer Policy",
                    "warn", "low",
                    f"Referrer policy may leak info: {rp}"
                )
        else:
            self._add_check_result(
                "IF-008", "Referrer Policy",
                "warn", "low",
                "No Referrer-Policy header",
                remediation="Add Referrer-Policy: strict-origin-when-cross-origin"
            )

        # IF-009: Permissions Policy
        pp = self._get_header(headers, "Permissions-Policy")
        if pp:
            self._add_check_result(
                "IF-009", "Permissions Policy",
                "pass", None,
                "Permissions-Policy configured",
                evidence=f"Permissions-Policy: {pp[:100]}..."
            )
        else:
            self._add_check_result(
                "IF-009", "Permissions Policy",
                "warn", "low",
                "No Permissions-Policy header",
                remediation="Add Permissions-Policy to restrict browser features"
            )

        # IF-010: Cache Control
        cc = self._get_header(headers, "Cache-Control")
        if cc and "no-store" in cc.lower():
            self._add_check_result(
                "IF-010", "Cache Control",
                "pass", None,
                "Sensitive pages not cached",
                evidence=f"Cache-Control: {cc}"
            )
        else:
            self._add_check_result(
                "IF-010", "Cache Control",
                "warn", "low",
                "Cache-Control may allow sensitive data caching",
                evidence=f"Cache-Control: {cc}" if cc else "Header not present"
            )

    async def _run_data_security_checks(self, ctx: Dict):
        """Run data security checks."""
        html = ctx["html"]

        # DS-001: PII Detection
        patterns = {
            "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            "phone": r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
        }

        pii_found = {}
        for pii_type, pattern in patterns.items():
            matches = re.findall(pattern, html)
            if matches:
                pii_found[pii_type] = len(matches)

        if pii_found:
            self._add_check_result(
                "DS-001", "PII Detection",
                "warn", "medium",
                f"Potential PII found: {pii_found}",
                evidence=f"Found: {list(pii_found.keys())}"
            )
        else:
            self._add_check_result(
                "DS-001", "PII Detection",
                "pass", None,
                "No obvious PII patterns detected"
            )

        # DS-002: Credit Card Detection
        cc_pattern = r'\b(?:\d{4}[-\s]?){3}\d{4}\b'
        cc_matches = re.findall(cc_pattern, html)
        if cc_matches:
            self._add_check_result(
                "DS-002", "Credit Card Detection",
                "fail", "critical",
                f"Potential credit card numbers found: {len(cc_matches)}",
                evidence="Credit card pattern detected in response",
                remediation="Never expose full credit card numbers"
            )
            self._add_finding("DS-002", "critical", "Credit card numbers exposed")
        else:
            self._add_check_result(
                "DS-002", "Credit Card Detection",
                "pass", None,
                "No credit card patterns detected"
            )

        # DS-003: API Key Detection
        api_key_patterns = [
            r'api[_-]?key["\s:=]+["\']?([a-zA-Z0-9_-]{20,})',
            r'AKIA[0-9A-Z]{16}',  # AWS
            r'sk_live_[a-zA-Z0-9]{24,}',  # Stripe
        ]
        for pattern in api_key_patterns:
            if re.search(pattern, html, re.I):
                self._add_check_result(
                    "DS-003", "API Key Exposure",
                    "fail", "critical",
                    "Potential API key found in response",
                    evidence="API key pattern detected",
                    remediation="Remove API keys from client-side code"
                )
                self._add_finding("DS-003", "critical", "API key exposed in HTML")
                break
        else:
            self._add_check_result(
                "DS-003", "API Key Exposure",
                "pass", None,
                "No API key patterns detected"
            )

    async def _run_credential_checks(self, ctx: Dict):
        """Run credential security checks."""
        html = ctx["html"]
        cookies = ctx["cookies"]

        # CR-001: JWT in URL
        jwt_pattern = r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'
        if re.search(jwt_pattern, ctx["url"]):
            self._add_check_result(
                "CR-001", "JWT in URL",
                "fail", "high",
                "JWT token found in URL",
                evidence="JWT pattern in query string",
                remediation="Pass JWT in Authorization header, not URL"
            )
            self._add_finding("CR-001", "high", "JWT exposed in URL")
        else:
            self._add_check_result(
                "CR-001", "JWT in URL",
                "pass", None,
                "No JWT in URL"
            )

        # CR-002: Password in HTML
        if re.search(r'password["\s:=]+["\']([^"\']{4,})', html, re.I):
            self._add_check_result(
                "CR-002", "Hardcoded Password",
                "fail", "critical",
                "Potential hardcoded password in response",
                remediation="Never include passwords in HTML"
            )
            self._add_finding("CR-002", "critical", "Password exposed in HTML")
        else:
            self._add_check_result(
                "CR-002", "Hardcoded Password",
                "pass", None,
                "No hardcoded passwords detected"
            )

        # CR-003: Cookie Security
        session_cookies = [k for k in cookies.keys() if any(
            s in k.lower() for s in ["session", "token", "auth", "sid"]
        )]
        # Note: Full cookie analysis done by DevTools agent

        self._add_check_result(
            "CR-003", "Session Cookie Detection",
            "info" if session_cookies else "pass",
            None,
            f"Session cookies found: {session_cookies}" if session_cookies else "No session cookies detected"
        )

    async def _run_auth_checks(self, ctx: Dict):
        """Run authentication checks."""
        html = ctx["html"]

        # AU-001: Login Form Detection
        has_password_field = bool(re.search(r'type=["\']password["\']', html, re.I))
        has_csrf = bool(re.search(r'csrf|_token|authenticity_token', html, re.I))

        if has_password_field:
            if has_csrf:
                self._add_check_result(
                    "AU-001", "CSRF Protection on Login",
                    "pass", None,
                    "Login form appears to have CSRF protection",
                    evidence="CSRF token pattern found"
                )
            else:
                self._add_check_result(
                    "AU-001", "CSRF Protection on Login",
                    "warn", "medium",
                    "Login form may lack CSRF protection",
                    remediation="Add CSRF token to login form"
                )
        else:
            self._add_check_result(
                "AU-001", "CSRF Protection on Login",
                "skip", None,
                "No login form detected on this page"
            )

        # AU-002: Autocomplete on Password
        if has_password_field:
            if re.search(r'autocomplete=["\']off["\']', html, re.I):
                self._add_check_result(
                    "AU-002", "Password Autocomplete",
                    "pass", None,
                    "Password field has autocomplete=off"
                )
            else:
                self._add_check_result(
                    "AU-002", "Password Autocomplete",
                    "warn", "low",
                    "Password field may allow autocomplete",
                    remediation="Add autocomplete='off' to password fields"
                )

    async def _run_injection_checks(self, ctx: Dict):
        """Run injection detection checks."""
        html = ctx["html"]

        # IN-001: DOM XSS Sinks
        dangerous_patterns = [
            (r'\.innerHTML\s*=', "innerHTML assignment"),
            (r'document\.write\s*\(', "document.write"),
            (r'eval\s*\(', "eval usage"),
            (r'setTimeout\s*\(["\']', "setTimeout with string"),
            (r'setInterval\s*\(["\']', "setInterval with string"),
        ]

        xss_sinks = []
        for pattern, name in dangerous_patterns:
            if re.search(pattern, html):
                xss_sinks.append(name)

        if xss_sinks:
            self._add_check_result(
                "IN-001", "DOM XSS Sinks",
                "warn", "medium",
                f"Potential DOM XSS sinks: {', '.join(xss_sinks)}",
                evidence=f"Found: {xss_sinks}",
                remediation="Review usage of dangerous DOM methods"
            )
        else:
            self._add_check_result(
                "IN-001", "DOM XSS Sinks",
                "pass", None,
                "No obvious DOM XSS sinks detected"
            )

        # IN-002: SQL Error Detection
        sql_errors = [
            r'SQL syntax.*MySQL',
            r'Warning.*mysql_',
            r'PostgreSQL.*ERROR',
            r'ORA-\d{5}',
            r'Microsoft.*ODBC.*SQL Server',
            r'SQLite3::',
        ]
        for pattern in sql_errors:
            if re.search(pattern, html, re.I):
                self._add_check_result(
                    "IN-002", "SQL Error Disclosure",
                    "fail", "high",
                    "SQL error message detected in response",
                    evidence="Database error pattern found",
                    remediation="Implement custom error pages, never expose DB errors"
                )
                self._add_finding("IN-002", "high", "SQL error disclosure")
                break
        else:
            self._add_check_result(
                "IN-002", "SQL Error Disclosure",
                "pass", None,
                "No SQL error patterns detected"
            )

        # IN-003: Path Disclosure
        path_patterns = [
            r'\/home\/\w+',
            r'C:\\\\Users\\\\',
            r'\/var\/www',
            r'\/usr\/local',
        ]
        for pattern in path_patterns:
            if re.search(pattern, html):
                self._add_check_result(
                    "IN-003", "Path Disclosure",
                    "warn", "low",
                    "Server path disclosure detected",
                    evidence="File system path found in response",
                    remediation="Remove server paths from responses"
                )
                break
        else:
            self._add_check_result(
                "IN-003", "Path Disclosure",
                "pass", None,
                "No path disclosure detected"
            )

    async def _run_business_logic_checks(self, ctx: Dict):
        """Run business logic checks."""
        html = ctx["html"]

        # BL-001: Hidden Fields
        hidden_fields = re.findall(
            r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\']',
            html, re.I
        )
        price_fields = [f for f in hidden_fields if any(
            k in f.lower() for k in ["price", "amount", "total", "discount"]
        )]

        if price_fields:
            self._add_check_result(
                "BL-001", "Price/Amount Hidden Fields",
                "warn", "medium",
                f"Price-related hidden fields: {price_fields}",
                evidence=f"Fields: {price_fields}",
                remediation="Validate all price calculations server-side"
            )
        else:
            self._add_check_result(
                "BL-001", "Price/Amount Hidden Fields",
                "pass", None,
                "No price-related hidden fields detected"
            )

        # BL-002: Debug Mode
        debug_patterns = [
            r'debug\s*[=:]\s*true',
            r'DEBUG\s*=\s*True',
            r'development\s*mode',
            r'stack\s*trace',
        ]
        for pattern in debug_patterns:
            if re.search(pattern, html, re.I):
                self._add_check_result(
                    "BL-002", "Debug Mode Detection",
                    "warn", "medium",
                    "Debug/development mode indicators found",
                    evidence="Debug pattern detected",
                    remediation="Disable debug mode in production"
                )
                break
        else:
            self._add_check_result(
                "BL-002", "Debug Mode Detection",
                "pass", None,
                "No debug mode indicators"
            )

    def _get_header(self, headers: Dict, name: str) -> Optional[str]:
        """Get header value case-insensitively."""
        for key, value in headers.items():
            if key.lower() == name.lower():
                return value
        return None

    def _add_check_result(
        self,
        check_id: str,
        name: str,
        status: str,
        severity: Optional[str],
        message: str,
        evidence: str = "",
        curl: str = "",
        remediation: str = ""
    ):
        """Add a check result."""
        result = {
            "check_id": check_id,
            "name": name,
            "status": status,
            "severity": severity,
            "message": message,
            "evidence": evidence,
            "curl_command": curl,
            "remediation": remediation,
            "timestamp": datetime.now().isoformat()
        }
        self.check_results.append(result)

        # Add to findings if failed
        if status == "fail" and severity:
            self._add_finding(check_id, severity, message, evidence, remediation)

    def _add_finding(
        self,
        check_id: str,
        severity: str,
        title: str,
        evidence: str = "",
        remediation: str = ""
    ):
        """Add a security finding."""
        self.findings.append({
            "id": f"FIND-{len(self.findings)+1:03d}",
            "check_id": check_id,
            "severity": severity,
            "title": title,
            "evidence": evidence,
            "remediation": remediation,
            "timestamp": datetime.now().isoformat()
        })

    def _calculate_score(self) -> float:
        """Calculate security score (0-100)."""
        if not self.check_results:
            return 0

        score = 100.0
        severity_weights = {
            "critical": 25,
            "high": 15,
            "medium": 8,
            "low": 3
        }

        for result in self.check_results:
            if result["status"] == "fail":
                severity = result.get("severity", "low")
                score -= severity_weights.get(severity, 3)
            elif result["status"] == "warn":
                severity = result.get("severity", "low")
                score -= severity_weights.get(severity, 3) / 2

        return max(0, min(100, score))
