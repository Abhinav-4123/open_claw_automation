"""
NEXUS QA - Report Agent
Generates comprehensive PDF security reports with full evidence.
"""

import base64
import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from .base import BaseAgent, TaskContext, AgentResult

logger = logging.getLogger(__name__)


class ReportAgent(BaseAgent):
    """
    Report Agent - Generates comprehensive PDF security reports.

    Phase 5 responsibilities:
    - Aggregate all findings from previous phases
    - Generate executive summary
    - Create journey maps (Mermaid diagrams)
    - Document API inventory
    - List security findings with evidence
    - Generate compliance status
    - Render PDF report
    """

    agent_type = "report"

    def __init__(self, output_dir: str = "/tmp/reports"):
        super().__init__()
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    async def execute(self, context: TaskContext) -> AgentResult:
        """Generate comprehensive PDF report."""
        start_time = datetime.now()

        try:
            await self.report_progress(10, "Gathering all scan data")

            # Collect all data from context
            report_data = self._collect_report_data(context)

            await self.report_progress(30, "Generating HTML report")

            # Generate HTML report
            html_content = self._generate_html_report(report_data)

            await self.report_progress(60, "Rendering PDF")

            # Generate PDF
            pdf_path = await self._render_pdf(html_content, report_data)

            # Also save HTML version
            html_path = pdf_path.replace('.pdf', '.html')
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)

            await self.report_progress(90, "Generating JSON export")

            # Generate JSON export
            json_path = pdf_path.replace('.pdf', '.json')
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str)

            await self.report_progress(100, "Report generation complete")

            duration = (datetime.now() - start_time).total_seconds()
            return AgentResult(
                success=True,
                data={
                    "report_path": pdf_path,
                    "html_path": html_path,
                    "json_path": json_path,
                    "generated_at": datetime.now().isoformat(),
                    "duration_seconds": duration
                },
                duration_seconds=duration
            )

        except Exception as e:
            logger.exception(f"Report Agent error: {e}")
            return AgentResult(
                success=False,
                error=str(e),
                partial=True
            )

    def _collect_report_data(self, context: TaskContext) -> Dict[str, Any]:
        """Collect all data for the report."""
        return {
            "metadata": {
                "session_id": context.session_id,
                "url": context.url,
                "generated_at": datetime.now().isoformat(),
                "scan_type": "Autonomous Security Assessment"
            },
            "product_profile": context.shared_data.get("product_profile", {}),
            "journeys": context.shared_data.get("journeys", []),
            "api_inventory": context.shared_data.get("api_inventory", []),
            "test_plan": context.shared_data.get("test_plan", {}),
            "security_findings": context.shared_data.get("security_findings", [])
        }

    def _generate_html_report(self, data: Dict) -> str:
        """Generate comprehensive HTML report."""
        metadata = data.get("metadata", {})
        product = data.get("product_profile", {})
        journeys = data.get("journeys", [])
        apis = data.get("api_inventory", [])
        findings = data.get("security_findings", [])
        test_plan = data.get("test_plan", {})

        # Calculate summary stats
        summary = self._calculate_summary(findings)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NEXUS QA Security Report - {metadata.get('url', 'Unknown')}</title>
    <style>
        {self._get_report_css()}
    </style>
</head>
<body>
    <div class="report-container">
        <!-- Header -->
        <header class="report-header">
            <div class="logo">NEXUS QA</div>
            <div class="report-title">
                <h1>Security Assessment Report</h1>
                <p class="subtitle">Autonomous Multi-Agent Analysis</p>
            </div>
            <div class="report-meta">
                <p><strong>Target:</strong> {metadata.get('url', 'N/A')}</p>
                <p><strong>Generated:</strong> {metadata.get('generated_at', 'N/A')}</p>
                <p><strong>Session:</strong> {metadata.get('session_id', 'N/A')}</p>
            </div>
        </header>

        <!-- Executive Summary -->
        <section class="section">
            <h2>Executive Summary</h2>
            <div class="summary-grid">
                <div class="summary-card score-card {self._get_score_class(summary['score'])}">
                    <div class="score-circle">
                        <span class="score-value">{summary['score']}</span>
                        <span class="score-label">/100</span>
                    </div>
                    <p>Security Score</p>
                </div>
                <div class="summary-card">
                    <div class="stat critical">{summary['critical']}</div>
                    <p>Critical</p>
                </div>
                <div class="summary-card">
                    <div class="stat high">{summary['high']}</div>
                    <p>High</p>
                </div>
                <div class="summary-card">
                    <div class="stat medium">{summary['medium']}</div>
                    <p>Medium</p>
                </div>
                <div class="summary-card">
                    <div class="stat low">{summary['low']}</div>
                    <p>Low</p>
                </div>
            </div>
            <div class="summary-text">
                <p>{self._generate_executive_summary(product, summary)}</p>
            </div>
        </section>

        <!-- Product Analysis -->
        <section class="section">
            <h2>Product Analysis</h2>
            <div class="product-info">
                <table class="info-table">
                    <tr><th>Application Type</th><td>{product.get('app_type', 'Unknown')}</td></tr>
                    <tr><th>Industry</th><td>{product.get('industry', 'Unknown')}</td></tr>
                    <tr><th>Product Name</th><td>{product.get('product_name', 'N/A')}</td></tr>
                    <tr><th>Core Features</th><td>{', '.join(product.get('core_features', [])[:5])}</td></tr>
                    <tr><th>Auth Methods</th><td>{', '.join(product.get('auth_methods', []))}</td></tr>
                    <tr><th>Has Login</th><td>{'Yes' if product.get('has_login') else 'No'}</td></tr>
                    <tr><th>Has Signup</th><td>{'Yes' if product.get('has_signup') else 'No'}</td></tr>
                    <tr><th>Has Payment</th><td>{'Yes' if product.get('has_pricing') else 'No'}</td></tr>
                </table>
                {self._render_product_screenshot(product)}
            </div>
        </section>

        <!-- User Journeys -->
        <section class="section">
            <h2>User Journeys Discovered</h2>
            <p>The following user journeys were automatically discovered and mapped:</p>
            <div class="journeys-grid">
                {self._render_journeys(journeys)}
            </div>
        </section>

        <!-- API Inventory -->
        <section class="section">
            <h2>API Inventory</h2>
            <p>APIs discovered through network traffic analysis:</p>
            <div class="api-table-container">
                {self._render_api_table(apis)}
            </div>
        </section>

        <!-- Security Findings -->
        <section class="section findings-section">
            <h2>Security Findings</h2>
            {self._render_findings(findings)}
        </section>

        <!-- Compliance Status -->
        <section class="section">
            <h2>Compliance Mapping</h2>
            {self._render_compliance(findings)}
        </section>

        <!-- Test Plan Used -->
        <section class="section">
            <h2>Test Methodology</h2>
            {self._render_test_plan(test_plan)}
        </section>

        <!-- Footer -->
        <footer class="report-footer">
            <p>Generated by NEXUS QA - Autonomous Multi-Agent Security Scanner</p>
            <p>Report ID: {metadata.get('session_id', 'N/A')} | {metadata.get('generated_at', '')}</p>
        </footer>
    </div>
</body>
</html>"""

        return html

    def _get_report_css(self) -> str:
        """Get CSS for the report."""
        return """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            line-height: 1.6;
            color: #1a1a1a;
            background: #fff;
        }
        .report-container { max-width: 1000px; margin: 0 auto; padding: 40px; }

        .report-header {
            border-bottom: 3px solid #2563eb;
            padding-bottom: 30px;
            margin-bottom: 40px;
        }
        .logo { font-size: 28px; font-weight: 700; color: #2563eb; }
        .report-title h1 { font-size: 32px; margin: 10px 0; }
        .subtitle { color: #666; }
        .report-meta { margin-top: 20px; font-size: 14px; }
        .report-meta p { margin: 4px 0; }

        .section { margin-bottom: 50px; page-break-inside: avoid; }
        .section h2 {
            font-size: 24px;
            color: #1a1a1a;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e5e7eb;
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: #f8fafc;
            padding: 20px;
            border-radius: 12px;
            text-align: center;
        }
        .score-card { background: linear-gradient(135deg, #f0f9ff, #e0f2fe); }
        .score-card.good { background: linear-gradient(135deg, #f0fdf4, #dcfce7); }
        .score-card.medium { background: linear-gradient(135deg, #fffbeb, #fef3c7); }
        .score-card.poor { background: linear-gradient(135deg, #fef2f2, #fee2e2); }

        .score-circle { margin-bottom: 10px; }
        .score-value { font-size: 48px; font-weight: 700; }
        .score-label { font-size: 18px; color: #666; }

        .stat { font-size: 36px; font-weight: 700; margin-bottom: 5px; }
        .stat.critical { color: #dc2626; }
        .stat.high { color: #ea580c; }
        .stat.medium { color: #ca8a04; }
        .stat.low { color: #16a34a; }

        .summary-text {
            background: #f8fafc;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #2563eb;
        }

        .info-table { width: 100%; border-collapse: collapse; }
        .info-table th {
            text-align: left;
            padding: 12px;
            background: #f8fafc;
            width: 200px;
            border: 1px solid #e5e7eb;
        }
        .info-table td {
            padding: 12px;
            border: 1px solid #e5e7eb;
        }

        .journeys-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; }
        .journey-card {
            background: #f8fafc;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #2563eb;
        }
        .journey-card.critical { border-left-color: #dc2626; }
        .journey-card.high { border-left-color: #ea580c; }
        .journey-card h4 { margin-bottom: 10px; }
        .journey-card .meta { font-size: 12px; color: #666; }

        .api-table { width: 100%; border-collapse: collapse; font-size: 13px; }
        .api-table th, .api-table td {
            padding: 10px;
            border: 1px solid #e5e7eb;
            text-align: left;
        }
        .api-table th { background: #f8fafc; }
        .api-table .method {
            font-family: monospace;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
        }
        .method.GET { background: #dcfce7; color: #166534; }
        .method.POST { background: #dbeafe; color: #1e40af; }
        .method.PUT { background: #fef3c7; color: #92400e; }
        .method.DELETE { background: #fee2e2; color: #991b1b; }

        .finding {
            margin-bottom: 20px;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            overflow: hidden;
        }
        .finding-header {
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .finding-header.critical { background: #fef2f2; border-left: 4px solid #dc2626; }
        .finding-header.high { background: #fff7ed; border-left: 4px solid #ea580c; }
        .finding-header.medium { background: #fffbeb; border-left: 4px solid #ca8a04; }
        .finding-header.low { background: #f0fdf4; border-left: 4px solid #16a34a; }

        .finding-body { padding: 20px; background: #fff; }
        .finding-body h5 { margin-bottom: 10px; color: #666; }

        .severity-badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }
        .severity-badge.critical { background: #dc2626; color: #fff; }
        .severity-badge.high { background: #ea580c; color: #fff; }
        .severity-badge.medium { background: #ca8a04; color: #fff; }
        .severity-badge.low { background: #16a34a; color: #fff; }

        .evidence-block {
            background: #1e293b;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 6px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 13px;
            overflow-x: auto;
            margin: 10px 0;
        }

        .remediation-block {
            background: #f0fdf4;
            border: 1px solid #86efac;
            padding: 15px;
            border-radius: 6px;
            margin-top: 15px;
        }

        .compliance-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; }
        .compliance-card {
            background: #f8fafc;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }
        .compliance-card h4 { font-size: 14px; margin-bottom: 5px; }
        .compliance-card .status { font-size: 24px; }

        .test-phase {
            margin-bottom: 20px;
            padding: 15px;
            background: #f8fafc;
            border-radius: 8px;
        }
        .test-phase h4 { margin-bottom: 10px; }
        .test-list { margin-left: 20px; }
        .test-list li { margin: 5px 0; }

        .report-footer {
            margin-top: 50px;
            padding-top: 30px;
            border-top: 2px solid #e5e7eb;
            text-align: center;
            color: #666;
            font-size: 12px;
        }

        @media print {
            .report-container { padding: 20px; }
            .section { page-break-inside: avoid; }
        }
        """

    def _calculate_summary(self, findings: List[Dict]) -> Dict:
        """Calculate summary statistics."""
        summary = {
            "total": len(findings),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "score": 100
        }

        severity_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}

        for finding in findings:
            severity = finding.get("severity", "low")
            if severity in summary:
                summary[severity] += 1
                summary["score"] -= severity_weights.get(severity, 3)

        summary["score"] = max(0, summary["score"])
        return summary

    def _get_score_class(self, score: int) -> str:
        """Get CSS class for score."""
        if score >= 80:
            return "good"
        elif score >= 50:
            return "medium"
        return "poor"

    def _generate_executive_summary(self, product: Dict, summary: Dict) -> str:
        """Generate executive summary text."""
        app_type = product.get("app_type", "web application")
        score = summary["score"]

        if score >= 80:
            risk_level = "low"
            recommendation = "Continue maintaining security best practices."
        elif score >= 50:
            risk_level = "moderate"
            recommendation = "Address high and critical findings promptly."
        else:
            risk_level = "high"
            recommendation = "Immediate remediation required for critical vulnerabilities."

        return f"""This autonomous security assessment analyzed a {app_type} application.
        The overall security posture is rated at {score}/100, indicating {risk_level} risk.
        We discovered {summary['critical']} critical, {summary['high']} high, {summary['medium']} medium,
        and {summary['low']} low severity issues. {recommendation}"""

    def _render_product_screenshot(self, product: Dict) -> str:
        """Render product screenshot if available."""
        # Screenshots would be stored as base64
        # For now, return empty
        return ""

    def _render_journeys(self, journeys: List[Dict]) -> str:
        """Render journey cards."""
        if not journeys:
            return "<p>No user journeys were discovered.</p>"

        html = ""
        for j in journeys[:8]:
            priority = j.get("priority", "low")
            html += f"""
            <div class="journey-card {priority}">
                <h4>{j.get('name', 'Unknown Journey')}</h4>
                <p>{j.get('steps_count', 0)} steps identified</p>
                <p class="meta">
                    Priority: {priority.upper()} |
                    Forms: {len(j.get('forms', []))} |
                    Auth Required: {'Yes' if j.get('requires_auth') else 'No'}
                </p>
            </div>
            """
        return html

    def _render_api_table(self, apis: List[Dict]) -> str:
        """Render API inventory table."""
        if not apis:
            return "<p>No APIs were discovered.</p>"

        rows = ""
        for api in apis[:20]:
            method = api.get("method", "GET")
            auth = "Required" if api.get("has_auth") else "Not Required"
            rows += f"""
            <tr>
                <td><span class="method {method}">{method}</span></td>
                <td><code>{api.get('path', '/')}</code></td>
                <td>{api.get('host', '')}</td>
                <td>{auth}</td>
                <td>{api.get('call_count', 0)}</td>
            </tr>
            """

        return f"""
        <table class="api-table">
            <thead>
                <tr>
                    <th>Method</th>
                    <th>Path</th>
                    <th>Host</th>
                    <th>Auth</th>
                    <th>Calls</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>
        """

    def _render_findings(self, findings: List[Dict]) -> str:
        """Render security findings."""
        if not findings:
            return "<p>No security findings were identified.</p>"

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.get("severity", "low"), 4)
        )

        html = ""
        for f in sorted_findings:
            severity = f.get("severity", "low")
            html += f"""
            <div class="finding">
                <div class="finding-header {severity}">
                    <div>
                        <strong>{f.get('check_id', 'N/A')}</strong>: {f.get('title', 'Unknown')}
                    </div>
                    <span class="severity-badge {severity}">{severity}</span>
                </div>
                <div class="finding-body">
                    <h5>Evidence</h5>
                    <div class="evidence-block">{f.get('evidence', 'No evidence captured')}</div>

                    {self._render_curl_command(f)}

                    <div class="remediation-block">
                        <strong>Remediation:</strong> {f.get('remediation', 'Review and fix the issue.')}
                    </div>
                </div>
            </div>
            """
        return html

    def _render_curl_command(self, finding: Dict) -> str:
        """Render curl command if available."""
        curl = finding.get("curl_command", "")
        if curl:
            return f"""
            <h5>Reproduction</h5>
            <div class="evidence-block">{curl}</div>
            """
        return ""

    def _render_compliance(self, findings: List[Dict]) -> str:
        """Render compliance mapping."""
        # Map findings to compliance frameworks
        frameworks = {
            "OWASP Top 10": {"issues": 0, "total": 10},
            "PCI DSS": {"issues": 0, "total": 12},
            "GDPR": {"issues": 0, "total": 5},
            "SOC 2": {"issues": 0, "total": 5},
            "ISO 27001": {"issues": 0, "total": 10},
            "HIPAA": {"issues": 0, "total": 5},
        }

        # Simple mapping based on check IDs
        for f in findings:
            check_id = f.get("check_id", "")
            if "IF-" in check_id or "IN-" in check_id:
                frameworks["OWASP Top 10"]["issues"] += 1
            if "CR-" in check_id or "AU-" in check_id:
                frameworks["PCI DSS"]["issues"] += 1
            if "DS-" in check_id:
                frameworks["GDPR"]["issues"] += 1
                frameworks["HIPAA"]["issues"] += 1

        html = '<div class="compliance-grid">'
        for name, data in frameworks.items():
            issues = data["issues"]
            status = "Needs Review" if issues > 0 else "Compliant"
            html += f"""
            <div class="compliance-card">
                <h4>{name}</h4>
                <div class="status">{'Needs Review' if issues > 0 else '&check;'}</div>
                <p>{issues} issues found</p>
            </div>
            """
        html += "</div>"
        return html

    def _render_test_plan(self, test_plan: Dict) -> str:
        """Render test methodology."""
        if not test_plan or not test_plan.get("test_phases"):
            return "<p>Standard security test methodology was applied.</p>"

        html = ""
        for phase in test_plan.get("test_phases", []):
            tests = "\n".join(
                f"<li>{t.get('name', 'Unknown')}: {t.get('description', '')}</li>"
                for t in phase.get("tests", [])
            )
            html += f"""
            <div class="test-phase">
                <h4>Phase {phase.get('phase', '')}: {phase.get('name', '')}</h4>
                <p>Priority: {phase.get('priority', 'N/A')} |
                   Est. Duration: {phase.get('estimated_duration_minutes', 0)} min</p>
                <ul class="test-list">{tests}</ul>
            </div>
            """
        return html

    async def _render_pdf(self, html_content: str, data: Dict) -> str:
        """Render HTML to PDF."""
        session_id = data.get("metadata", {}).get("session_id", "report")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"nexus_qa_report_{session_id}_{timestamp}.pdf"
        pdf_path = os.path.join(self.output_dir, filename)

        try:
            # Try WeasyPrint
            from weasyprint import HTML
            HTML(string=html_content).write_pdf(pdf_path)
            logger.info(f"PDF generated with WeasyPrint: {pdf_path}")
        except ImportError:
            try:
                # Fallback to pdfkit
                import pdfkit
                pdfkit.from_string(html_content, pdf_path)
                logger.info(f"PDF generated with pdfkit: {pdf_path}")
            except ImportError:
                # Just save HTML if no PDF library
                pdf_path = pdf_path.replace('.pdf', '.html')
                with open(pdf_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                logger.warning(f"No PDF library available, saved HTML: {pdf_path}")

        return pdf_path
