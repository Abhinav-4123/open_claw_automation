"""
NEXUS QA - Recommendations Engine
Generates prioritized fix recommendations based on security findings.
"""

import uuid
from datetime import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from enum import Enum


class Priority(Enum):
    """Priority levels for recommendations."""
    P0 = "P0"  # Critical - Fix within 48 hours
    P1 = "P1"  # High - Fix this sprint
    P2 = "P2"  # Medium - Fix this quarter


class ComplianceFramework(Enum):
    """Compliance frameworks for mapping."""
    OWASP = "OWASP"
    CWE = "CWE"
    PCI_DSS = "PCI-DSS"
    GDPR = "GDPR"
    ISO_27001 = "ISO 27001"
    SOC_2 = "SOC 2"
    HIPAA = "HIPAA"
    NIST = "NIST"


@dataclass
class Recommendation:
    """A security recommendation."""
    id: str
    title: str
    description: str
    priority: Priority
    category: str
    check_id: str
    compliance: List[str]
    fix_guidance: str
    code_example: Optional[str] = None
    references: List[str] = field(default_factory=list)
    scan_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    status: str = "open"  # open, in_progress, resolved, wont_fix
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "priority": self.priority.value,
            "category": self.category,
            "check_id": self.check_id,
            "compliance": self.compliance,
            "fix_guidance": self.fix_guidance,
            "code_example": self.code_example,
            "references": self.references,
            "scan_id": self.scan_id,
            "created_at": self.created_at.isoformat(),
            "status": self.status,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolved_by": self.resolved_by
        }


# Fix guidance templates for common issues
FIX_TEMPLATES = {
    # Injection
    "sql_injection": {
        "title": "SQL Injection Vulnerability",
        "guidance": "Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.",
        "code_example": """# Bad
query = f"SELECT * FROM users WHERE id = {user_input}"

# Good - Parameterized query
cursor.execute("SELECT * FROM users WHERE id = ?", (user_input,))""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ]
    },
    "xss_reflected": {
        "title": "Cross-Site Scripting (XSS) - Reflected",
        "guidance": "Encode all user input before rendering. Use Content-Security-Policy headers. Implement input validation.",
        "code_example": """# Bad - Direct output
return f"<div>{user_input}</div>"

# Good - Escape output
from html import escape
return f"<div>{escape(user_input)}</div>"

# Best - Use template engine with auto-escaping
# Jinja2, React, Vue all auto-escape by default""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        ]
    },
    "command_injection": {
        "title": "Command Injection Vulnerability",
        "guidance": "Avoid shell commands. Use language-native libraries. If shell is required, use allowlists and subprocess with shell=False.",
        "code_example": """# Bad
os.system(f"ping {user_input}")

# Good - Use subprocess with list args
import subprocess
subprocess.run(["ping", "-c", "4", validated_host], shell=False)""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
        ]
    },

    # Authentication
    "weak_session": {
        "title": "Weak Session Management",
        "guidance": "Use secure, HttpOnly, SameSite cookies. Implement session timeouts. Regenerate session IDs after authentication.",
        "code_example": """# Secure cookie settings
response.set_cookie(
    "session_id",
    value=session_id,
    httponly=True,
    secure=True,
    samesite="Strict",
    max_age=3600
)""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
        ]
    },
    "idor": {
        "title": "Insecure Direct Object Reference (IDOR)",
        "guidance": "Implement authorization checks for every resource access. Use indirect references. Verify user ownership.",
        "code_example": """# Bad - Direct access without auth check
def get_document(doc_id):
    return Document.query.get(doc_id)

# Good - Verify ownership
def get_document(doc_id, user_id):
    doc = Document.query.get(doc_id)
    if doc.owner_id != user_id:
        raise PermissionDenied()
    return doc""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html"
        ]
    },

    # Credentials
    "exposed_secrets": {
        "title": "Exposed Secrets/Credentials",
        "guidance": "Remove secrets from code. Use environment variables or secret management. Rotate compromised credentials immediately.",
        "code_example": """# Bad - Hardcoded secret
API_KEY = "sk-1234567890abcdef"

# Good - Environment variable
import os
API_KEY = os.environ.get("API_KEY")

# Best - Secret manager
from google.cloud import secretmanager
client = secretmanager.SecretManagerServiceClient()
API_KEY = client.access_secret_version(name="projects/x/secrets/api-key/versions/latest")""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
        ]
    },
    "jwt_in_url": {
        "title": "JWT Token in URL",
        "guidance": "Never pass tokens in URLs. Use Authorization headers or HttpOnly cookies. Tokens in URLs may be logged or leaked via Referer.",
        "code_example": """# Bad - Token in URL
fetch(`/api/data?token=${jwt}`)

# Good - Authorization header
fetch('/api/data', {
    headers: {
        'Authorization': `Bearer ${jwt}`
    }
})""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html"
        ]
    },

    # Infrastructure
    "missing_hsts": {
        "title": "Missing HSTS Header",
        "guidance": "Enable HTTP Strict Transport Security (HSTS) with a minimum max-age of 1 year. Include subdomains if applicable.",
        "code_example": """# Nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# Express.js
const helmet = require('helmet');
app.use(helmet.hsts({
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
}));""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
        ]
    },
    "missing_csp": {
        "title": "Missing Content Security Policy",
        "guidance": "Implement a strict CSP to prevent XSS and data injection attacks. Start with a restrictive policy and whitelist required sources.",
        "code_example": """# Nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';" always;

# Express.js
const helmet = require('helmet');
app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"]
    }
}));""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
        ]
    },
    "cors_misconfigured": {
        "title": "CORS Misconfiguration",
        "guidance": "Restrict Access-Control-Allow-Origin to specific trusted domains. Never use wildcard (*) with credentials. Validate Origin header.",
        "code_example": """# Bad - Wildcard origin
Access-Control-Allow-Origin: *

# Good - Specific origin
ALLOWED_ORIGINS = ["https://app.example.com", "https://www.example.com"]

@app.before_request
def validate_origin():
    origin = request.headers.get('Origin')
    if origin in ALLOWED_ORIGINS:
        response.headers['Access-Control-Allow-Origin'] = origin""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html"
        ]
    },

    # Rate Limiting
    "no_rate_limit": {
        "title": "Missing Rate Limiting",
        "guidance": "Implement rate limiting on all endpoints, especially authentication and API endpoints. Use sliding window or token bucket algorithms.",
        "code_example": """# Flask with Flask-Limiter
from flask_limiter import Limiter
limiter = Limiter(app, key_func=get_remote_address)

@app.route("/api/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    pass

# FastAPI with slowapi
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)

@app.post("/api/login")
@limiter.limit("5/minute")
def login():
    pass""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html"
        ]
    },

    # Data Security
    "pii_exposed": {
        "title": "PII Exposure in Response",
        "guidance": "Mask or redact sensitive PII in responses. Implement field-level access control. Log access to sensitive data.",
        "code_example": """# Mask sensitive fields
def mask_email(email):
    parts = email.split('@')
    return f"{parts[0][:2]}***@{parts[1]}"

def mask_ssn(ssn):
    return f"***-**-{ssn[-4:]}"

# Response sanitization
def sanitize_user_response(user):
    return {
        "id": user.id,
        "name": user.name,
        "email": mask_email(user.email),
        "ssn": mask_ssn(user.ssn) if user.ssn else None
    }""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/User_Privacy_Protection_Cheat_Sheet.html"
        ]
    },

    # Business Logic
    "race_condition": {
        "title": "Race Condition Vulnerability",
        "guidance": "Use database transactions with appropriate isolation levels. Implement optimistic or pessimistic locking. Use atomic operations.",
        "code_example": """# Bad - Race condition in balance update
user.balance -= amount
user.save()

# Good - Atomic update with pessimistic lock
from django.db import transaction

with transaction.atomic():
    user = User.objects.select_for_update().get(id=user_id)
    if user.balance >= amount:
        user.balance -= amount
        user.save()
    else:
        raise InsufficientFunds()""",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Race_Conditions.html"
        ]
    }
}

# Priority mapping based on severity and impact
PRIORITY_RULES = {
    # P0 - Critical (Fix within 48 hours)
    "P0": [
        "IN-001",  # Reflected XSS
        "IN-002",  # Stored XSS
        "IN-004",  # SQL Injection
        "IN-005",  # NoSQL Injection
        "IN-007",  # Command Injection
        "IN-009",  # XXE
        "CR-001",  # JWT in URL
        "CR-002",  # Exposed API Key
        "CR-003",  # Hardcoded Secrets
        "AU-006",  # Privilege Escalation
        "AU-007",  # IDOR
        "BL-003",  # Race Condition (financial)
    ],
    # P1 - High (Fix this sprint)
    "P1": [
        "IN-003",  # DOM XSS
        "IN-006",  # SSTI
        "IN-008",  # LDAP Injection
        "IN-011",  # Path Traversal
        "AU-001",  # Weak Session
        "AU-002",  # Session Fixation
        "AU-003",  # Missing Logout
        "AU-004",  # No RBAC
        "AU-005",  # Broken Access Control
        "CR-004",  # Weak Token
        "CR-005",  # Token in localStorage
        "RL-001",  # No Rate Limit
        "RL-002",  # Auth Brute Force
        "IF-001",  # Weak TLS
        "IF-002",  # Missing HSTS
        "IF-003",  # Missing CSP
        "IF-006",  # CORS Misconfigured
        "BL-002",  # Price Manipulation
        "BL-005",  # Mass Assignment
    ],
    # P2 - Medium (Fix this quarter)
    "P2": [
        "IN-010",  # Header Injection
        "IN-012",  # CRLF Injection
        "AU-008",  # Missing MFA
        "AU-009",  # Weak Password Policy
        "AU-010",  # No Account Lockout
        "CR-006",  # Sensitive in Error
        "CR-007",  # Debug Mode
        "CR-008",  # Verbose Errors
        "RL-003",  # API Abuse
        "RL-004",  # Resource Exhaustion
        "CS-001",  # Sensitive localStorage
        "CS-002",  # Cache Control
        "IF-004",  # X-Content-Type-Options
        "IF-005",  # X-Frame-Options
        "IF-007",  # Server Disclosure
        "IF-008",  # Referrer Policy
        "IF-009",  # Permissions Policy
        "DS-001",  # PII Exposure
        "DS-002",  # Missing Encryption
        "BL-001",  # Workflow Bypass
        "BL-004",  # Anti-Automation Bypass
    ]
}


class RecommendationsEngine:
    """
    Engine for generating prioritized security recommendations.

    Takes security scan results and generates actionable recommendations
    with fix guidance, code examples, and compliance mappings.
    """

    def __init__(self):
        self._recommendations: Dict[str, Recommendation] = {}
        self._history: List[Recommendation] = []

    def generate_from_scan(
        self,
        scan_results: Dict[str, Any],
        scan_id: str
    ) -> List[Recommendation]:
        """
        Generate recommendations from scan results.

        Args:
            scan_results: Security scan results
            scan_id: Associated scan ID

        Returns:
            List of recommendations
        """
        recommendations = []

        # Process each category's results
        for category, checks in scan_results.get("categories", {}).items():
            for check in checks:
                if check.get("status") == "FAIL":
                    rec = self._create_recommendation(
                        check_id=check.get("id", ""),
                        check_name=check.get("name", ""),
                        category=category,
                        finding=check.get("finding", ""),
                        compliance=check.get("compliance", []),
                        scan_id=scan_id
                    )
                    if rec:
                        recommendations.append(rec)
                        self._recommendations[rec.id] = rec

        return recommendations

    def _create_recommendation(
        self,
        check_id: str,
        check_name: str,
        category: str,
        finding: str,
        compliance: List[str],
        scan_id: str
    ) -> Optional[Recommendation]:
        """Create a recommendation for a failed check."""

        # Determine priority
        priority = self._get_priority(check_id)

        # Get fix template if available
        template = self._get_fix_template(check_id, check_name)

        return Recommendation(
            id=f"rec_{uuid.uuid4().hex[:8]}",
            title=template.get("title", check_name),
            description=finding or f"Security issue detected: {check_name}",
            priority=priority,
            category=category,
            check_id=check_id,
            compliance=compliance,
            fix_guidance=template.get("guidance", "Review and fix this security issue."),
            code_example=template.get("code_example"),
            references=template.get("references", []),
            scan_id=scan_id
        )

    def _get_priority(self, check_id: str) -> Priority:
        """Determine priority based on check ID."""
        if check_id in PRIORITY_RULES["P0"]:
            return Priority.P0
        elif check_id in PRIORITY_RULES["P1"]:
            return Priority.P1
        else:
            return Priority.P2

    def _get_fix_template(
        self,
        check_id: str,
        check_name: str
    ) -> Dict[str, Any]:
        """Get fix template for a check."""

        # Map check IDs to templates
        check_to_template = {
            "IN-001": "xss_reflected",
            "IN-002": "xss_reflected",
            "IN-003": "xss_reflected",
            "IN-004": "sql_injection",
            "IN-005": "sql_injection",
            "IN-007": "command_injection",
            "AU-001": "weak_session",
            "AU-007": "idor",
            "CR-001": "jwt_in_url",
            "CR-002": "exposed_secrets",
            "CR-003": "exposed_secrets",
            "IF-002": "missing_hsts",
            "IF-003": "missing_csp",
            "IF-006": "cors_misconfigured",
            "RL-001": "no_rate_limit",
            "RL-002": "no_rate_limit",
            "DS-001": "pii_exposed",
            "BL-003": "race_condition",
        }

        template_key = check_to_template.get(check_id)
        if template_key:
            return FIX_TEMPLATES.get(template_key, {})

        # Default template
        return {
            "title": check_name,
            "guidance": f"Address the security issue: {check_name}. Review OWASP guidelines for remediation.",
            "references": ["https://owasp.org/www-project-web-security-testing-guide/"]
        }

    def get_all_recommendations(self) -> List[Recommendation]:
        """Get all current recommendations."""
        return list(self._recommendations.values())

    def get_by_priority(self, priority: Priority) -> List[Recommendation]:
        """Get recommendations by priority level."""
        return [
            r for r in self._recommendations.values()
            if r.priority == priority and r.status == "open"
        ]

    def get_by_category(self, category: str) -> List[Recommendation]:
        """Get recommendations by security category."""
        return [
            r for r in self._recommendations.values()
            if r.category == category and r.status == "open"
        ]

    def get_by_scan(self, scan_id: str) -> List[Recommendation]:
        """Get recommendations for a specific scan."""
        return [
            r for r in self._recommendations.values()
            if r.scan_id == scan_id
        ]

    def get_recommendation(self, rec_id: str) -> Optional[Recommendation]:
        """Get a specific recommendation."""
        return self._recommendations.get(rec_id)

    def resolve_recommendation(
        self,
        rec_id: str,
        resolved_by: Optional[str] = None
    ) -> bool:
        """Mark a recommendation as resolved."""
        rec = self._recommendations.get(rec_id)
        if not rec:
            return False

        rec.status = "resolved"
        rec.resolved_at = datetime.now()
        rec.resolved_by = resolved_by
        self._history.append(rec)

        return True

    def mark_in_progress(self, rec_id: str) -> bool:
        """Mark a recommendation as in progress."""
        rec = self._recommendations.get(rec_id)
        if not rec:
            return False

        rec.status = "in_progress"
        return True

    def mark_wont_fix(
        self,
        rec_id: str,
        reason: Optional[str] = None
    ) -> bool:
        """Mark a recommendation as won't fix."""
        rec = self._recommendations.get(rec_id)
        if not rec:
            return False

        rec.status = "wont_fix"
        rec.resolved_at = datetime.now()
        self._history.append(rec)

        return True

    def get_summary(self) -> Dict[str, Any]:
        """Get recommendations summary."""
        open_recs = [r for r in self._recommendations.values() if r.status == "open"]

        return {
            "total": len(open_recs),
            "by_priority": {
                "P0": len([r for r in open_recs if r.priority == Priority.P0]),
                "P1": len([r for r in open_recs if r.priority == Priority.P1]),
                "P2": len([r for r in open_recs if r.priority == Priority.P2])
            },
            "by_category": self._count_by_category(open_recs),
            "resolved": len([r for r in self._history if r.status == "resolved"]),
            "wont_fix": len([r for r in self._history if r.status == "wont_fix"])
        }

    def _count_by_category(self, recs: List[Recommendation]) -> Dict[str, int]:
        """Count recommendations by category."""
        counts = {}
        for rec in recs:
            counts[rec.category] = counts.get(rec.category, 0) + 1
        return counts

    def get_compliance_report(
        self,
        framework: ComplianceFramework
    ) -> Dict[str, Any]:
        """Get compliance-specific report."""
        framework_name = framework.value
        relevant_recs = [
            r for r in self._recommendations.values()
            if framework_name in r.compliance and r.status == "open"
        ]

        return {
            "framework": framework_name,
            "total_issues": len(relevant_recs),
            "critical": len([r for r in relevant_recs if r.priority == Priority.P0]),
            "high": len([r for r in relevant_recs if r.priority == Priority.P1]),
            "medium": len([r for r in relevant_recs if r.priority == Priority.P2]),
            "recommendations": [r.to_dict() for r in relevant_recs]
        }

    def export_recommendations(
        self,
        format: str = "json",
        priority: Optional[Priority] = None
    ) -> Any:
        """Export recommendations in specified format."""
        recs = self.get_all_recommendations()

        if priority:
            recs = [r for r in recs if r.priority == priority]

        if format == "json":
            return [r.to_dict() for r in recs]
        elif format == "csv":
            return self._to_csv(recs)
        elif format == "markdown":
            return self._to_markdown(recs)

        return recs

    def _to_csv(self, recs: List[Recommendation]) -> str:
        """Convert recommendations to CSV format."""
        lines = ["ID,Title,Priority,Category,Status,Compliance"]
        for rec in recs:
            compliance = ";".join(rec.compliance)
            lines.append(
                f'{rec.id},"{rec.title}",{rec.priority.value},{rec.category},{rec.status},"{compliance}"'
            )
        return "\n".join(lines)

    def _to_markdown(self, recs: List[Recommendation]) -> str:
        """Convert recommendations to Markdown format."""
        lines = ["# Security Recommendations", ""]

        # Group by priority
        for priority in [Priority.P0, Priority.P1, Priority.P2]:
            priority_recs = [r for r in recs if r.priority == priority]
            if not priority_recs:
                continue

            priority_label = {
                Priority.P0: "Critical (P0) - Fix within 48 hours",
                Priority.P1: "High (P1) - Fix this sprint",
                Priority.P2: "Medium (P2) - Fix this quarter"
            }[priority]

            lines.append(f"## {priority_label}")
            lines.append("")

            for rec in priority_recs:
                lines.append(f"### {rec.title}")
                lines.append(f"**ID:** {rec.check_id} | **Category:** {rec.category}")
                lines.append(f"**Compliance:** {', '.join(rec.compliance)}")
                lines.append("")
                lines.append(rec.description)
                lines.append("")
                lines.append("**Fix Guidance:**")
                lines.append(rec.fix_guidance)
                lines.append("")
                if rec.code_example:
                    lines.append("**Code Example:**")
                    lines.append(f"```python\n{rec.code_example}\n```")
                    lines.append("")
                if rec.references:
                    lines.append("**References:**")
                    for ref in rec.references:
                        lines.append(f"- {ref}")
                    lines.append("")
                lines.append("---")
                lines.append("")

        return "\n".join(lines)


# Singleton instance
_recommendations_engine: Optional[RecommendationsEngine] = None


def get_recommendations_engine() -> RecommendationsEngine:
    """Get the singleton recommendations engine instance."""
    global _recommendations_engine
    if _recommendations_engine is None:
        _recommendations_engine = RecommendationsEngine()
    return _recommendations_engine
