"""
NEXUS QA - Security Models
Data models for security scanning and vulnerability management.

Feature Classification:
- DETERMINISTIC: Pure regex/header checks, 100% accurate for what they detect
- HEURISTIC: Rule-based guessing, may have false positives/negatives
- AI_REQUIRED: Uses LLM/VLM, premium feature

Accuracy Levels:
- HIGH: Can definitively detect the issue (header present/absent, pattern match)
- MEDIUM: Strong indicators but may miss some cases
- LOW: Best-effort guess, requires manual verification
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"
    ERROR = "error"


class CheckType(str, Enum):
    """Classification of check methodology."""
    DETERMINISTIC = "deterministic"  # Pure regex/header - no guessing
    HEURISTIC = "heuristic"          # Rule-based guessing
    AI_REQUIRED = "ai_required"      # Needs LLM/VLM - Premium


class Accuracy(str, Enum):
    """Accuracy level of the check."""
    HIGH = "high"      # Definitively detects issue
    MEDIUM = "medium"  # Strong indicators
    LOW = "low"        # Best-effort guess


class SecurityCategory(str, Enum):
    DATA_SECURITY = "data_security"
    CREDENTIALS = "credentials"
    RATE_LIMITING = "rate_limiting"
    CACHE_STORAGE = "cache_storage"
    AUTHENTICATION = "authentication"
    INJECTION = "injection"
    INFRASTRUCTURE = "infrastructure"
    BUSINESS_LOGIC = "business_logic"


@dataclass
class SecurityCheck:
    """Definition of a security check."""
    id: str
    name: str
    category: SecurityCategory
    description: str
    severity: Severity
    remediation: str
    cwe_id: Optional[str] = None
    owasp_id: Optional[str] = None
    pci_dss: Optional[str] = None
    gdpr_article: Optional[str] = None
    iso27001: Optional[str] = None
    soc2: Optional[str] = None
    passive: bool = True  # True if check doesn't require active testing
    compliance: List[str] = field(default_factory=list)  # Combined compliance tags
    # New feature flags
    check_type: CheckType = CheckType.DETERMINISTIC
    accuracy: Accuracy = Accuracy.HIGH
    requires_ai: bool = False  # Premium flag
    can_verify: bool = True    # Can actually verify or just warns
    method: str = "regex"      # regex, header, api, llm, vlm

    def __post_init__(self):
        """Build compliance list from individual fields if not provided."""
        if not self.compliance:
            compliance = []
            if self.owasp_id:
                compliance.append(f"OWASP {self.owasp_id}")
            if self.cwe_id:
                compliance.append(self.cwe_id)
            if self.pci_dss:
                compliance.append(f"PCI-DSS {self.pci_dss}")
            if self.gdpr_article:
                compliance.append(f"GDPR {self.gdpr_article}")
            if self.iso27001:
                compliance.append(f"ISO27001 {self.iso27001}")
            if self.soc2:
                compliance.append(f"SOC2 {self.soc2}")
            self.compliance = compliance

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category.value,
            "description": self.description,
            "severity": self.severity.value,
            "check_type": self.check_type.value,
            "accuracy": self.accuracy.value,
            "requires_ai": self.requires_ai,
            "can_verify": self.can_verify,
            "method": self.method,
            "compliance": self.compliance
        }


@dataclass
class CheckResult:
    """Result of executing a security check."""
    check_id: str
    check_name: str
    category: SecurityCategory
    status: CheckStatus
    severity: Severity
    message: str
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    # Feature flags from check definition
    check_type: CheckType = CheckType.DETERMINISTIC
    accuracy: Accuracy = Accuracy.HIGH
    requires_ai: bool = False
    can_verify: bool = True
    method: str = "regex"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "check_id": self.check_id,
            "check_name": self.check_name,
            "category": self.category.value,
            "status": self.status.value,
            "severity": self.severity.value,
            "message": self.message,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "check_type": self.check_type.value,
            "accuracy": self.accuracy.value,
            "requires_ai": self.requires_ai,
            "can_verify": self.can_verify,
            "method": self.method,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }


@dataclass
class CategoryResult:
    """Results for a security category."""
    category: SecurityCategory
    category_name: str
    checks_run: int
    checks_passed: int
    checks_failed: int
    checks_warning: int
    checks_skipped: int
    results: List[CheckResult] = field(default_factory=list)
    score: float = 0.0  # 0-100


@dataclass
class ScanResult:
    """Complete security scan result."""
    scan_id: str
    url: str
    timestamp: datetime
    duration_seconds: float = 0.0
    status: str = "running"  # running, completed, error
    overall_score: float = 0.0
    total_checks: int = 0
    checks_passed: int = 0
    checks_failed: int = 0
    checks_warning: int = 0
    checks_skipped: int = 0
    category_results: List[CategoryResult] = field(default_factory=list)
    recommendations: List[Any] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class Recommendation:
    """Security recommendation with priority."""
    id: str
    check_id: str
    title: str
    description: str
    priority: str  # P0, P1, P2
    category: str
    remediation: str
    evidence: Optional[str] = None
    compliance_tags: List[str] = field(default_factory=list)
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.now)
