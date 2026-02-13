"""
NEXUS QA - Database Models
SQLite table definitions and data classes.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any
import json


@dataclass
class ScanRecord:
    """Database record for a security scan."""
    id: Optional[int] = None
    scan_id: str = ""
    url: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    duration_seconds: float = 0.0
    overall_score: float = 0.0
    total_checks: int = 0
    checks_passed: int = 0
    checks_failed: int = 0
    checks_warning: int = 0
    checks_skipped: int = 0
    status: str = "pending"
    error: Optional[str] = None
    category_scores: str = "{}"  # JSON string of category -> score

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "url": self.url,
            "timestamp": self.timestamp.isoformat(),
            "duration_seconds": self.duration_seconds,
            "overall_score": self.overall_score,
            "total_checks": self.total_checks,
            "checks_passed": self.checks_passed,
            "checks_failed": self.checks_failed,
            "checks_warning": self.checks_warning,
            "checks_skipped": self.checks_skipped,
            "status": self.status,
            "error": self.error,
            "category_scores": json.loads(self.category_scores),
        }


@dataclass
class CheckResultRecord:
    """Database record for individual check results."""
    id: Optional[int] = None
    scan_id: str = ""
    check_id: str = ""
    category: str = ""
    name: str = ""
    status: str = ""  # pass, fail, warn, skip
    severity: str = ""  # critical, high, medium, low
    message: str = ""
    evidence: Optional[str] = None
    remediation: str = ""
    cwe_id: Optional[str] = None
    owasp_id: Optional[str] = None
    compliance_tags: str = "[]"  # JSON array

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "check_id": self.check_id,
            "category": self.category,
            "name": self.name,
            "status": self.status,
            "severity": self.severity,
            "message": self.message,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "owasp_id": self.owasp_id,
            "compliance_tags": json.loads(self.compliance_tags),
        }


@dataclass
class RecommendationRecord:
    """Database record for recommendations."""
    id: Optional[int] = None
    rec_id: str = ""
    scan_id: str = ""
    check_id: str = ""
    title: str = ""
    description: str = ""
    priority: str = ""  # P0, P1, P2
    category: str = ""
    remediation: str = ""
    evidence: Optional[str] = None
    compliance_tags: str = "[]"  # JSON array
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "rec_id": self.rec_id,
            "scan_id": self.scan_id,
            "check_id": self.check_id,
            "title": self.title,
            "description": self.description,
            "priority": self.priority,
            "category": self.category,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "compliance_tags": json.loads(self.compliance_tags),
            "resolved": self.resolved,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolved_by": self.resolved_by,
            "notes": self.notes,
        }


@dataclass
class JourneyRecord:
    """Database record for detected user journeys."""
    id: Optional[int] = None
    journey_id: str = ""
    url: str = ""
    name: str = ""
    category: str = ""  # auth, payments, profile, etc.
    description: str = ""
    steps: str = "[]"  # JSON array of step objects
    detected_at: datetime = field(default_factory=datetime.now)
    last_tested: Optional[datetime] = None
    test_status: str = "pending"  # pending, pass, fail, partial
    coverage_percent: float = 0.0
    test_results: str = "{}"  # JSON object

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "journey_id": self.journey_id,
            "url": self.url,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "steps": json.loads(self.steps),
            "detected_at": self.detected_at.isoformat(),
            "last_tested": self.last_tested.isoformat() if self.last_tested else None,
            "test_status": self.test_status,
            "coverage_percent": self.coverage_percent,
            "test_results": json.loads(self.test_results),
        }


@dataclass
class ClarificationRecord:
    """Database record for clarification requests."""
    id: Optional[int] = None
    clarification_id: str = ""
    journey_id: Optional[str] = None
    scan_id: Optional[str] = None
    type: str = ""  # ambiguous_element, missing_credentials, etc.
    question: str = ""
    context: str = "{}"  # JSON object with context info
    options: str = "[]"  # JSON array of possible options
    created_at: datetime = field(default_factory=datetime.now)
    responded_at: Optional[datetime] = None
    response: Optional[str] = None
    status: str = "pending"  # pending, responded, expired

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "clarification_id": self.clarification_id,
            "journey_id": self.journey_id,
            "scan_id": self.scan_id,
            "type": self.type,
            "question": self.question,
            "context": json.loads(self.context),
            "options": json.loads(self.options),
            "created_at": self.created_at.isoformat(),
            "responded_at": self.responded_at.isoformat() if self.responded_at else None,
            "response": self.response,
            "status": self.status,
        }


# SQL Schema
SCHEMA = """
-- Security Scans
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT UNIQUE NOT NULL,
    url TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    duration_seconds REAL DEFAULT 0,
    overall_score REAL DEFAULT 0,
    total_checks INTEGER DEFAULT 0,
    checks_passed INTEGER DEFAULT 0,
    checks_failed INTEGER DEFAULT 0,
    checks_warning INTEGER DEFAULT 0,
    checks_skipped INTEGER DEFAULT 0,
    status TEXT DEFAULT 'pending',
    error TEXT,
    category_scores TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_scans_url ON scans(url);

-- Check Results
CREATE TABLE IF NOT EXISTS check_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    check_id TEXT NOT NULL,
    category TEXT NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT,
    evidence TEXT,
    remediation TEXT,
    cwe_id TEXT,
    owasp_id TEXT,
    compliance_tags TEXT DEFAULT '[]',
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);

CREATE INDEX IF NOT EXISTS idx_check_results_scan ON check_results(scan_id);
CREATE INDEX IF NOT EXISTS idx_check_results_status ON check_results(status);

-- Recommendations
CREATE TABLE IF NOT EXISTS recommendations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rec_id TEXT UNIQUE NOT NULL,
    scan_id TEXT NOT NULL,
    check_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    priority TEXT NOT NULL,
    category TEXT NOT NULL,
    remediation TEXT,
    evidence TEXT,
    compliance_tags TEXT DEFAULT '[]',
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at DATETIME,
    resolved_by TEXT,
    notes TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
);

CREATE INDEX IF NOT EXISTS idx_recommendations_priority ON recommendations(priority);
CREATE INDEX IF NOT EXISTS idx_recommendations_resolved ON recommendations(resolved);

-- User Journeys
CREATE TABLE IF NOT EXISTS journeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    journey_id TEXT UNIQUE NOT NULL,
    url TEXT NOT NULL,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT,
    steps TEXT DEFAULT '[]',
    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_tested DATETIME,
    test_status TEXT DEFAULT 'pending',
    coverage_percent REAL DEFAULT 0,
    test_results TEXT DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_journeys_category ON journeys(category);
CREATE INDEX IF NOT EXISTS idx_journeys_status ON journeys(test_status);

-- Clarifications
CREATE TABLE IF NOT EXISTS clarifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    clarification_id TEXT UNIQUE NOT NULL,
    journey_id TEXT,
    scan_id TEXT,
    type TEXT NOT NULL,
    question TEXT NOT NULL,
    context TEXT DEFAULT '{}',
    options TEXT DEFAULT '[]',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    responded_at DATETIME,
    response TEXT,
    status TEXT DEFAULT 'pending'
);

CREATE INDEX IF NOT EXISTS idx_clarifications_status ON clarifications(status);

-- Statistics (daily aggregates)
CREATE TABLE IF NOT EXISTS daily_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date DATE UNIQUE NOT NULL,
    scans_count INTEGER DEFAULT 0,
    avg_score REAL DEFAULT 0,
    total_checks_run INTEGER DEFAULT 0,
    total_passed INTEGER DEFAULT 0,
    total_failed INTEGER DEFAULT 0,
    total_warning INTEGER DEFAULT 0,
    journeys_detected INTEGER DEFAULT 0,
    clarifications_pending INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_daily_stats_date ON daily_stats(date DESC);
"""
