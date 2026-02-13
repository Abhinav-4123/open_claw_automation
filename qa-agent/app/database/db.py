"""
NEXUS QA - Database Operations
SQLite database handler with async support.
"""

import sqlite3
import json
from datetime import datetime, date, timedelta
from typing import List, Dict, Optional, Any
from pathlib import Path
import threading
from contextlib import contextmanager

from .models import (
    SCHEMA,
    ScanRecord,
    CheckResultRecord,
    RecommendationRecord,
    JourneyRecord,
    ClarificationRecord,
)


class Database:
    """SQLite database manager for NEXUS QA."""

    def __init__(self, db_path: str = "nexus_qa.db"):
        self.db_path = Path(db_path)
        self._local = threading.local()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Get thread-local database connection."""
        if not hasattr(self._local, 'connection'):
            self._local.connection = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False
            )
            self._local.connection.row_factory = sqlite3.Row
        return self._local.connection

    @contextmanager
    def _cursor(self):
        """Context manager for database cursor."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()

    def _init_db(self):
        """Initialize database schema."""
        with self._cursor() as cursor:
            cursor.executescript(SCHEMA)

    # ==================== Scans ====================

    def save_scan(self, scan: ScanRecord) -> int:
        """Save a scan record."""
        with self._cursor() as cursor:
            cursor.execute("""
                INSERT OR REPLACE INTO scans (
                    scan_id, url, timestamp, duration_seconds,
                    overall_score, total_checks, checks_passed,
                    checks_failed, checks_warning, checks_skipped,
                    status, error, category_scores
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan.scan_id, scan.url, scan.timestamp,
                scan.duration_seconds, scan.overall_score,
                scan.total_checks, scan.checks_passed,
                scan.checks_failed, scan.checks_warning,
                scan.checks_skipped, scan.status, scan.error,
                scan.category_scores
            ))
            return cursor.lastrowid

    def get_scan(self, scan_id: str) -> Optional[ScanRecord]:
        """Get a scan by ID."""
        with self._cursor() as cursor:
            cursor.execute(
                "SELECT * FROM scans WHERE scan_id = ?",
                (scan_id,)
            )
            row = cursor.fetchone()
            if row:
                return ScanRecord(
                    id=row['id'],
                    scan_id=row['scan_id'],
                    url=row['url'],
                    timestamp=datetime.fromisoformat(row['timestamp']),
                    duration_seconds=row['duration_seconds'],
                    overall_score=row['overall_score'],
                    total_checks=row['total_checks'],
                    checks_passed=row['checks_passed'],
                    checks_failed=row['checks_failed'],
                    checks_warning=row['checks_warning'],
                    checks_skipped=row['checks_skipped'],
                    status=row['status'],
                    error=row['error'],
                    category_scores=row['category_scores']
                )
            return None

    def get_recent_scans(self, limit: int = 50) -> List[ScanRecord]:
        """Get recent scans."""
        with self._cursor() as cursor:
            cursor.execute(
                "SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
            return [
                ScanRecord(
                    id=row['id'],
                    scan_id=row['scan_id'],
                    url=row['url'],
                    timestamp=datetime.fromisoformat(row['timestamp']),
                    duration_seconds=row['duration_seconds'],
                    overall_score=row['overall_score'],
                    total_checks=row['total_checks'],
                    checks_passed=row['checks_passed'],
                    checks_failed=row['checks_failed'],
                    checks_warning=row['checks_warning'],
                    checks_skipped=row['checks_skipped'],
                    status=row['status'],
                    error=row['error'],
                    category_scores=row['category_scores']
                )
                for row in cursor.fetchall()
            ]

    def get_scans_by_url(self, url: str, limit: int = 10) -> List[ScanRecord]:
        """Get scans for a specific URL."""
        with self._cursor() as cursor:
            cursor.execute(
                "SELECT * FROM scans WHERE url = ? ORDER BY timestamp DESC LIMIT ?",
                (url, limit)
            )
            return [
                ScanRecord(
                    id=row['id'],
                    scan_id=row['scan_id'],
                    url=row['url'],
                    timestamp=datetime.fromisoformat(row['timestamp']),
                    duration_seconds=row['duration_seconds'],
                    overall_score=row['overall_score'],
                    total_checks=row['total_checks'],
                    checks_passed=row['checks_passed'],
                    checks_failed=row['checks_failed'],
                    checks_warning=row['checks_warning'],
                    checks_skipped=row['checks_skipped'],
                    status=row['status'],
                    error=row['error'],
                    category_scores=row['category_scores']
                )
                for row in cursor.fetchall()
            ]

    # ==================== Check Results ====================

    def save_check_result(self, result: CheckResultRecord) -> int:
        """Save a check result."""
        with self._cursor() as cursor:
            cursor.execute("""
                INSERT INTO check_results (
                    scan_id, check_id, category, name, status,
                    severity, message, evidence, remediation,
                    cwe_id, owasp_id, compliance_tags
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                result.scan_id, result.check_id, result.category,
                result.name, result.status, result.severity,
                result.message, result.evidence, result.remediation,
                result.cwe_id, result.owasp_id, result.compliance_tags
            ))
            return cursor.lastrowid

    def save_check_results_bulk(self, results: List[CheckResultRecord]):
        """Save multiple check results."""
        with self._cursor() as cursor:
            cursor.executemany("""
                INSERT INTO check_results (
                    scan_id, check_id, category, name, status,
                    severity, message, evidence, remediation,
                    cwe_id, owasp_id, compliance_tags
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                (
                    r.scan_id, r.check_id, r.category,
                    r.name, r.status, r.severity,
                    r.message, r.evidence, r.remediation,
                    r.cwe_id, r.owasp_id, r.compliance_tags
                )
                for r in results
            ])

    def get_check_results(self, scan_id: str) -> List[CheckResultRecord]:
        """Get all check results for a scan."""
        with self._cursor() as cursor:
            cursor.execute(
                "SELECT * FROM check_results WHERE scan_id = ?",
                (scan_id,)
            )
            return [
                CheckResultRecord(
                    id=row['id'],
                    scan_id=row['scan_id'],
                    check_id=row['check_id'],
                    category=row['category'],
                    name=row['name'],
                    status=row['status'],
                    severity=row['severity'],
                    message=row['message'],
                    evidence=row['evidence'],
                    remediation=row['remediation'],
                    cwe_id=row['cwe_id'],
                    owasp_id=row['owasp_id'],
                    compliance_tags=row['compliance_tags']
                )
                for row in cursor.fetchall()
            ]

    # ==================== Recommendations ====================

    def save_recommendation(self, rec: RecommendationRecord) -> int:
        """Save a recommendation."""
        with self._cursor() as cursor:
            cursor.execute("""
                INSERT OR REPLACE INTO recommendations (
                    rec_id, scan_id, check_id, title, description,
                    priority, category, remediation, evidence,
                    compliance_tags, resolved, resolved_at,
                    resolved_by, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rec.rec_id, rec.scan_id, rec.check_id,
                rec.title, rec.description, rec.priority,
                rec.category, rec.remediation, rec.evidence,
                rec.compliance_tags, rec.resolved, rec.resolved_at,
                rec.resolved_by, rec.notes
            ))
            return cursor.lastrowid

    def save_recommendations_bulk(self, recs: List[RecommendationRecord]):
        """Save multiple recommendations."""
        with self._cursor() as cursor:
            cursor.executemany("""
                INSERT OR REPLACE INTO recommendations (
                    rec_id, scan_id, check_id, title, description,
                    priority, category, remediation, evidence,
                    compliance_tags, resolved, resolved_at,
                    resolved_by, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                (
                    r.rec_id, r.scan_id, r.check_id,
                    r.title, r.description, r.priority,
                    r.category, r.remediation, r.evidence,
                    r.compliance_tags, r.resolved, r.resolved_at,
                    r.resolved_by, r.notes
                )
                for r in recs
            ])

    def get_recommendations(
        self,
        priority: Optional[str] = None,
        resolved: Optional[bool] = None,
        limit: int = 100
    ) -> List[RecommendationRecord]:
        """Get recommendations with optional filters."""
        query = "SELECT * FROM recommendations WHERE 1=1"
        params = []

        if priority:
            query += " AND priority = ?"
            params.append(priority)

        if resolved is not None:
            query += " AND resolved = ?"
            params.append(resolved)

        query += " ORDER BY CASE priority WHEN 'P0' THEN 1 WHEN 'P1' THEN 2 ELSE 3 END"
        query += " LIMIT ?"
        params.append(limit)

        with self._cursor() as cursor:
            cursor.execute(query, params)
            return [
                RecommendationRecord(
                    id=row['id'],
                    rec_id=row['rec_id'],
                    scan_id=row['scan_id'],
                    check_id=row['check_id'],
                    title=row['title'],
                    description=row['description'],
                    priority=row['priority'],
                    category=row['category'],
                    remediation=row['remediation'],
                    evidence=row['evidence'],
                    compliance_tags=row['compliance_tags'],
                    resolved=bool(row['resolved']),
                    resolved_at=datetime.fromisoformat(row['resolved_at']) if row['resolved_at'] else None,
                    resolved_by=row['resolved_by'],
                    notes=row['notes']
                )
                for row in cursor.fetchall()
            ]

    def resolve_recommendation(
        self,
        rec_id: str,
        resolved_by: str = "user",
        notes: Optional[str] = None
    ) -> bool:
        """Mark a recommendation as resolved."""
        with self._cursor() as cursor:
            cursor.execute("""
                UPDATE recommendations
                SET resolved = TRUE, resolved_at = ?, resolved_by = ?, notes = ?
                WHERE rec_id = ?
            """, (datetime.now(), resolved_by, notes, rec_id))
            return cursor.rowcount > 0

    # ==================== Journeys ====================

    def save_journey(self, journey: JourneyRecord) -> int:
        """Save a journey record."""
        with self._cursor() as cursor:
            cursor.execute("""
                INSERT OR REPLACE INTO journeys (
                    journey_id, url, name, category, description,
                    steps, detected_at, last_tested, test_status,
                    coverage_percent, test_results
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                journey.journey_id, journey.url, journey.name,
                journey.category, journey.description, journey.steps,
                journey.detected_at, journey.last_tested, journey.test_status,
                journey.coverage_percent, journey.test_results
            ))
            return cursor.lastrowid

    def get_journey(self, journey_id: str) -> Optional[JourneyRecord]:
        """Get a journey by ID."""
        with self._cursor() as cursor:
            cursor.execute(
                "SELECT * FROM journeys WHERE journey_id = ?",
                (journey_id,)
            )
            row = cursor.fetchone()
            if row:
                return JourneyRecord(
                    id=row['id'],
                    journey_id=row['journey_id'],
                    url=row['url'],
                    name=row['name'],
                    category=row['category'],
                    description=row['description'],
                    steps=row['steps'],
                    detected_at=datetime.fromisoformat(row['detected_at']),
                    last_tested=datetime.fromisoformat(row['last_tested']) if row['last_tested'] else None,
                    test_status=row['test_status'],
                    coverage_percent=row['coverage_percent'],
                    test_results=row['test_results']
                )
            return None

    def get_journeys(
        self,
        category: Optional[str] = None,
        status: Optional[str] = None
    ) -> List[JourneyRecord]:
        """Get journeys with optional filters."""
        query = "SELECT * FROM journeys WHERE 1=1"
        params = []

        if category:
            query += " AND category = ?"
            params.append(category)

        if status:
            query += " AND test_status = ?"
            params.append(status)

        query += " ORDER BY detected_at DESC"

        with self._cursor() as cursor:
            cursor.execute(query, params)
            return [
                JourneyRecord(
                    id=row['id'],
                    journey_id=row['journey_id'],
                    url=row['url'],
                    name=row['name'],
                    category=row['category'],
                    description=row['description'],
                    steps=row['steps'],
                    detected_at=datetime.fromisoformat(row['detected_at']),
                    last_tested=datetime.fromisoformat(row['last_tested']) if row['last_tested'] else None,
                    test_status=row['test_status'],
                    coverage_percent=row['coverage_percent'],
                    test_results=row['test_results']
                )
                for row in cursor.fetchall()
            ]

    def update_journey_test_status(
        self,
        journey_id: str,
        status: str,
        coverage: float,
        results: Dict[str, Any]
    ) -> bool:
        """Update journey test status."""
        with self._cursor() as cursor:
            cursor.execute("""
                UPDATE journeys
                SET last_tested = ?, test_status = ?,
                    coverage_percent = ?, test_results = ?
                WHERE journey_id = ?
            """, (
                datetime.now(), status, coverage,
                json.dumps(results), journey_id
            ))
            return cursor.rowcount > 0

    # ==================== Clarifications ====================

    def save_clarification(self, clarification: ClarificationRecord) -> int:
        """Save a clarification request."""
        with self._cursor() as cursor:
            cursor.execute("""
                INSERT INTO clarifications (
                    clarification_id, journey_id, scan_id, type,
                    question, context, options, created_at,
                    responded_at, response, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                clarification.clarification_id, clarification.journey_id,
                clarification.scan_id, clarification.type,
                clarification.question, clarification.context,
                clarification.options, clarification.created_at,
                clarification.responded_at, clarification.response,
                clarification.status
            ))
            return cursor.lastrowid

    def get_pending_clarifications(self) -> List[ClarificationRecord]:
        """Get all pending clarifications."""
        with self._cursor() as cursor:
            cursor.execute(
                "SELECT * FROM clarifications WHERE status = 'pending' ORDER BY created_at"
            )
            return [
                ClarificationRecord(
                    id=row['id'],
                    clarification_id=row['clarification_id'],
                    journey_id=row['journey_id'],
                    scan_id=row['scan_id'],
                    type=row['type'],
                    question=row['question'],
                    context=row['context'],
                    options=row['options'],
                    created_at=datetime.fromisoformat(row['created_at']),
                    responded_at=datetime.fromisoformat(row['responded_at']) if row['responded_at'] else None,
                    response=row['response'],
                    status=row['status']
                )
                for row in cursor.fetchall()
            ]

    def respond_to_clarification(
        self,
        clarification_id: str,
        response: str
    ) -> bool:
        """Respond to a clarification request."""
        with self._cursor() as cursor:
            cursor.execute("""
                UPDATE clarifications
                SET response = ?, responded_at = ?, status = 'responded'
                WHERE clarification_id = ?
            """, (response, datetime.now(), clarification_id))
            return cursor.rowcount > 0

    # ==================== Statistics ====================

    def update_daily_stats(self):
        """Update daily statistics."""
        today = date.today()

        with self._cursor() as cursor:
            # Get today's scan stats
            cursor.execute("""
                SELECT
                    COUNT(*) as scans_count,
                    AVG(overall_score) as avg_score,
                    SUM(total_checks) as total_checks,
                    SUM(checks_passed) as total_passed,
                    SUM(checks_failed) as total_failed,
                    SUM(checks_warning) as total_warning
                FROM scans
                WHERE DATE(timestamp) = ?
            """, (today,))
            scan_stats = cursor.fetchone()

            # Get journey count
            cursor.execute(
                "SELECT COUNT(*) FROM journeys WHERE DATE(detected_at) = ?",
                (today,)
            )
            journeys_count = cursor.fetchone()[0]

            # Get pending clarifications
            cursor.execute(
                "SELECT COUNT(*) FROM clarifications WHERE status = 'pending'"
            )
            pending_clarifications = cursor.fetchone()[0]

            # Upsert daily stats
            cursor.execute("""
                INSERT OR REPLACE INTO daily_stats (
                    date, scans_count, avg_score, total_checks_run,
                    total_passed, total_failed, total_warning,
                    journeys_detected, clarifications_pending
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                today,
                scan_stats['scans_count'] or 0,
                scan_stats['avg_score'] or 0,
                scan_stats['total_checks'] or 0,
                scan_stats['total_passed'] or 0,
                scan_stats['total_failed'] or 0,
                scan_stats['total_warning'] or 0,
                journeys_count,
                pending_clarifications
            ))

    def get_trend_data(self, days: int = 7) -> List[Dict[str, Any]]:
        """Get trend data for the last N days."""
        with self._cursor() as cursor:
            cursor.execute("""
                SELECT * FROM daily_stats
                WHERE date >= DATE('now', ?)
                ORDER BY date
            """, (f'-{days} days',))
            return [dict(row) for row in cursor.fetchall()]

    def get_overview_stats(self) -> Dict[str, Any]:
        """Get overview statistics."""
        with self._cursor() as cursor:
            # Latest scan score
            cursor.execute(
                "SELECT overall_score FROM scans ORDER BY timestamp DESC LIMIT 1"
            )
            row = cursor.fetchone()
            latest_score = row[0] if row else 0

            # Total scans
            cursor.execute("SELECT COUNT(*) FROM scans")
            total_scans = cursor.fetchone()[0]

            # Average score (last 7 days)
            cursor.execute("""
                SELECT AVG(overall_score) FROM scans
                WHERE timestamp >= DATETIME('now', '-7 days')
            """)
            row = cursor.fetchone()
            avg_score_7d = row[0] if row[0] else 0

            # Open recommendations by priority
            cursor.execute("""
                SELECT priority, COUNT(*) as count
                FROM recommendations
                WHERE resolved = FALSE
                GROUP BY priority
            """)
            open_recs = {row['priority']: row['count'] for row in cursor.fetchall()}

            # Total journeys
            cursor.execute("SELECT COUNT(*) FROM journeys")
            total_journeys = cursor.fetchone()[0]

            # Pending clarifications
            cursor.execute(
                "SELECT COUNT(*) FROM clarifications WHERE status = 'pending'"
            )
            pending_clarifications = cursor.fetchone()[0]

            return {
                "latest_score": round(latest_score, 1),
                "total_scans": total_scans,
                "avg_score_7d": round(avg_score_7d, 1),
                "open_recommendations": open_recs,
                "total_recommendations": sum(open_recs.values()),
                "total_journeys": total_journeys,
                "pending_clarifications": pending_clarifications,
            }


# Singleton instance
_db_instance: Optional[Database] = None


def get_db(db_path: str = "nexus_qa.db") -> Database:
    """Get the singleton database instance."""
    global _db_instance
    if _db_instance is None:
        _db_instance = Database(db_path)
    return _db_instance
