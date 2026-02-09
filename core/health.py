"""
Health Monitor - Watches system health and detects issues
"""
from dataclasses import dataclass
from typing import List
from datetime import datetime, timedelta


@dataclass
class HealthReport:
    score: int  # 0-100
    status: str  # healthy, degraded, critical
    issues: List[str]
    timestamp: datetime


class HealthMonitor:
    """Monitors system health"""

    def __init__(self):
        self.last_check: HealthReport = None

    def check(self) -> HealthReport:
        """Run health check"""
        score = 100
        issues = []

        # Import here to avoid circular imports
        from memory.database import get_memory
        from .brain import brain

        memory = get_memory()
        stats = memory.get_outreach_stats()

        # Check 1: Active agents
        active_agents = len([a for a in brain.agents.values() if a.status == "running"])
        if active_agents == 0:
            score -= 40
            issues.append("no_active_agents")
        elif active_agents < 2:
            score -= 15
            issues.append("low_agent_count")

        # Check 2: Response rate
        response_rate = stats.get("response_rate", 0)
        if stats.get("total_sent", 0) > 20:  # Only check if we have enough data
            if response_rate < 0.03:
                score -= 30
                issues.append("low_response_rate_critical")
            elif response_rate < 0.05:
                score -= 15
                issues.append("low_response_rate")

        # Check 3: Failed agents
        failed_agents = len([a for a in brain.agents.values() if a.status == "failed"])
        if failed_agents > 3:
            score -= 25
            issues.append("multiple_agents_failed")
        elif failed_agents > 0:
            score -= 10
            issues.append("agent_failed")

        # Check 4: Recent activity
        if brain.decisions:
            last_decision = brain.decisions[-1]
            time_since_decision = datetime.now() - last_decision.timestamp
            if time_since_decision > timedelta(hours=1):
                score -= 20
                issues.append("no_recent_activity")

        # Check 5: Decision success rate
        recent_decisions = brain.decisions[-10:] if len(brain.decisions) >= 10 else brain.decisions
        if recent_decisions:
            success_rate = sum(1 for d in recent_decisions if d.success) / len(recent_decisions)
            if success_rate < 0.5:
                score -= 20
                issues.append("low_decision_success_rate")

        # Determine status
        if score >= 75:
            status = "healthy"
        elif score >= 50:
            status = "degraded"
        else:
            status = "critical"

        report = HealthReport(
            score=max(0, score),
            status=status,
            issues=issues,
            timestamp=datetime.now()
        )

        self.last_check = report
        return report
