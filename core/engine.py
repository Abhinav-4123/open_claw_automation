"""
THE ENGINE - The Autonomous Execution Loop
Runs forever, self-heals, self-optimizes

This is what makes it "the first autonomous AI company"
"""
import os
import asyncio
import json
import traceback
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import logging

from .brain import brain, DecisionType
from .health import HealthMonitor
from .logger import DecisionLogger

# Setup logging
log_dir = os.getenv("LOG_DIR", "/var/log/openclaw")
os.makedirs(log_dir, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.FileHandler(f"{log_dir}/engine.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("Engine")


class AutonomousEngine:
    """
    The heart of the autonomous company.

    Capabilities:
    1. THINK - Use AI to analyze and decide
    2. ACT - Execute decisions
    3. LEARN - Improve from outcomes
    4. HEAL - Recover from failures
    5. SCALE - Adjust resources dynamically
    6. REPORT - Keep owner informed
    """

    def __init__(self):
        self.brain = brain
        self.health_monitor = HealthMonitor()
        self.decision_logger = DecisionLogger()

        self.running = False
        self.started_at: Optional[datetime] = None
        self.cycle_count = 0
        self.error_count = 0
        self.consecutive_errors = 0

        # Timing
        self.think_interval = 300  # 5 minutes
        self.health_check_interval = 60  # 1 minute
        self.report_interval = 86400  # 24 hours

        self.last_think = datetime.now()
        self.last_health_check = datetime.now()
        self.last_report = datetime.now() - timedelta(days=1)

        logger.info("Autonomous Engine initialized")

    async def start(self):
        """Start the autonomous loop"""
        self.running = True
        self.started_at = datetime.now()
        self.brain.running = True

        logger.info("=" * 60)
        logger.info("AUTONOMOUS ENGINE STARTING")
        logger.info(f"Time: {self.started_at.isoformat()}")
        logger.info("=" * 60)

        # Initial setup
        await self._initialize()

        # Main loop
        while self.running:
            try:
                await self._run_cycle()
                self.consecutive_errors = 0

            except Exception as e:
                self.error_count += 1
                self.consecutive_errors += 1
                logger.error(f"Cycle error: {e}\n{traceback.format_exc()}")

                # Self-healing
                if self.consecutive_errors >= 5:
                    logger.warning("Too many consecutive errors, initiating self-heal")
                    await self._self_heal()

            # Brief pause between cycles
            await asyncio.sleep(10)

    async def _initialize(self):
        """Initialize the system"""
        logger.info("Initializing system...")

        # Ensure database is ready
        from memory.database import get_memory
        memory = get_memory()

        # Initialize mission if needed
        if not memory.get_mission():
            memory.initialize_mission(
                goal="$1M MRR",
                strategy={
                    "phase": "growth",
                    "channels": ["twitter", "linkedin"],
                    "daily_target": 50,
                    "message_style": "value_first",
                    "version": 1
                }
            )
            logger.info("Mission initialized: $1M MRR")

        # Spawn initial agents
        await self._ensure_minimum_agents()

        logger.info("Initialization complete")

    async def _run_cycle(self):
        """Run one cycle of the autonomous loop"""
        self.cycle_count += 1
        now = datetime.now()

        logger.info(f"--- Cycle {self.cycle_count} ---")

        # 1. Health check (every minute)
        if (now - self.last_health_check).seconds >= self.health_check_interval:
            await self._check_health()
            self.last_health_check = now

        # 2. Think and act (every 5 minutes)
        if (now - self.last_think).seconds >= self.think_interval:
            await self._think_and_act()
            self.last_think = now

        # 3. Daily report
        if (now - self.last_report).seconds >= self.report_interval:
            await self._send_daily_report()
            self.last_report = now

    async def _check_health(self):
        """Check system health and take corrective action"""
        health = self.health_monitor.check()

        if health.score < 50:
            logger.warning(f"Health critical: {health.score}/100")
            logger.warning(f"Issues: {health.issues}")

            # Automatic corrective actions
            for issue in health.issues:
                await self._fix_issue(issue)

        elif health.score < 75:
            logger.info(f"Health moderate: {health.score}/100")

        else:
            logger.debug(f"Health good: {health.score}/100")

    async def _fix_issue(self, issue: str):
        """Automatically fix common issues"""
        logger.info(f"Fixing issue: {issue}")

        if "no_active_agents" in issue:
            await self._ensure_minimum_agents()

        elif "low_response_rate" in issue:
            # Change strategy
            context = self._build_context()
            context["urgent_issue"] = "response_rate_critical"
            decision = await self.brain.think(context)
            await self.brain.execute_decision(decision)

        elif "agent_failed" in issue:
            # Restart failed agents
            await self._restart_failed_agents()

    async def _think_and_act(self):
        """Core thinking loop - analyze and decide"""
        context = self._build_context()

        # Think
        logger.info("Thinking...")
        decision = await self.brain.think(context)

        # Log decision
        self.decision_logger.log(decision)
        logger.info(f"Decision: {decision.type.value} - {decision.reasoning[:100]}")

        # Act
        logger.info("Executing...")
        success = await self.brain.execute_decision(decision)

        if success:
            logger.info("Execution successful")
        else:
            logger.warning(f"Execution failed: {decision.outcome}")

    def _build_context(self) -> Dict[str, Any]:
        """Build context for AI decision making"""
        from memory.database import get_memory
        memory = get_memory()

        stats = memory.get_outreach_stats()
        mission = memory.get_mission()
        health = self.health_monitor.check()

        return {
            "timestamp": datetime.now().isoformat(),
            "uptime_hours": (datetime.now() - self.started_at).seconds / 3600 if self.started_at else 0,
            "cycle_count": self.cycle_count,
            "health_score": health.score,
            "health_issues": health.issues,
            "outreach": {
                "total_sent": stats.get("total_sent", 0),
                "responses": stats.get("responses", 0),
                "response_rate": stats.get("response_rate", 0),
                "conversions": stats.get("conversions", 0),
                "conversion_rate": stats.get("conversion_rate", 0)
            },
            "mission": {
                "goal": mission.goal if mission else "$1M MRR",
                "current_mrr": mission.current_mrr if mission else 0,
                "customers": mission.customers if mission else 0,
                "strategy": mission.strategy if mission else {}
            },
            "agents": {
                "active": len([a for a in self.brain.agents.values() if a.status == "running"]),
                "total": len(self.brain.agents),
                "failed": len([a for a in self.brain.agents.values() if a.status == "failed"])
            },
            "recent_decisions": [
                {"type": d.type.value, "success": d.success}
                for d in self.brain.decisions[-5:]
            ]
        }

    async def _ensure_minimum_agents(self):
        """Ensure minimum number of agents are running"""
        from agents import MarketingAgent, spawner

        active = len([a for a in self.brain.agents.values() if a.status == "running"])

        if active < self.brain.min_agents:
            needed = self.brain.min_agents - active
            logger.info(f"Spawning {needed} agents to meet minimum")

            for i in range(needed):
                platform = "twitter" if i % 2 == 0 else "linkedin"
                await self.brain._spawn_agent({"role": "marketing", "platform": platform})

    async def _restart_failed_agents(self):
        """Restart any failed agents"""
        failed = [a for a in self.brain.agents.values() if a.status == "failed"]

        for agent in failed:
            logger.info(f"Restarting failed agent: {agent.id}")
            await self.brain._spawn_agent({"role": agent.role, "platform": "twitter"})
            agent.status = "retired"  # Mark old one as retired

    async def _self_heal(self):
        """Emergency self-healing procedure"""
        logger.warning("INITIATING SELF-HEAL PROCEDURE")

        # 1. Clear all failed agents
        for agent_id, agent in self.brain.agents.items():
            if agent.status == "failed":
                agent.status = "retired"

        # 2. Ensure minimum agents
        await self._ensure_minimum_agents()

        # 3. Reset error counter
        self.consecutive_errors = 0

        # 4. Notify owner
        from tools.notifications import notifications
        notifications.notify_error(
            "Self-Heal Triggered",
            f"The system encountered {self.error_count} errors and initiated self-healing. "
            f"System is now recovered and continuing operation."
        )

        logger.info("Self-heal complete")

    async def _send_daily_report(self):
        """Send daily status report"""
        logger.info("Sending daily report")

        from tools.notifications import notifications
        from memory.database import get_memory

        memory = get_memory()
        stats = memory.get_outreach_stats()
        mission = memory.get_mission()

        notifications.notify_daily({
            "outreach": stats,
            "mission": {
                "goal": mission.goal if mission else "$1M MRR",
                "current_mrr": mission.current_mrr if mission else 0,
                "customers": mission.customers if mission else 0
            },
            "active_agents": len([a for a in self.brain.agents.values() if a.status == "running"])
        })

    def get_status(self) -> Dict[str, Any]:
        """Get current status for API"""
        return {
            "engine": {
                "status": "running" if self.running else "stopped",
                "started_at": self.started_at.isoformat() if self.started_at else None,
                "uptime": str(datetime.now() - self.started_at) if self.started_at else "0",
                "cycles": self.cycle_count,
                "errors": self.error_count
            },
            "brain": self.brain.get_status_report(),
            "health": self.health_monitor.check().__dict__
        }

    def stop(self):
        """Stop the engine"""
        logger.info("Engine stopping...")
        self.running = False
        self.brain.running = False


# Global engine instance
engine = AutonomousEngine()


async def run_forever():
    """Entry point for autonomous operation"""
    await engine.start()
