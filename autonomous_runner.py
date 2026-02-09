"""
Autonomous Runner - Runs the swarm 24/7 without human intervention
Only contacts human for payment approvals
"""
import os
import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, Any
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('/var/log/openclaw/autonomous.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

from dotenv import load_dotenv
load_dotenv()

from agents import OrchestratorAgent, MarketingAgent, FeedbackAgent, ImproverAgent, spawner
from memory.database import get_memory
from tools.notifications import notifications


class AutonomousSwarm:
    """
    Fully autonomous swarm controller.
    Runs forever, makes decisions, only asks human for payments.
    """

    def __init__(self):
        self.memory = get_memory()
        self.orchestrator = None
        self.running = True
        self.cycle_count = 0

        # Configuration
        self.daily_outreach_target = 50
        self.feedback_check_interval = 3600  # 1 hour
        self.improvement_check_interval = 86400  # 24 hours
        self.report_time = "09:00"  # Daily report at 9 AM

        # State
        self.last_feedback_check = datetime.now()
        self.last_improvement_check = datetime.now()
        self.last_daily_report = datetime.now() - timedelta(days=1)

        logger.info("Autonomous Swarm initialized")

    async def start(self):
        """Start the autonomous loop"""
        logger.info("=" * 50)
        logger.info("AUTONOMOUS SWARM STARTING")
        logger.info("=" * 50)

        # Initialize mission
        self._init_mission()

        # Start orchestrator
        self.orchestrator = OrchestratorAgent()
        logger.info(f"Orchestrator started: {self.orchestrator.agent_id}")

        # Main loop
        while self.running:
            try:
                await self._run_cycle()
                self.cycle_count += 1

                # Sleep between cycles (5 minutes)
                await asyncio.sleep(300)

            except Exception as e:
                logger.error(f"Cycle error: {e}")
                notifications.notify_error("Cycle Error", str(e))
                await asyncio.sleep(60)

    def _init_mission(self):
        """Initialize or update mission"""
        mission = self.memory.get_mission()
        if not mission:
            self.memory.initialize_mission(
                goal="$1M MRR",
                strategy={
                    "phase": "outreach",
                    "channels": ["twitter", "linkedin"],
                    "daily_target": self.daily_outreach_target,
                    "current_message": "default"
                }
            )
            logger.info("Mission initialized: $1M MRR")

    async def _run_cycle(self):
        """Run one autonomous cycle"""
        now = datetime.now()
        logger.info(f"Cycle {self.cycle_count} starting at {now.isoformat()}")

        # 1. Check metrics
        metrics = await self._get_metrics()
        logger.info(f"Metrics: {json.dumps(metrics, indent=2)}")

        # 2. Run outreach if needed
        await self._manage_outreach(metrics)

        # 3. Collect feedback (hourly)
        if (now - self.last_feedback_check).seconds > self.feedback_check_interval:
            await self._collect_feedback()
            self.last_feedback_check = now

        # 4. Run improvement cycle (daily)
        if (now - self.last_improvement_check).seconds > self.improvement_check_interval:
            await self._run_improvement_cycle()
            self.last_improvement_check = now

        # 5. Send daily report
        if self._should_send_daily_report(now):
            await self._send_daily_report(metrics)
            self.last_daily_report = now

        # 6. Self-optimize strategy
        await self._optimize_strategy(metrics)

        logger.info(f"Cycle {self.cycle_count} complete")

    async def _get_metrics(self) -> Dict[str, Any]:
        """Get current metrics"""
        stats = self.memory.get_outreach_stats()
        mission = self.memory.get_mission()

        return {
            "outreach": stats,
            "mission": {
                "goal": mission.goal if mission else "$1M MRR",
                "current_mrr": mission.current_mrr if mission else 0,
                "customers": mission.customers if mission else 0,
                "strategy": mission.strategy if mission else {}
            },
            "active_agents": len(spawner.list_active_agents()),
            "timestamp": datetime.now().isoformat()
        }

    async def _manage_outreach(self, metrics: Dict):
        """Spawn marketing agents if below daily target"""
        total_sent = metrics["outreach"]["total_sent"]
        target = self.daily_outreach_target

        if total_sent < target:
            remaining = target - total_sent
            logger.info(f"Outreach: {total_sent}/{target}. Spawning agents for {remaining} more.")

            # Spawn agents for each channel
            channels = metrics["mission"]["strategy"].get("channels", ["twitter"])

            for channel in channels:
                agent = await spawner.spawn(
                    role=f"Marketing-{channel}",
                    agent_class=MarketingAgent,
                    parent_id=self.orchestrator.agent_id,
                    platform=channel
                )

                count = remaining // len(channels)
                task = f"Reach out to {count} potential customers. Be personalized and provide value."

                asyncio.create_task(agent.run(task))
                logger.info(f"Spawned {channel} agent for {count} targets")

    async def _collect_feedback(self):
        """Spawn feedback agent to collect responses"""
        logger.info("Starting feedback collection")

        agent = await spawner.spawn(
            role="Feedback-Collector",
            agent_class=FeedbackAgent,
            parent_id=self.orchestrator.agent_id
        )

        await agent.run("Collect and analyze all new responses. Store insights in memory.")
        logger.info("Feedback collection complete")

    async def _run_improvement_cycle(self):
        """Run product improvement analysis"""
        logger.info("Starting improvement cycle")

        agent = await spawner.spawn(
            role="Product-Improver",
            agent_class=ImproverAgent,
            parent_id=self.orchestrator.agent_id
        )

        result = await agent.run("""
        Analyze all collected feedback.
        Identify top 3 improvements.
        Prioritize by impact vs effort.
        Create implementation plans for quick wins.
        """)

        # Notify about improvements
        if result.get("result"):
            notifications.notify_improvement_proposed({
                "title": "Daily Improvement Analysis",
                "description": result["result"][:500],
                "impact_score": 7,
                "effort_score": 5
            })

        logger.info("Improvement cycle complete")

    def _should_send_daily_report(self, now: datetime) -> bool:
        """Check if we should send daily report"""
        report_hour = int(self.report_time.split(":")[0])

        if now.hour == report_hour:
            if (now - self.last_daily_report).days >= 1:
                return True
        return False

    async def _send_daily_report(self, metrics: Dict):
        """Send daily email report"""
        logger.info("Sending daily report")
        notifications.notify_daily(metrics)

    async def _optimize_strategy(self, metrics: Dict):
        """Self-optimize based on performance"""
        response_rate = metrics["outreach"]["response_rate"]
        conversion_rate = metrics["outreach"]["conversion_rate"]

        strategy = metrics["mission"]["strategy"]
        changes = []

        # If response rate < 5%, change messaging
        if response_rate < 0.05 and metrics["outreach"]["total_sent"] > 20:
            strategy["current_message"] = "value_heavy"
            changes.append("Switched to value-heavy messaging due to low response rate")
            logger.warning(f"Low response rate ({response_rate*100:.1f}%). Changing strategy.")

        # If Twitter doing better than LinkedIn, focus there
        # (In production, track per-channel metrics)

        # If conversion rate > 10%, scale up
        if conversion_rate > 0.10:
            strategy["daily_target"] = min(100, strategy.get("daily_target", 50) + 20)
            changes.append(f"Increased daily target to {strategy['daily_target']}")
            logger.info("High conversion rate! Scaling up outreach.")

        if changes:
            self.memory.update_mission(strategy=strategy)
            logger.info(f"Strategy updated: {changes}")

    async def request_payment_approval(self, service: str, amount: float, reason: str):
        """
        Request human approval for payment.
        This is the ONLY place that requires human input.
        """
        logger.info(f"PAYMENT APPROVAL NEEDED: ${amount} for {service}")

        notifications.notify_payment_required(
            service=service,
            amount=amount,
            reason=reason,
            action_url=f"http://localhost:8080/approve-payment/{service}"
        )

        # The system continues running other tasks
        # Payment-dependent actions are queued until approved
        return {
            "status": "pending_approval",
            "service": service,
            "amount": amount
        }

    def stop(self):
        """Stop the swarm"""
        self.running = False
        logger.info("Swarm stopping...")


async def main():
    """Entry point for autonomous operation"""
    swarm = AutonomousSwarm()

    try:
        await swarm.start()
    except KeyboardInterrupt:
        swarm.stop()
        logger.info("Swarm stopped by user")


if __name__ == "__main__":
    asyncio.run(main())
