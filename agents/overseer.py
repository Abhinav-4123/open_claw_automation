"""
Overseer Agent - The System Watchdog
Monitors everything, reviews progress, unblocks issues, creates resources
Runs every 2 hours to ensure continuous progress
"""
import os
import json
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum

import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))


class BlockerType(Enum):
    MISSING_RESOURCE = "missing_resource"
    AGENT_STUCK = "agent_stuck"
    TASK_FAILED = "task_failed"
    DEPENDENCY_ISSUE = "dependency_issue"
    CONFIGURATION_ERROR = "configuration_error"
    EXTERNAL_SERVICE = "external_service"
    UNKNOWN = "unknown"


class ActionType(Enum):
    CREATE_AGENT = "create_agent"
    CREATE_TASK = "create_task"
    RESTART_AGENT = "restart_agent"
    ESCALATE_TO_QUEEN = "escalate_to_queen"
    CREATE_RESOURCE = "create_resource"
    SEND_NOTIFICATION = "send_notification"
    MODIFY_CONFIG = "modify_config"
    RETRY_TASK = "retry_task"


@dataclass
class SystemStatus:
    """Current system status snapshot"""
    timestamp: datetime
    active_agents: int
    pending_tasks: int
    completed_tasks: int
    failed_tasks: int
    blockers: List[Dict]
    health_score: float  # 0-100
    recommendations: List[str]


@dataclass
class Blocker:
    """An identified blocker in the system"""
    id: str
    type: BlockerType
    description: str
    affected_agent: Optional[str]
    affected_task: Optional[str]
    severity: str  # critical, high, medium, low
    detected_at: datetime
    resolved: bool = False
    resolution: Optional[str] = None


@dataclass
class OverseerAction:
    """An action taken by the Overseer"""
    id: str
    type: ActionType
    description: str
    target: str
    status: str  # pending, in_progress, completed, failed
    created_at: datetime
    completed_at: Optional[datetime] = None
    result: Optional[Dict] = None


class OverseerAgent:
    """
    The Overseer Agent - System Watchdog and Orchestrator

    Responsibilities:
    - Monitor system health every 2 hours
    - Review progress on all tasks and goals
    - Identify blockers and bottlenecks
    - Communicate with Queen for strategic planning
    - Coordinate with other agents to resolve issues
    - Create new resources when needed
    - Ensure continuous progress toward company goals
    """

    def __init__(self):
        self.model = genai.GenerativeModel('gemini-2.0-flash')
        self.agent_id = f"overseer_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.check_interval = 2 * 60 * 60  # 2 hours in seconds
        self.last_check: Optional[datetime] = None
        self.status_history: List[SystemStatus] = []
        self.blockers: Dict[str, Blocker] = {}
        self.actions: Dict[str, OverseerAction] = {}
        self.running = False

        # Thresholds for health scoring
        self.thresholds = {
            "max_pending_tasks": 20,
            "min_completion_rate": 0.6,
            "max_failed_tasks": 5,
            "max_idle_agents": 2,
            "max_blocker_age_hours": 4
        }

    async def start_monitoring(self):
        """Start the periodic monitoring loop"""
        self.running = True
        print(f"[OVERSEER] Starting monitoring cycle (every {self.check_interval // 3600} hours)")

        while self.running:
            try:
                await self.run_check_cycle()
            except Exception as e:
                print(f"[OVERSEER] Error in check cycle: {e}")

            # Wait for next check interval
            await asyncio.sleep(self.check_interval)

    async def stop_monitoring(self):
        """Stop the monitoring loop"""
        self.running = False
        print("[OVERSEER] Monitoring stopped")

    async def run_check_cycle(self):
        """Run a complete check cycle"""
        print(f"\n{'='*60}")
        print(f"[OVERSEER] Running system check at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}")

        # 1. Gather system status
        status = await self.gather_system_status()
        self.status_history.append(status)
        self.last_check = datetime.now()

        # 2. Analyze and identify blockers
        new_blockers = await self.identify_blockers(status)
        for blocker in new_blockers:
            self.blockers[blocker.id] = blocker

        # 3. Generate action plan
        actions = await self.plan_actions(status, new_blockers)

        # 4. Execute actions
        for action in actions:
            await self.execute_action(action)

        # 5. Report to Queen if needed
        if status.health_score < 70 or len(new_blockers) > 0:
            await self.report_to_queen(status, new_blockers)

        # 6. Log summary
        self._log_summary(status, new_blockers, actions)

        return status

    async def gather_system_status(self) -> SystemStatus:
        """Gather current system status from all components"""
        from agents.chef import chef
        from agents.queen import queen
        from control_center import control_center

        # Get agent stats
        all_agents = chef.get_all_agents()
        active_agents = len([a for a in all_agents if a.get("status") == "active"])

        # Get task stats
        dashboard = control_center.get_dashboard_data()
        metrics = dashboard.get("metrics", {})
        pending_tasks = metrics.get("pending_tasks", 0)
        completed_tasks = metrics.get("completed_tasks", 0)
        active_tasks = metrics.get("active_tasks", 0)

        # Calculate failed tasks (from recent activity)
        failed_tasks = 0  # Would be tracked in actual implementation

        # Get Queen status
        queen_status = queen.get_status()
        daily_goals = queen_status.get("daily_goals", 0)
        goals_completed = queen_status.get("goals_completed", 0)

        # Identify blockers
        blockers = []

        # Check for idle agents
        for agent in all_agents:
            if agent.get("status") == "active" and not agent.get("current_task"):
                idle_time = datetime.now()  # Would calculate actual idle time
                if agent.get("tasks_completed", 0) == 0:
                    blockers.append({
                        "type": "idle_agent",
                        "agent_id": agent.get("id"),
                        "description": f"Agent {agent.get('type')} has no tasks"
                    })

        # Check for stalled tasks
        for task in dashboard.get("active_tasks", []):
            # Would check if task has been active too long
            pass

        # Check if daily goals are being met
        if daily_goals > 0 and goals_completed / daily_goals < 0.5:
            blockers.append({
                "type": "goals_behind",
                "description": f"Daily goals behind: {goals_completed}/{daily_goals}"
            })

        # Calculate health score
        health_score = self._calculate_health_score(
            active_agents=active_agents,
            pending_tasks=pending_tasks,
            completed_tasks=completed_tasks,
            failed_tasks=failed_tasks,
            blockers_count=len(blockers),
            goals_completion=goals_completed / max(daily_goals, 1)
        )

        # Generate recommendations
        recommendations = await self._generate_recommendations(
            health_score, blockers, active_agents, pending_tasks
        )

        return SystemStatus(
            timestamp=datetime.now(),
            active_agents=active_agents,
            pending_tasks=pending_tasks,
            completed_tasks=completed_tasks,
            failed_tasks=failed_tasks,
            blockers=blockers,
            health_score=health_score,
            recommendations=recommendations
        )

    def _calculate_health_score(
        self,
        active_agents: int,
        pending_tasks: int,
        completed_tasks: int,
        failed_tasks: int,
        blockers_count: int,
        goals_completion: float
    ) -> float:
        """Calculate overall system health score (0-100)"""
        score = 100.0

        # Penalize for too many pending tasks
        if pending_tasks > self.thresholds["max_pending_tasks"]:
            score -= min(20, (pending_tasks - self.thresholds["max_pending_tasks"]) * 2)

        # Penalize for failed tasks
        if failed_tasks > 0:
            score -= min(30, failed_tasks * 5)

        # Penalize for blockers
        score -= min(25, blockers_count * 5)

        # Bonus for goal completion
        score += goals_completion * 10

        # Penalize for no active agents
        if active_agents == 0:
            score -= 30

        return max(0, min(100, score))

    async def _generate_recommendations(
        self,
        health_score: float,
        blockers: List[Dict],
        active_agents: int,
        pending_tasks: int
    ) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []

        if health_score < 50:
            recommendations.append("CRITICAL: System health is poor. Immediate attention required.")

        if pending_tasks > self.thresholds["max_pending_tasks"]:
            recommendations.append(f"Create additional agents to handle {pending_tasks} pending tasks")

        if active_agents < 3:
            recommendations.append("Spawn more worker agents for parallel processing")

        for blocker in blockers:
            if blocker.get("type") == "idle_agent":
                recommendations.append(f"Assign tasks to idle agent: {blocker.get('agent_id')}")
            elif blocker.get("type") == "goals_behind":
                recommendations.append("Prioritize daily goals - behind schedule")

        if not recommendations:
            recommendations.append("System healthy. Continue current operations.")

        return recommendations

    async def identify_blockers(self, status: SystemStatus) -> List[Blocker]:
        """Identify new blockers in the system"""
        new_blockers = []

        for blocker_info in status.blockers:
            blocker_id = f"blocker_{datetime.now().strftime('%H%M%S')}_{len(self.blockers)}"

            blocker_type = {
                "idle_agent": BlockerType.AGENT_STUCK,
                "goals_behind": BlockerType.DEPENDENCY_ISSUE,
                "task_stalled": BlockerType.TASK_FAILED
            }.get(blocker_info.get("type"), BlockerType.UNKNOWN)

            severity = "high" if status.health_score < 50 else "medium"

            blocker = Blocker(
                id=blocker_id,
                type=blocker_type,
                description=blocker_info.get("description", "Unknown issue"),
                affected_agent=blocker_info.get("agent_id"),
                affected_task=blocker_info.get("task_id"),
                severity=severity,
                detected_at=datetime.now()
            )
            new_blockers.append(blocker)

        return new_blockers

    async def plan_actions(
        self,
        status: SystemStatus,
        blockers: List[Blocker]
    ) -> List[OverseerAction]:
        """Plan actions to resolve blockers and improve system health"""
        actions = []

        # Use AI to generate action plan
        prompt = f"""As the Overseer Agent, analyze this system status and plan corrective actions:

System Health: {status.health_score:.1f}/100
Active Agents: {status.active_agents}
Pending Tasks: {status.pending_tasks}
Completed Tasks: {status.completed_tasks}
Failed Tasks: {status.failed_tasks}

Blockers:
{json.dumps([{"type": b.type.value, "description": b.description, "severity": b.severity} for b in blockers], indent=2)}

Recommendations:
{json.dumps(status.recommendations, indent=2)}

Generate specific actions to improve system performance.
Return JSON array:
[
    {{
        "action_type": "create_agent|create_task|restart_agent|escalate_to_queen|create_resource",
        "description": "What to do",
        "target": "What/who to act on",
        "priority": "critical|high|medium|low"
    }}
]

Return ONLY the JSON array, no other text. Maximum 5 actions."""

        try:
            response = self.model.generate_content(prompt)
            text = response.text.strip()
            if "```" in text:
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]

            planned_actions = json.loads(text)

            for i, action_info in enumerate(planned_actions[:5]):
                action_type = {
                    "create_agent": ActionType.CREATE_AGENT,
                    "create_task": ActionType.CREATE_TASK,
                    "restart_agent": ActionType.RESTART_AGENT,
                    "escalate_to_queen": ActionType.ESCALATE_TO_QUEEN,
                    "create_resource": ActionType.CREATE_RESOURCE,
                    "retry_task": ActionType.RETRY_TASK
                }.get(action_info.get("action_type"), ActionType.SEND_NOTIFICATION)

                action = OverseerAction(
                    id=f"action_{datetime.now().strftime('%H%M%S')}_{i}",
                    type=action_type,
                    description=action_info.get("description", ""),
                    target=action_info.get("target", ""),
                    status="pending",
                    created_at=datetime.now()
                )
                actions.append(action)

        except Exception as e:
            print(f"[OVERSEER] Error planning actions: {e}")
            # Fallback: basic actions based on status
            if status.pending_tasks > 10 and status.active_agents < 4:
                actions.append(OverseerAction(
                    id=f"action_{datetime.now().strftime('%H%M%S')}_fallback",
                    type=ActionType.CREATE_AGENT,
                    description="Create additional worker agent for pending tasks",
                    target="coder",
                    status="pending",
                    created_at=datetime.now()
                ))

        return actions

    async def execute_action(self, action: OverseerAction):
        """Execute a planned action"""
        action.status = "in_progress"
        self.actions[action.id] = action

        print(f"[OVERSEER] Executing: {action.type.value} - {action.description}")

        try:
            if action.type == ActionType.CREATE_AGENT:
                result = await self._action_create_agent(action.target)
            elif action.type == ActionType.CREATE_TASK:
                result = await self._action_create_task(action.description, action.target)
            elif action.type == ActionType.RESTART_AGENT:
                result = await self._action_restart_agent(action.target)
            elif action.type == ActionType.ESCALATE_TO_QUEEN:
                result = await self._action_escalate_to_queen(action.description)
            elif action.type == ActionType.CREATE_RESOURCE:
                result = await self._action_create_resource(action.target, action.description)
            elif action.type == ActionType.RETRY_TASK:
                result = await self._action_retry_task(action.target)
            else:
                result = {"status": "skipped", "reason": "Unknown action type"}

            action.status = "completed"
            action.result = result
            action.completed_at = datetime.now()

        except Exception as e:
            action.status = "failed"
            action.result = {"error": str(e)}
            print(f"[OVERSEER] Action failed: {e}")

    async def _action_create_agent(self, agent_type: str) -> Dict:
        """Create a new agent"""
        from agents.chef import chef
        agent = await chef.create_agent(agent_type)
        return {"agent_id": agent.get("id"), "type": agent_type}

    async def _action_create_task(self, description: str, category: str) -> Dict:
        """Create a new task"""
        from control_center import control_center
        control_center.receive_user_input(
            text=description,
            category=category,
            priority="high"
        )
        return {"task_created": True, "description": description[:50]}

    async def _action_restart_agent(self, agent_id: str) -> Dict:
        """Restart a stuck agent"""
        from agents.chef import chef
        # In real implementation, would actually restart the agent
        if agent_id in chef.agent_registry:
            chef.agent_registry[agent_id]["status"] = "active"
            chef.agent_registry[agent_id]["current_task"] = None
        return {"restarted": agent_id}

    async def _action_escalate_to_queen(self, issue: str) -> Dict:
        """Escalate issue to Queen for strategic decision"""
        from agents.queen import queen

        prompt = f"""URGENT ESCALATION FROM OVERSEER:

Issue: {issue}

Please provide strategic guidance on how to address this issue.
What agents or resources should be allocated?
What is the priority of this issue?"""

        try:
            response = self.model.generate_content(prompt)
            guidance = response.text[:500]
        except:
            guidance = "Unable to get Queen guidance - proceeding with default actions"

        return {"escalated": True, "queen_guidance": guidance}

    async def _action_create_resource(self, resource_type: str, description: str) -> Dict:
        """Create a new resource (file, config, etc.)"""
        # In real implementation, would create actual resources
        return {"resource_created": resource_type, "description": description[:50]}

    async def _action_retry_task(self, task_id: str) -> Dict:
        """Retry a failed task"""
        from control_center import control_center
        # Would reset task status and re-queue
        return {"retried": task_id}

    async def report_to_queen(self, status: SystemStatus, blockers: List[Blocker]):
        """Send status report to Queen Agent"""
        from agents.queen import queen

        report = f"""
=== OVERSEER STATUS REPORT ===
Time: {status.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
Health Score: {status.health_score:.1f}/100

Metrics:
- Active Agents: {status.active_agents}
- Pending Tasks: {status.pending_tasks}
- Completed Tasks: {status.completed_tasks}
- Failed Tasks: {status.failed_tasks}

Blockers ({len(blockers)}):
{chr(10).join([f'  - [{b.severity.upper()}] {b.description}' for b in blockers]) or '  None'}

Recommendations:
{chr(10).join([f'  - {r}' for r in status.recommendations])}
================================
"""
        print(report)

        # Update Queen metrics
        queen.metrics["overseer_last_report"] = datetime.now().isoformat()
        queen.metrics["system_health"] = status.health_score

    def _log_summary(
        self,
        status: SystemStatus,
        blockers: List[Blocker],
        actions: List[OverseerAction]
    ):
        """Log check cycle summary"""
        print(f"\n[OVERSEER] Check Complete:")
        print(f"  Health Score: {status.health_score:.1f}/100")
        print(f"  Blockers Found: {len(blockers)}")
        print(f"  Actions Taken: {len(actions)}")
        print(f"  Next Check: {(datetime.now() + timedelta(seconds=self.check_interval)).strftime('%H:%M:%S')}")

    def get_status(self) -> Dict:
        """Get Overseer status"""
        return {
            "agent_id": self.agent_id,
            "running": self.running,
            "last_check": self.last_check.isoformat() if self.last_check else None,
            "check_interval_hours": self.check_interval / 3600,
            "total_checks": len(self.status_history),
            "active_blockers": len([b for b in self.blockers.values() if not b.resolved]),
            "actions_taken": len(self.actions),
            "latest_health_score": self.status_history[-1].health_score if self.status_history else None
        }

    def get_health_history(self, limit: int = 10) -> List[Dict]:
        """Get health score history"""
        return [
            {
                "timestamp": s.timestamp.isoformat(),
                "health_score": s.health_score,
                "active_agents": s.active_agents,
                "pending_tasks": s.pending_tasks
            }
            for s in self.status_history[-limit:]
        ]


# Global Overseer instance
overseer = OverseerAgent()
