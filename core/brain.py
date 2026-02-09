"""
THE BRAIN - Central Intelligence for Autonomous Operation
This is the core decision-making engine that runs 24/7

Architecture:
- Self-healing: Restarts failed agents
- Self-optimizing: Adjusts strategy based on results
- Self-scaling: Spawns/retires agents based on workload
- Self-documenting: Logs every decision for transparency
"""
import os
import asyncio
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import google.generativeai as genai

# Configure Gemini
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))


class DecisionType(Enum):
    SPAWN_AGENT = "spawn_agent"
    RETIRE_AGENT = "retire_agent"
    CHANGE_STRATEGY = "change_strategy"
    SCALE_UP = "scale_up"
    SCALE_DOWN = "scale_down"
    PAUSE_OUTREACH = "pause_outreach"
    RESUME_OUTREACH = "resume_outreach"
    REQUEST_APPROVAL = "request_approval"
    IMPROVE_PRODUCT = "improve_product"
    SEND_REPORT = "send_report"


@dataclass
class Decision:
    id: str
    timestamp: datetime
    type: DecisionType
    reasoning: str
    data: Dict[str, Any]
    outcome: Optional[str] = None
    success: Optional[bool] = None


@dataclass
class AgentState:
    id: str
    role: str
    status: str  # running, idle, failed, retired
    spawned_at: datetime
    last_activity: datetime
    tasks_completed: int
    success_rate: float
    current_task: Optional[str] = None


@dataclass
class SystemState:
    timestamp: datetime
    total_outreach: int
    responses: int
    conversions: int
    active_agents: int
    mrr: float
    customers: int
    response_rate: float
    conversion_rate: float
    health_score: float  # 0-100


class TheBrain:
    """
    The autonomous decision-making engine.
    Thinks, decides, acts, learns, repeats.
    """

    def __init__(self):
        self.model = genai.GenerativeModel('gemini-2.0-flash')
        self.decisions: List[Decision] = []
        self.agents: Dict[str, AgentState] = {}
        self.state_history: List[SystemState] = []
        self.running = False

        # Configuration
        self.min_agents = 2
        self.max_agents = 20
        self.target_response_rate = 0.10  # 10%
        self.target_conversion_rate = 0.03  # 3%
        self.health_threshold = 50  # Below this, take corrective action

        # Learning parameters
        self.successful_strategies: List[Dict] = []
        self.failed_strategies: List[Dict] = []

    async def think(self, context: Dict[str, Any]) -> Decision:
        """
        Use AI to analyze situation and decide next action.
        This is the core intelligence loop.
        """
        prompt = f"""You are the autonomous CEO brain of an AI company.

CURRENT STATE:
{json.dumps(context, indent=2, default=str)}

RECENT DECISIONS:
{json.dumps([asdict(d) for d in self.decisions[-10:]], indent=2, default=str)}

GOALS:
- Primary: Reach $1M MRR
- Secondary: Maintain >10% response rate
- Tertiary: Convert >3% of responses to customers

AVAILABLE ACTIONS:
1. SPAWN_AGENT - Create a new marketing/feedback/improvement agent
2. RETIRE_AGENT - Stop an underperforming agent
3. CHANGE_STRATEGY - Modify outreach approach
4. SCALE_UP - Increase daily targets
5. SCALE_DOWN - Decrease daily targets (if burning money)
6. PAUSE_OUTREACH - Stop if response rate critically low
7. IMPROVE_PRODUCT - Trigger product improvement cycle
8. SEND_REPORT - Send status update to owner

RULES:
- Never request payment without owner approval
- If response rate < 5%, change messaging before scaling
- If health score < 50, diagnose and fix issues
- Always explain your reasoning

Analyze the situation and decide the SINGLE best action to take right now.

Respond in JSON format:
{{
    "action": "ACTION_NAME",
    "reasoning": "Why this action",
    "parameters": {{}}
}}
"""

        response = self.model.generate_content(prompt)
        result = self._parse_ai_response(response.text)

        decision = Decision(
            id=str(uuid.uuid4())[:8],
            timestamp=datetime.now(),
            type=DecisionType[result["action"]],
            reasoning=result["reasoning"],
            data=result.get("parameters", {})
        )

        self.decisions.append(decision)
        return decision

    def _parse_ai_response(self, text: str) -> Dict:
        """Parse AI response, handling various formats"""
        try:
            # Try to extract JSON from response
            import re
            json_match = re.search(r'\{[\s\S]*\}', text)
            if json_match:
                return json.loads(json_match.group())
        except:
            pass

        # Default safe action
        return {
            "action": "SEND_REPORT",
            "reasoning": "Could not parse AI response, sending status report",
            "parameters": {}
        }

    async def execute_decision(self, decision: Decision) -> bool:
        """Execute a decision and record outcome"""
        try:
            if decision.type == DecisionType.SPAWN_AGENT:
                await self._spawn_agent(decision.data)
            elif decision.type == DecisionType.RETIRE_AGENT:
                await self._retire_agent(decision.data)
            elif decision.type == DecisionType.CHANGE_STRATEGY:
                await self._change_strategy(decision.data)
            elif decision.type == DecisionType.SCALE_UP:
                await self._scale_up(decision.data)
            elif decision.type == DecisionType.SCALE_DOWN:
                await self._scale_down(decision.data)
            elif decision.type == DecisionType.IMPROVE_PRODUCT:
                await self._trigger_improvement(decision.data)
            elif decision.type == DecisionType.SEND_REPORT:
                await self._send_report(decision.data)

            decision.success = True
            decision.outcome = "Executed successfully"
            return True

        except Exception as e:
            decision.success = False
            decision.outcome = str(e)
            return False

    async def _spawn_agent(self, params: Dict):
        """Spawn a new agent"""
        from agents import MarketingAgent, FeedbackAgent, ImproverAgent, spawner

        role = params.get("role", "marketing")
        platform = params.get("platform", "twitter")

        if role == "marketing":
            agent = await spawner.spawn(
                role=f"Marketing-{platform}",
                agent_class=MarketingAgent,
                platform=platform
            )
        elif role == "feedback":
            agent = await spawner.spawn(
                role="Feedback",
                agent_class=FeedbackAgent
            )
        elif role == "improvement":
            agent = await spawner.spawn(
                role="Improver",
                agent_class=ImproverAgent
            )

        self.agents[agent.agent_id] = AgentState(
            id=agent.agent_id,
            role=role,
            status="running",
            spawned_at=datetime.now(),
            last_activity=datetime.now(),
            tasks_completed=0,
            success_rate=0.0
        )

    async def _retire_agent(self, params: Dict):
        """Retire an underperforming agent"""
        agent_id = params.get("agent_id")
        if agent_id in self.agents:
            self.agents[agent_id].status = "retired"

    async def _change_strategy(self, params: Dict):
        """Change marketing strategy"""
        # Store for learning
        current_strategy = params.get("current", {})
        new_strategy = params.get("new", {})

        if self._get_current_response_rate() < 0.05:
            self.failed_strategies.append(current_strategy)
        else:
            self.successful_strategies.append(current_strategy)

    async def _scale_up(self, params: Dict):
        """Increase outreach capacity"""
        active_count = len([a for a in self.agents.values() if a.status == "running"])
        if active_count < self.max_agents:
            await self._spawn_agent({"role": "marketing", "platform": "twitter"})

    async def _scale_down(self, params: Dict):
        """Decrease outreach capacity"""
        # Find lowest performing agent and retire
        running_agents = [a for a in self.agents.values() if a.status == "running"]
        if running_agents and len(running_agents) > self.min_agents:
            worst = min(running_agents, key=lambda a: a.success_rate)
            await self._retire_agent({"agent_id": worst.id})

    async def _trigger_improvement(self, params: Dict):
        """Trigger product improvement cycle"""
        from agents import ImproverAgent, spawner

        agent = await spawner.spawn(
            role="Improver-Triggered",
            agent_class=ImproverAgent,
            focus_area=params.get("focus", "general")
        )

        await agent.run("Analyze feedback and propose top 3 improvements")

    async def _send_report(self, params: Dict):
        """Send status report to owner"""
        from tools.notifications import notifications

        state = self._calculate_system_state()
        notifications.notify_daily({
            "outreach": {
                "total_sent": state.total_outreach,
                "responses": state.responses,
                "response_rate": state.response_rate,
                "conversions": state.conversions
            },
            "mission": {
                "goal": "$1M MRR",
                "current_mrr": state.mrr,
                "customers": state.customers
            },
            "active_agents": state.active_agents
        })

    def _calculate_system_state(self) -> SystemState:
        """Calculate current system state"""
        from memory.database import get_memory
        memory = get_memory()

        stats = memory.get_outreach_stats()
        mission = memory.get_mission()

        total = stats.get("total_sent", 0)
        responses = stats.get("responses", 0)
        conversions = stats.get("conversions", 0)

        response_rate = responses / total if total > 0 else 0
        conversion_rate = conversions / total if total > 0 else 0

        # Calculate health score
        health = 100
        if response_rate < 0.05:
            health -= 30
        if conversion_rate < 0.01:
            health -= 20
        if len([a for a in self.agents.values() if a.status == "failed"]) > 2:
            health -= 25

        state = SystemState(
            timestamp=datetime.now(),
            total_outreach=total,
            responses=responses,
            conversions=conversions,
            active_agents=len([a for a in self.agents.values() if a.status == "running"]),
            mrr=mission.current_mrr if mission else 0,
            customers=mission.customers if mission else 0,
            response_rate=response_rate,
            conversion_rate=conversion_rate,
            health_score=max(0, health)
        )

        self.state_history.append(state)
        return state

    def _get_current_response_rate(self) -> float:
        if self.state_history:
            return self.state_history[-1].response_rate
        return 0.0

    def get_status_report(self) -> Dict[str, Any]:
        """Get current status for external queries"""
        state = self._calculate_system_state()

        return {
            "status": "running" if self.running else "stopped",
            "uptime": str(datetime.now() - self.state_history[0].timestamp) if self.state_history else "0",
            "health_score": state.health_score,
            "metrics": {
                "total_outreach": state.total_outreach,
                "responses": state.responses,
                "response_rate": f"{state.response_rate*100:.1f}%",
                "conversions": state.conversions,
                "mrr": f"${state.mrr:,.0f}",
                "customers": state.customers
            },
            "agents": {
                "active": len([a for a in self.agents.values() if a.status == "running"]),
                "total_spawned": len(self.agents),
                "failed": len([a for a in self.agents.values() if a.status == "failed"])
            },
            "recent_decisions": [
                {
                    "id": d.id,
                    "time": d.timestamp.isoformat(),
                    "action": d.type.value,
                    "reasoning": d.reasoning[:100],
                    "success": d.success
                }
                for d in self.decisions[-5:]
            ],
            "last_updated": datetime.now().isoformat()
        }


# Global brain instance
brain = TheBrain()
