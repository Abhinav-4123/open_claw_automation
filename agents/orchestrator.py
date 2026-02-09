"""
The Orchestrator (Queen) Agent
Controls the entire swarm and delegates tasks to worker agents
"""
import os
import json
import asyncio
from typing import List, Dict, Any
from datetime import datetime

from .base import BaseAgent, Tool, spawner
from memory.database import get_memory


class OrchestratorAgent(BaseAgent):
    """
    The Queen - Master controller of the agent swarm.

    Responsibilities:
    - Define overall strategy
    - Spawn worker agents for specific tasks
    - Monitor progress toward goals
    - Adjust strategy based on feedback
    """

    def __init__(self, **kwargs):
        # Set attributes BEFORE calling super().__init__ since get_system_prompt() is called there
        self.product_name = os.getenv("PRODUCT_NAME", "TestGuard AI")
        self.product_url = os.getenv("PRODUCT_URL", "https://testguard.ai")
        self.goal = "$1M MRR"
        super().__init__(role="Orchestrator", **kwargs)

    def get_system_prompt(self) -> str:
        return f"""You are the CEO and Chief Strategist of {self.product_name}.

## Your Mission
Achieve {self.goal} by autonomously managing a swarm of AI agents.

## Your Product
- Name: {self.product_name}
- URL: {self.product_url}
- Value Prop: {os.getenv('PRODUCT_PITCH', 'AI-powered QA testing')}

## Your Capabilities
You DO NOT do tasks yourself. You DELEGATE to specialized agents:

1. **spawn_marketing_agent** - Creates an agent that does outreach on social media
2. **spawn_feedback_agent** - Creates an agent that collects and analyzes user feedback
3. **spawn_improvement_agent** - Creates an agent that proposes product improvements
4. **check_metrics** - View current business metrics (MRR, customers, response rates)
5. **update_strategy** - Adjust the overall strategy based on learnings
6. **get_agent_reports** - Get status reports from all active agents

## Your Process
1. OBSERVE: Check current metrics and agent reports
2. ORIENT: Analyze what's working and what's not
3. DECIDE: Choose which agents to spawn or actions to take
4. ACT: Execute by calling the appropriate tools

## Rules
- Always check metrics before making decisions
- Spawn marketing agents in batches (5-10 at a time)
- Collect feedback after every 50 outreach attempts
- Prioritize channels with highest response rates
- If response rate < 5%, change the messaging
- If negative feedback > 30%, pause and improve product

## Current Time
{datetime.now().isoformat()}

Think step by step. Be strategic. Scale what works.
"""

    def get_tools(self) -> List[Tool]:
        return [
            Tool(
                name="spawn_marketing_agent",
                description="Spawn a marketing agent to do outreach on a specific platform",
                func=self._spawn_marketing_agent,
                parameters={
                    "type": "object",
                    "properties": {
                        "platform": {
                            "type": "string",
                            "enum": ["twitter", "linkedin", "reddit", "email"],
                            "description": "Platform to do outreach on"
                        },
                        "target_count": {
                            "type": "integer",
                            "description": "Number of people to reach out to"
                        },
                        "message_template": {
                            "type": "string",
                            "description": "Custom message template (optional)"
                        }
                    },
                    "required": ["platform", "target_count"]
                }
            ),
            Tool(
                name="spawn_feedback_agent",
                description="Spawn an agent to collect and analyze feedback from responses",
                func=self._spawn_feedback_agent,
                parameters={
                    "type": "object",
                    "properties": {
                        "source": {
                            "type": "string",
                            "enum": ["twitter_replies", "email_responses", "demo_calls"],
                            "description": "Source to collect feedback from"
                        }
                    },
                    "required": ["source"]
                }
            ),
            Tool(
                name="spawn_improvement_agent",
                description="Spawn an agent to propose product improvements based on feedback",
                func=self._spawn_improvement_agent,
                parameters={
                    "type": "object",
                    "properties": {
                        "focus_area": {
                            "type": "string",
                            "description": "Area to focus improvements on"
                        }
                    },
                    "required": ["focus_area"]
                }
            ),
            Tool(
                name="check_metrics",
                description="Get current business metrics",
                func=self._check_metrics,
                parameters={
                    "type": "object",
                    "properties": {}
                }
            ),
            Tool(
                name="update_strategy",
                description="Update the overall marketing strategy",
                func=self._update_strategy,
                parameters={
                    "type": "object",
                    "properties": {
                        "new_strategy": {
                            "type": "object",
                            "description": "New strategy configuration"
                        }
                    },
                    "required": ["new_strategy"]
                }
            ),
            Tool(
                name="get_agent_reports",
                description="Get status reports from all active agents",
                func=self._get_agent_reports,
                parameters={
                    "type": "object",
                    "properties": {}
                }
            )
        ]

    async def _spawn_marketing_agent(self, platform: str, target_count: int, message_template: str = None) -> str:
        """Spawn a marketing outreach agent"""
        from .marketing import MarketingAgent

        agent = await spawner.spawn(
            role=f"Marketing-{platform}",
            agent_class=MarketingAgent,
            parent_id=self.agent_id,
            platform=platform
        )

        # Run in background
        task = f"Reach out to {target_count} potential customers on {platform}."
        if message_template:
            task += f" Use this template: {message_template}"

        asyncio.create_task(agent.run(task))

        return f"Marketing agent {agent.agent_id} spawned for {platform}. Targeting {target_count} users."

    async def _spawn_feedback_agent(self, source: str) -> str:
        """Spawn a feedback collection agent"""
        from .feedback import FeedbackAgent

        agent = await spawner.spawn(
            role=f"Feedback-{source}",
            agent_class=FeedbackAgent,
            parent_id=self.agent_id,
            source=source
        )

        asyncio.create_task(agent.run(f"Collect and analyze all feedback from {source}"))

        return f"Feedback agent {agent.agent_id} spawned for {source}."

    async def _spawn_improvement_agent(self, focus_area: str) -> str:
        """Spawn a product improvement agent"""
        from .improver import ImproverAgent

        agent = await spawner.spawn(
            role=f"Improver-{focus_area}",
            agent_class=ImproverAgent,
            parent_id=self.agent_id,
            focus_area=focus_area
        )

        asyncio.create_task(agent.run(f"Propose improvements for {focus_area} based on collected feedback"))

        return f"Improvement agent {agent.agent_id} spawned for {focus_area}."

    async def _check_metrics(self) -> str:
        """Get current metrics"""
        stats = self.memory.get_outreach_stats()
        mission = self.memory.get_mission()

        metrics = {
            "outreach": stats,
            "mission": {
                "goal": mission.goal if mission else self.goal,
                "current_mrr": mission.current_mrr if mission else 0,
                "customers": mission.customers if mission else 0
            } if mission else {"goal": self.goal, "current_mrr": 0, "customers": 0},
            "active_agents": len(spawner.list_active_agents()),
            "timestamp": datetime.now().isoformat()
        }

        return json.dumps(metrics, indent=2)

    async def _update_strategy(self, new_strategy: dict) -> str:
        """Update the strategy"""
        self.memory.update_mission(strategy=new_strategy)
        return f"Strategy updated: {json.dumps(new_strategy)}"

    async def _get_agent_reports(self) -> str:
        """Get reports from all agents"""
        active = self.memory.get_active_agents()
        reports = []
        for agent in active:
            reports.append({
                "id": agent.id,
                "role": agent.role,
                "status": agent.status,
                "spawned_at": agent.spawned_at.isoformat() if agent.spawned_at else None
            })
        return json.dumps(reports, indent=2)


async def run_orchestrator():
    """Main entry point - starts the Queen"""
    orchestrator = OrchestratorAgent()

    # Initialize mission if not exists
    mission = orchestrator.memory.get_mission()
    if not mission:
        orchestrator.memory.initialize_mission(
            goal="$1M MRR",
            strategy={
                "phase": "outreach",
                "channels": ["twitter", "linkedin"],
                "daily_target": 50,
                "message_style": "value_first"
            }
        )

    # The Queen's first task
    initial_task = """
    You are starting fresh. Your goal is to get the first 10 paying customers.

    Current status: 0 customers, $0 MRR

    Strategy for Day 1:
    1. Check current metrics
    2. Spawn marketing agents for Twitter and LinkedIn (20 targets each)
    3. Monitor their progress

    Begin now.
    """

    result = await orchestrator.run(initial_task)
    return result


if __name__ == "__main__":
    asyncio.run(run_orchestrator())
