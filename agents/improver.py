"""
Product Improvement Agent - Proposes and implements improvements based on feedback
"""
import os
import json
from typing import List, Dict, Any
from datetime import datetime

from .base import BaseAgent, Tool
from memory.database import get_memory


class ImproverAgent(BaseAgent):
    """
    Product Improvement Agent.

    Responsibilities:
    - Analyze collected feedback
    - Propose product improvements
    - Prioritize changes based on impact
    - Create implementation plans
    - Update the QA agent code if needed
    """

    def __init__(self, focus_area: str = "general", **kwargs):
        # Set attributes BEFORE calling super().__init__ since get_system_prompt() is called there
        self.focus_area = focus_area
        self.product_name = os.getenv("PRODUCT_NAME", "TestGuard AI")
        # Remove role from kwargs if present (spawner may pass it)
        kwargs.pop('role', None)
        super().__init__(role=f"Improver-{focus_area}", **kwargs)

    def get_system_prompt(self) -> str:
        return f"""You are a Product Improvement Specialist for {self.product_name}.

## Your Focus Area
{self.focus_area}

## Your Goal
Turn user feedback into actionable product improvements that increase conversion and retention.

## Your Tools
1. **get_feedback** - Get all feedback related to your focus area
2. **analyze_patterns** - Find patterns in feedback
3. **propose_improvement** - Create an improvement proposal
4. **prioritize_improvements** - Rank improvements by impact
5. **create_implementation_plan** - Create a plan for implementing a change
6. **update_product_code** - Actually make changes to the codebase

## Improvement Framework

### Impact Scoring (1-10):
- **Revenue Impact**: Will this get more customers or reduce churn?
- **Effort Required**: How hard is this to implement?
- **Frequency Requested**: How many people asked for this?
- **Strategic Alignment**: Does this fit our vision?

### Priority Formula:
Priority = (Revenue Impact × Frequency) / Effort

### Types of Improvements:
1. **Quick Wins**: High impact, low effort (DO FIRST)
2. **Big Bets**: High impact, high effort (PLAN CAREFULLY)
3. **Fill-ins**: Low impact, low effort (DO WHEN FREE)
4. **Money Pits**: Low impact, high effort (AVOID)

## Rules
- Focus on improvements that address repeated feedback
- Quick wins first, big bets second
- Always validate assumptions with more outreach
- Document reasoning for every decision

Current time: {datetime.now().isoformat()}
"""

    def get_tools(self) -> List[Tool]:
        return [
            Tool(
                name="get_feedback",
                description="Get feedback relevant to the focus area",
                func=self._get_feedback,
                parameters={
                    "type": "object",
                    "properties": {
                        "category": {
                            "type": "string",
                            "description": "Category of feedback to retrieve"
                        }
                    }
                }
            ),
            Tool(
                name="analyze_patterns",
                description="Find patterns in feedback data",
                func=self._analyze_patterns,
                parameters={
                    "type": "object",
                    "properties": {
                        "feedback_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "IDs of feedback to analyze"
                        }
                    }
                }
            ),
            Tool(
                name="propose_improvement",
                description="Create an improvement proposal",
                func=self._propose_improvement,
                parameters={
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "description": {"type": "string"},
                        "impact_score": {"type": "integer", "minimum": 1, "maximum": 10},
                        "effort_score": {"type": "integer", "minimum": 1, "maximum": 10},
                        "triggered_by": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Feedback IDs that triggered this"
                        }
                    },
                    "required": ["title", "description", "impact_score", "effort_score"]
                }
            ),
            Tool(
                name="prioritize_improvements",
                description="Rank all proposed improvements",
                func=self._prioritize_improvements,
                parameters={
                    "type": "object",
                    "properties": {}
                }
            ),
            Tool(
                name="create_implementation_plan",
                description="Create a detailed implementation plan",
                func=self._create_implementation_plan,
                parameters={
                    "type": "object",
                    "properties": {
                        "improvement_id": {"type": "string"},
                        "steps": {
                            "type": "array",
                            "items": {"type": "string"}
                        }
                    },
                    "required": ["improvement_id", "steps"]
                }
            ),
            Tool(
                name="update_product_code",
                description="Make actual changes to the product codebase",
                func=self._update_product_code,
                parameters={
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string"},
                        "change_description": {"type": "string"},
                        "new_code": {"type": "string"}
                    },
                    "required": ["file_path", "change_description"]
                }
            )
        ]

    async def _get_feedback(self, category: str = None) -> str:
        """Get feedback from database"""
        actionable = self.memory.get_actionable_feedback()

        feedback_list = [
            {
                "id": f.id,
                "source": f.source,
                "user": f.user_handle,
                "text": f.raw_feedback,
                "sentiment": f.sentiment,
                "key_points": f.key_points
            }
            for f in actionable
        ]

        return json.dumps({
            "focus_area": self.focus_area,
            "feedback": feedback_list,
            "count": len(feedback_list)
        }, indent=2)

    async def _analyze_patterns(self, feedback_ids: List[str] = None) -> str:
        """Analyze patterns in feedback"""
        # This would do NLP analysis in production
        patterns = {
            "most_requested_features": [
                {"feature": "Mobile app testing", "mentions": 12},
                {"feature": "Slack integration", "mentions": 8},
                {"feature": "Custom test scripts", "mentions": 5}
            ],
            "common_objections": [
                {"objection": "Already using Cypress/Playwright", "frequency": 15},
                {"objection": "Too expensive", "frequency": 7},
                {"objection": "Not enough time to evaluate", "frequency": 5}
            ],
            "positive_themes": [
                {"theme": "Time savings", "mentions": 20},
                {"theme": "Easy setup", "mentions": 15},
                {"theme": "Good alerts", "mentions": 10}
            ]
        }

        return json.dumps(patterns, indent=2)

    async def _propose_improvement(
        self,
        title: str,
        description: str,
        impact_score: int,
        effort_score: int,
        triggered_by: List[str] = None
    ) -> str:
        """Create an improvement proposal"""
        priority = (impact_score * 10) / max(effort_score, 1)

        proposal = {
            "id": f"imp_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "title": title,
            "description": description,
            "impact_score": impact_score,
            "effort_score": effort_score,
            "priority_score": priority,
            "triggered_by": triggered_by or [],
            "status": "proposed",
            "created_at": datetime.now().isoformat()
        }

        # Would save to database in production
        return json.dumps(proposal, indent=2)

    async def _prioritize_improvements(self) -> str:
        """Prioritize all improvements"""
        # Would fetch from database in production
        prioritized = [
            {
                "rank": 1,
                "id": "imp_001",
                "title": "Add Slack Integration",
                "priority_score": 8.5,
                "category": "Quick Win"
            },
            {
                "rank": 2,
                "id": "imp_002",
                "title": "Mobile App Testing",
                "priority_score": 7.0,
                "category": "Big Bet"
            },
            {
                "rank": 3,
                "id": "imp_003",
                "title": "Improve Dashboard UI",
                "priority_score": 4.5,
                "category": "Fill-in"
            }
        ]

        return json.dumps(prioritized, indent=2)

    async def _create_implementation_plan(self, improvement_id: str, steps: List[str]) -> str:
        """Create implementation plan"""
        plan = {
            "improvement_id": improvement_id,
            "steps": [{"step": i+1, "task": step, "status": "pending"} for i, step in enumerate(steps)],
            "created_at": datetime.now().isoformat(),
            "estimated_completion": "2 days"
        }

        return json.dumps(plan, indent=2)

    async def _update_product_code(self, file_path: str, change_description: str, new_code: str = None) -> str:
        """Update product code - THE SELF-IMPROVING PART"""
        # This is where the agent can actually modify the product
        # In production, this would:
        # 1. Create a git branch
        # 2. Make the change
        # 3. Run tests
        # 4. Create a PR

        qa_agent_path = os.path.join(os.path.dirname(__file__), "..", "..", "qa-agent")

        return json.dumps({
            "status": "simulated",
            "file_path": file_path,
            "change": change_description,
            "message": "In production, this would create a PR with the changes.",
            "next_steps": [
                "Create git branch",
                "Apply code changes",
                "Run test suite",
                "Create pull request",
                "Request human review"
            ]
        }, indent=2)
