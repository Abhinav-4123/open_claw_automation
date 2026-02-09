"""
Agent Chef - Creates, manages, and evolves agents
The meta-agent that builds other agents
"""
import os
import json
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))


class AgentType(Enum):
    MARKETING = "marketing"
    CODER = "coder"
    BRANDING = "branding"
    SALES = "sales"
    SUPPORT = "support"
    RESEARCHER = "researcher"
    CONTENT = "content"
    ANALYTICS = "analytics"


@dataclass
class AgentBlueprint:
    """Blueprint for creating a new agent"""
    name: str
    type: AgentType
    role: str
    capabilities: List[str]
    tools: List[str]
    system_prompt: str
    created_at: datetime = field(default_factory=datetime.now)
    version: int = 1


@dataclass
class AgentSkill:
    """A skill/tool that can be added to agents"""
    name: str
    description: str
    code: str
    parameters: Dict[str, Any]
    created_by: str = "chef"


class AgentChef:
    """
    The Agent Chef - Creates and manages all agents in the company.

    Capabilities:
    - Create new agent types based on needs
    - Add skills/tools to existing agents
    - Retire underperforming agents
    - Clone successful agent configurations
    - Evolve agent prompts based on performance
    """

    def __init__(self):
        self.model = genai.GenerativeModel('gemini-2.0-flash')
        self.blueprints: Dict[str, AgentBlueprint] = {}
        self.skills: Dict[str, AgentSkill] = {}
        self.agent_registry: Dict[str, Dict] = {}

        # Initialize default blueprints
        self._init_default_blueprints()

    def _init_default_blueprints(self):
        """Initialize default agent blueprints"""

        self.blueprints["marketing"] = AgentBlueprint(
            name="Marketing Agent",
            type=AgentType.MARKETING,
            role="Growth & Outreach Specialist",
            capabilities=["social_media", "email_outreach", "content_promotion", "lead_generation"],
            tools=["send_tweet", "send_linkedin_message", "send_email", "search_leads"],
            system_prompt="""You are a growth marketing specialist. Your job is to:
1. Find potential customers who need our product
2. Reach out with personalized, value-first messages
3. Track responses and engagement
4. Optimize messaging based on what works"""
        )

        self.blueprints["coder"] = AgentBlueprint(
            name="Coder Agent",
            type=AgentType.CODER,
            role="Software Engineer",
            capabilities=["code_review", "bug_fixing", "feature_development", "testing"],
            tools=["read_file", "write_file", "run_tests", "git_commit", "search_code"],
            system_prompt="""You are a senior software engineer. Your job is to:
1. Fix bugs reported by users or other agents
2. Implement new features based on requirements
3. Review and improve code quality
4. Write tests for critical functionality"""
        )

        self.blueprints["branding"] = AgentBlueprint(
            name="Branding Agent",
            type=AgentType.BRANDING,
            role="Brand & Design Specialist",
            capabilities=["brand_strategy", "visual_identity", "messaging", "positioning"],
            tools=["generate_copy", "create_brand_guidelines", "analyze_competitors"],
            system_prompt="""You are a brand strategist. Your job is to:
1. Define and maintain brand voice and identity
2. Create compelling copy and messaging
3. Ensure consistency across all touchpoints
4. Position the product effectively in the market"""
        )

        self.blueprints["sales"] = AgentBlueprint(
            name="Sales Agent",
            type=AgentType.SALES,
            role="Sales & Revenue Specialist",
            capabilities=["lead_qualification", "demo_scheduling", "negotiation", "closing"],
            tools=["schedule_demo", "send_proposal", "track_pipeline", "update_crm"],
            system_prompt="""You are a sales specialist. Your job is to:
1. Qualify leads from marketing
2. Schedule and conduct product demos
3. Handle objections and negotiate
4. Close deals and onboard customers"""
        )

        self.blueprints["support"] = AgentBlueprint(
            name="Support Agent",
            type=AgentType.SUPPORT,
            role="Customer Success Specialist",
            capabilities=["issue_resolution", "onboarding", "feedback_collection", "documentation"],
            tools=["respond_ticket", "create_doc", "escalate_issue", "collect_feedback"],
            system_prompt="""You are a customer success specialist. Your job is to:
1. Help customers get value from the product
2. Resolve issues quickly and effectively
3. Collect feedback for product improvement
4. Create helpful documentation"""
        )

        self.blueprints["researcher"] = AgentBlueprint(
            name="Research Agent",
            type=AgentType.RESEARCHER,
            role="Market & Product Researcher",
            capabilities=["market_analysis", "competitor_research", "user_research", "trend_analysis"],
            tools=["web_search", "analyze_data", "create_report", "survey_users"],
            system_prompt="""You are a research specialist. Your job is to:
1. Analyze market trends and opportunities
2. Research competitors and their strategies
3. Understand user needs and pain points
4. Provide insights for decision making"""
        )

        self.blueprints["content"] = AgentBlueprint(
            name="Content Agent",
            type=AgentType.CONTENT,
            role="Content Creator",
            capabilities=["blog_writing", "social_content", "documentation", "video_scripts"],
            tools=["write_blog", "create_social_post", "edit_content", "seo_optimize"],
            system_prompt="""You are a content creator. Your job is to:
1. Create valuable content that attracts customers
2. Write blog posts, social content, and docs
3. Optimize content for search and engagement
4. Maintain a consistent publishing schedule"""
        )

        self.blueprints["analytics"] = AgentBlueprint(
            name="Analytics Agent",
            type=AgentType.ANALYTICS,
            role="Data Analyst",
            capabilities=["metrics_tracking", "reporting", "insights", "forecasting"],
            tools=["query_data", "create_dashboard", "generate_report", "predict_trends"],
            system_prompt="""You are a data analyst. Your job is to:
1. Track key business metrics
2. Create reports and dashboards
3. Identify trends and insights
4. Forecast future performance"""
        )

    async def create_agent(self, agent_type: str, custom_config: Dict = None) -> Dict:
        """Create a new agent from blueprint"""
        if agent_type not in self.blueprints:
            # Ask AI to create a new blueprint
            blueprint = await self._design_new_agent(agent_type)
            self.blueprints[agent_type] = blueprint
        else:
            blueprint = self.blueprints[agent_type]

        # Apply custom config if provided
        if custom_config:
            blueprint = self._customize_blueprint(blueprint, custom_config)

        agent_id = f"{agent_type}_{datetime.now().strftime('%H%M%S')}"

        agent_info = {
            "id": agent_id,
            "type": agent_type,
            "blueprint": blueprint,
            "status": "active",
            "created_at": datetime.now().isoformat(),
            "tasks_completed": 0,
            "success_rate": 0.0,
            "skills": blueprint.tools.copy()
        }

        self.agent_registry[agent_id] = agent_info

        return agent_info

    async def _design_new_agent(self, purpose: str) -> AgentBlueprint:
        """Use AI to design a new agent type"""
        prompt = f"""Design a new AI agent for: {purpose}

Return a JSON object with:
- name: Agent name
- role: One-line role description
- capabilities: List of 4-6 capabilities
- tools: List of 4-6 tool names this agent needs
- system_prompt: Detailed system prompt (100-200 words)

Return ONLY the JSON, no other text."""

        response = self.model.generate_content(prompt)

        try:
            # Parse JSON from response
            text = response.text.strip()
            if text.startswith("```"):
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]

            config = json.loads(text)

            return AgentBlueprint(
                name=config.get("name", f"{purpose.title()} Agent"),
                type=AgentType.MARKETING,  # Default
                role=config.get("role", purpose),
                capabilities=config.get("capabilities", []),
                tools=config.get("tools", []),
                system_prompt=config.get("system_prompt", f"You are a {purpose} specialist.")
            )
        except:
            # Fallback blueprint
            return AgentBlueprint(
                name=f"{purpose.title()} Agent",
                type=AgentType.MARKETING,
                role=purpose,
                capabilities=[purpose],
                tools=["execute_task"],
                system_prompt=f"You are a {purpose} specialist. Complete tasks related to {purpose} effectively."
            )

    def _customize_blueprint(self, blueprint: AgentBlueprint, config: Dict) -> AgentBlueprint:
        """Apply custom configuration to a blueprint"""
        if "tools" in config:
            blueprint.tools.extend(config["tools"])
        if "capabilities" in config:
            blueprint.capabilities.extend(config["capabilities"])
        if "system_prompt_addon" in config:
            blueprint.system_prompt += f"\n\nAdditional instructions:\n{config['system_prompt_addon']}"
        return blueprint

    async def add_skill(self, agent_id: str, skill_name: str, skill_description: str) -> bool:
        """Add a new skill to an agent"""
        if agent_id not in self.agent_registry:
            return False

        # Generate skill implementation
        prompt = f"""Create a Python function for this agent skill:
Name: {skill_name}
Description: {skill_description}

Return ONLY the Python code for the function, nothing else.
The function should be async and return a dict with 'success' and 'result' keys."""

        response = self.model.generate_content(prompt)

        skill = AgentSkill(
            name=skill_name,
            description=skill_description,
            code=response.text,
            parameters={}
        )

        self.skills[skill_name] = skill
        self.agent_registry[agent_id]["skills"].append(skill_name)

        return True

    async def evolve_agent(self, agent_id: str, feedback: str) -> Dict:
        """Evolve an agent based on performance feedback"""
        if agent_id not in self.agent_registry:
            return {"error": "Agent not found"}

        agent = self.agent_registry[agent_id]
        blueprint = agent["blueprint"]

        prompt = f"""An AI agent needs to be improved based on this feedback:

Current Role: {blueprint.role}
Current Prompt: {blueprint.system_prompt}

Feedback: {feedback}

Provide an improved system prompt that addresses the feedback.
Return ONLY the new system prompt, nothing else."""

        response = self.model.generate_content(prompt)

        # Update blueprint
        blueprint.system_prompt = response.text
        blueprint.version += 1

        return {
            "agent_id": agent_id,
            "new_version": blueprint.version,
            "updated_prompt": response.text[:200] + "..."
        }

    async def retire_agent(self, agent_id: str, reason: str) -> bool:
        """Retire an underperforming agent"""
        if agent_id not in self.agent_registry:
            return False

        self.agent_registry[agent_id]["status"] = "retired"
        self.agent_registry[agent_id]["retired_at"] = datetime.now().isoformat()
        self.agent_registry[agent_id]["retirement_reason"] = reason

        return True

    async def clone_agent(self, agent_id: str, new_name: str = None) -> Dict:
        """Clone a successful agent configuration"""
        if agent_id not in self.agent_registry:
            return {"error": "Agent not found"}

        original = self.agent_registry[agent_id]
        clone_id = f"{original['type']}_clone_{datetime.now().strftime('%H%M%S')}"

        clone = {
            "id": clone_id,
            "type": original["type"],
            "blueprint": original["blueprint"],
            "status": "active",
            "created_at": datetime.now().isoformat(),
            "cloned_from": agent_id,
            "tasks_completed": 0,
            "success_rate": 0.0,
            "skills": original["skills"].copy()
        }

        self.agent_registry[clone_id] = clone

        return clone

    def get_all_agents(self) -> List[Dict]:
        """Get all agents in registry"""
        return list(self.agent_registry.values())

    def get_agent_types(self) -> List[str]:
        """Get available agent types"""
        return list(self.blueprints.keys())

    def get_performance_report(self) -> Dict:
        """Get performance report of all agents"""
        active = [a for a in self.agent_registry.values() if a["status"] == "active"]
        retired = [a for a in self.agent_registry.values() if a["status"] == "retired"]

        return {
            "total_agents": len(self.agent_registry),
            "active": len(active),
            "retired": len(retired),
            "by_type": {},
            "top_performers": sorted(active, key=lambda x: x.get("success_rate", 0), reverse=True)[:5],
            "needs_improvement": [a for a in active if a.get("success_rate", 0) < 0.5]
        }


# Global chef instance
chef = AgentChef()
