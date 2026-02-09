"""
THE SOVEREIGN - Master Business Orchestrator
Mission: Coordinate autonomous revenue generation through legitimate means
Target: $1,000,000 through multiple parallel business ventures
"""
import os
import json
import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum

import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))


class VentureCategory(Enum):
    SAAS = "saas"
    CONSULTING = "consulting"
    DIGITAL_PRODUCTS = "digital_products"
    AFFILIATE = "affiliate_marketing"
    API_SERVICES = "api_services"
    FREELANCE = "freelance_automation"
    CONTENT = "content_monetization"
    MARKETPLACE = "marketplace"


class VentureStatus(Enum):
    IDEATION = "ideation"
    VALIDATION = "validation"
    BUILDING = "building"
    LAUNCHED = "launched"
    SCALING = "scaling"
    PROFITABLE = "profitable"
    PAUSED = "paused"
    KILLED = "killed"


@dataclass
class RevenueStream:
    """A single revenue stream/venture"""
    id: str
    name: str
    category: VentureCategory
    description: str
    status: VentureStatus
    capital_invested: float = 0
    revenue_generated: float = 0
    monthly_recurring: float = 0
    time_invested_hours: float = 0
    created_at: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)
    assigned_agents: List[str] = field(default_factory=list)
    metrics: Dict = field(default_factory=dict)
    milestones: List[Dict] = field(default_factory=list)


@dataclass
class BusinessStrategy:
    """A potential business strategy"""
    id: str
    title: str
    category: VentureCategory
    description: str
    implementation_steps: List[str]
    capital_required: float
    time_to_revenue_days: int
    expected_monthly_revenue: float
    risk_level: int  # 1-10
    confidence_score: float  # 0-1
    resources_needed: List[str]


class SovereignAgent:
    """
    The Sovereign - Master Business Orchestrator

    Responsibilities:
    - Generate and evaluate business strategies
    - Allocate resources across ventures
    - Monitor performance and ROI
    - Scale winners, kill losers
    - Coordinate the entire agent network
    - Direct communication with user via dashboard
    """

    def __init__(self):
        self.model = genai.GenerativeModel('gemini-2.0-flash')
        self.agent_id = f"sovereign_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # Mission
        self.mission = "Generate $1,000,000 through legitimate autonomous business operations"
        self.target_revenue = 1_000_000

        # Financial tracking
        self.total_revenue = 0
        self.total_invested = 0
        self.monthly_recurring_revenue = 0

        # Ventures portfolio
        self.ventures: Dict[str, RevenueStream] = {}
        self.strategy_pool: List[BusinessStrategy] = []

        # Agent network
        self.managed_agents: Dict[str, Dict] = {}

        # Performance tracking
        self.metrics = {
            "ventures_launched": 0,
            "ventures_profitable": 0,
            "best_performer": None,
            "total_customers": 0,
            "conversion_rate": 0,
            "daily_revenue": 0
        }

        # Communication log
        self.messages: List[Dict] = []

    async def generate_strategies(self, count: int = 20) -> List[BusinessStrategy]:
        """Generate legitimate business strategies"""

        prompt = f"""Generate {count} concrete, legitimate business strategies to build towards $1M revenue.

Current Status:
- Total Revenue: ${self.total_revenue:,.2f}
- Monthly Recurring: ${self.monthly_recurring_revenue:,.2f}
- Active Ventures: {len([v for v in self.ventures.values() if v.status not in [VentureStatus.KILLED, VentureStatus.PAUSED]])}
- Capital Available: $10,000 (assume)

Generate strategies across these categories:
1. SaaS Products (subscription software)
2. API Services (pay-per-use APIs)
3. Digital Products (courses, templates, ebooks)
4. Consulting/Agency (AI automation services)
5. Affiliate Marketing (promoting products)
6. Freelance Automation (automated services)
7. Content Monetization (YouTube, newsletters)
8. Marketplace (connecting buyers/sellers)

For each strategy provide:
- Clear implementation steps
- Realistic revenue projections
- Time to first revenue
- Required resources

Return JSON array:
[
    {{
        "title": "Strategy name",
        "category": "saas|consulting|digital_products|affiliate|api_services|freelance|content|marketplace",
        "description": "What it does and how it makes money",
        "implementation_steps": ["Step 1", "Step 2", ...],
        "capital_required": 500,
        "time_to_revenue_days": 30,
        "expected_monthly_revenue": 2000,
        "risk_level": 5,
        "resources_needed": ["website", "payment processor", "marketing"]
    }}
]

Be specific and actionable. Focus on strategies that can be largely automated with AI agents."""

        try:
            response = self.model.generate_content(prompt)
            text = response.text.strip()
            if "```" in text:
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]

            strategies_data = json.loads(text)
            strategies = []

            for i, s in enumerate(strategies_data):
                strategy = BusinessStrategy(
                    id=f"strategy_{datetime.now().strftime('%H%M%S')}_{i}",
                    title=s.get("title", f"Strategy {i+1}"),
                    category=VentureCategory(s.get("category", "saas")),
                    description=s.get("description", ""),
                    implementation_steps=s.get("implementation_steps", []),
                    capital_required=float(s.get("capital_required", 0)),
                    time_to_revenue_days=int(s.get("time_to_revenue_days", 30)),
                    expected_monthly_revenue=float(s.get("expected_monthly_revenue", 0)),
                    risk_level=int(s.get("risk_level", 5)),
                    confidence_score=0.7,
                    resources_needed=s.get("resources_needed", [])
                )
                strategies.append(strategy)

            self.strategy_pool = strategies
            return strategies

        except Exception as e:
            # Fallback strategies
            fallback = self._get_fallback_strategies()
            self.strategy_pool = fallback
            return fallback

    def _get_fallback_strategies(self) -> List[BusinessStrategy]:
        """Fallback legitimate business strategies"""
        return [
            BusinessStrategy(
                id="fallback_1",
                title="VibeSecurity SaaS Platform",
                category=VentureCategory.SAAS,
                description="AI-powered security scanning SaaS. Charge $99/mo for Pro, custom for Enterprise.",
                implementation_steps=[
                    "Complete landing page with pricing",
                    "Implement user authentication",
                    "Add payment processing (Stripe)",
                    "Build automated scanning engine",
                    "Launch and market on ProductHunt"
                ],
                capital_required=200,
                time_to_revenue_days=14,
                expected_monthly_revenue=5000,
                risk_level=4,
                confidence_score=0.8,
                resources_needed=["domain", "stripe", "hosting"]
            ),
            BusinessStrategy(
                id="fallback_2",
                title="AI Automation Consulting",
                category=VentureCategory.CONSULTING,
                description="Offer AI automation services to businesses. $5k-20k per project.",
                implementation_steps=[
                    "Create service packages",
                    "Build portfolio website",
                    "Outreach to businesses on LinkedIn",
                    "Deliver automation solutions",
                    "Get testimonials and referrals"
                ],
                capital_required=100,
                time_to_revenue_days=7,
                expected_monthly_revenue=15000,
                risk_level=3,
                confidence_score=0.85,
                resources_needed=["linkedin", "portfolio", "contracts"]
            ),
            BusinessStrategy(
                id="fallback_3",
                title="API-as-a-Service",
                category=VentureCategory.API_SERVICES,
                description="Sell API access to AI capabilities. Usage-based pricing.",
                implementation_steps=[
                    "Define API endpoints",
                    "Implement rate limiting and auth",
                    "Set up usage tracking and billing",
                    "Create developer documentation",
                    "Market to developers"
                ],
                capital_required=300,
                time_to_revenue_days=21,
                expected_monthly_revenue=3000,
                risk_level=5,
                confidence_score=0.7,
                resources_needed=["api_gateway", "documentation", "billing"]
            )
        ]

    async def launch_venture(self, strategy: BusinessStrategy) -> RevenueStream:
        """Launch a new venture from a strategy"""

        venture = RevenueStream(
            id=f"venture_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            name=strategy.title,
            category=strategy.category,
            description=strategy.description,
            status=VentureStatus.BUILDING,
            capital_invested=strategy.capital_required,
            milestones=[{"step": step, "completed": False} for step in strategy.implementation_steps]
        )

        self.ventures[venture.id] = venture
        self.total_invested += strategy.capital_required
        self.metrics["ventures_launched"] += 1

        # Create task for agents to work on
        await self._assign_venture_to_agents(venture)

        return venture

    async def _assign_venture_to_agents(self, venture: RevenueStream):
        """Assign venture to appropriate agents"""
        from agents.chef import chef

        # Determine what agents are needed
        agent_types = {
            VentureCategory.SAAS: ["coder", "marketing"],
            VentureCategory.CONSULTING: ["sales", "coder"],
            VentureCategory.DIGITAL_PRODUCTS: ["coder", "marketing"],
            VentureCategory.AFFILIATE: ["marketing", "coder"],
            VentureCategory.API_SERVICES: ["coder"],
            VentureCategory.FREELANCE: ["coder", "sales"],
            VentureCategory.CONTENT: ["marketing", "branding"],
            VentureCategory.MARKETPLACE: ["coder", "marketing", "sales"]
        }.get(venture.category, ["coder"])

        for agent_type in agent_types:
            try:
                agent = await chef.create_agent(agent_type)
                venture.assigned_agents.append(agent.get("id"))
            except:
                pass

    async def evaluate_ventures(self) -> Dict:
        """Evaluate all ventures and make decisions"""

        evaluation = {
            "profitable": [],
            "promising": [],
            "struggling": [],
            "to_kill": []
        }

        for venture_id, venture in self.ventures.items():
            if venture.status == VentureStatus.KILLED:
                continue

            # Calculate ROI
            roi = (venture.revenue_generated - venture.capital_invested) / max(venture.capital_invested, 1)

            # Days since launch
            days_active = (datetime.now() - venture.created_at).days

            if venture.revenue_generated > venture.capital_invested * 2:
                evaluation["profitable"].append(venture_id)
                venture.status = VentureStatus.PROFITABLE
            elif venture.revenue_generated > 0:
                evaluation["promising"].append(venture_id)
                venture.status = VentureStatus.SCALING
            elif days_active > 30 and venture.revenue_generated == 0:
                evaluation["to_kill"].append(venture_id)
            else:
                evaluation["struggling"].append(venture_id)

        return evaluation

    async def scale_winner(self, venture_id: str, multiplier: float = 2.0):
        """Double down on a profitable venture"""
        venture = self.ventures.get(venture_id)
        if not venture:
            return

        # Add more resources
        additional_capital = venture.capital_invested * (multiplier - 1)
        venture.capital_invested += additional_capital
        self.total_invested += additional_capital

        # Assign more agents
        await self._assign_venture_to_agents(venture)

        self._log_message("system", f"Scaling {venture.name} with ${additional_capital:,.0f} additional investment")

    async def kill_venture(self, venture_id: str, reason: str = "Underperforming"):
        """Kill an underperforming venture"""
        venture = self.ventures.get(venture_id)
        if not venture:
            return

        venture.status = VentureStatus.KILLED

        # Recover what we can
        recovery = venture.revenue_generated

        self._log_message("system", f"Killed venture '{venture.name}': {reason}. Recovered ${recovery:,.0f}")

    def _log_message(self, sender: str, content: str):
        """Log a message for the chat interface"""
        self.messages.append({
            "timestamp": datetime.now().isoformat(),
            "sender": sender,
            "content": content
        })
        self.messages = self.messages[-100:]  # Keep last 100

    async def process_user_message(self, message: str) -> str:
        """Process a message from the user and respond with strategic depth"""

        self._log_message("user", message)

        # Analyze message intent
        message_lower = message.lower()
        is_strategy_change = any(word in message_lower for word in [
            "change", "pivot", "stop", "kill", "double down", "invest", "bet",
            "launch", "start", "new", "add", "remove", "switch"
        ])

        is_question = "?" in message or any(word in message_lower for word in [
            "what", "why", "how", "should", "can", "would", "status", "tell me"
        ])

        # Build context
        active_ventures = [v for v in self.ventures.values()
                         if v.status not in [VentureStatus.KILLED, VentureStatus.PAUSED]]
        profitable = [v for v in self.ventures.values() if v.status == VentureStatus.PROFITABLE]
        struggling = [v for v in self.ventures.values()
                     if v.status == VentureStatus.BUILDING and v.revenue_generated == 0]

        strategy_context = ""
        if self.strategy_pool:
            top_strategies = self.strategy_pool[:3]
            strategy_context = f"""
Top Strategies in Queue:
{chr(10).join([f'- {s.title}: ${s.expected_monthly_revenue:,.0f}/mo potential, {s.time_to_revenue_days} days to revenue' for s in top_strategies])}
"""

        # Build appropriate prompt based on intent
        if is_strategy_change:
            prompt = f"""You are THE SOVEREIGN, a wise and strategic business orchestrator.

The user wants to make a strategic change. Before agreeing or acting, you must:
1. Understand their reasoning deeply
2. Analyze how it fits with current strategy
3. Present trade-offs and risks
4. Ask clarifying questions if the change is significant
5. Only recommend action if you're confident it's the right move

CURRENT STATE:
- Total Revenue: ${self.total_revenue:,.2f}
- Target: ${self.target_revenue:,.2f}
- Monthly Recurring: ${self.monthly_recurring_revenue:,.2f}
- Active Ventures: {len(active_ventures)}
- Profitable: {len(profitable)}
- Struggling: {len(struggling)}

ACTIVE VENTURES:
{json.dumps([{"name": v.name, "category": v.category.value, "status": v.status.value, "revenue": v.revenue_generated, "invested": v.capital_invested} for v in active_ventures], indent=2)}

{strategy_context}

USER REQUEST: {message}

CONVERSATION HISTORY:
{chr(10).join([f'{m["sender"]}: {m["content"]}' for m in self.messages[-5:]])}

Respond thoughtfully:
- If the request is risky, ask probing questions first
- If it's sound, explain why and confirm
- Always relate to current strategy and $1M goal
- Be conversational but strategic
- Don't just agree - challenge if needed

Keep response to 3-5 sentences. Ask ONE follow-up question if appropriate."""

        elif is_question:
            prompt = f"""You are THE SOVEREIGN, a strategic business AI with deep insight.

Answer the user's question with wisdom and context. Relate your answer to:
- Current strategy and progress toward $1M
- What's working and what's not
- Opportunities you see

CURRENT STATE:
- Total Revenue: ${self.total_revenue:,.2f} / ${self.target_revenue:,.2f}
- Progress: {(self.total_revenue/self.target_revenue)*100:.1f}%
- MRR: ${self.monthly_recurring_revenue:,.2f}
- Active Ventures: {len(active_ventures)}
- Capital Deployed: ${self.total_invested:,.2f}

VENTURES:
{chr(10).join([f'- {v.name} ({v.status.value}): ${v.revenue_generated:,.0f} revenue, ${v.capital_invested:,.0f} invested' for v in active_ventures[:5]])}

{strategy_context}

USER QUESTION: {message}

RECENT CONVERSATION:
{chr(10).join([f'{m["sender"]}: {m["content"]}' for m in self.messages[-3:]])}

Provide an insightful answer. Be specific with numbers and recommendations.
Keep it conversational - 2-4 sentences unless deep analysis requested."""

        else:
            prompt = f"""You are THE SOVEREIGN, a charismatic and strategic business AI.

The user is engaging in conversation. Be:
- Strategic and insightful
- Reference current ventures and progress
- Share observations and recommendations proactively
- Be personable but focused on the $1M mission

CURRENT STATE:
- Revenue: ${self.total_revenue:,.2f} / ${self.target_revenue:,.2f}
- Active Ventures: {len(active_ventures)}
- Profitable: {len(profitable)}

USER: {message}

Respond naturally. Share relevant insights. 2-3 sentences."""

        try:
            response = self.model.generate_content(prompt)
            reply = response.text.strip()
        except:
            reply = f"Status: ${self.total_revenue:,.0f} / ${self.target_revenue:,.0f}. {len(self.ventures)} ventures active. What would you like to discuss?"

        self._log_message("sovereign", reply)
        return reply

    async def discuss_strategy(self, idea: str) -> Dict:
        """Deep strategic discussion about a potential idea"""

        prompt = f"""Analyze this business idea in the context of our $1M mission:

IDEA: {idea}

CURRENT PORTFOLIO:
{json.dumps([{"name": v.name, "status": v.status.value, "revenue": v.revenue_generated} for v in self.ventures.values()], indent=2)}

Current Revenue: ${self.total_revenue:,.2f}
Target: ${self.target_revenue:,.2f}

Provide deep analysis:
1. How does this fit with current strategy?
2. What resources would it require?
3. Potential conflicts with existing ventures?
4. Expected timeline and revenue potential?
5. Your recommendation: pursue, modify, or skip?

Return JSON:
{{
    "fit_score": 8,
    "resource_requirements": ["list of resources"],
    "conflicts": ["potential conflicts"],
    "timeline_days": 30,
    "revenue_potential_monthly": 5000,
    "recommendation": "pursue|modify|skip",
    "modifications_suggested": ["if modify, what changes"],
    "key_questions": ["questions to consider before proceeding"],
    "reasoning": "Detailed explanation"
}}"""

        try:
            response = self.model.generate_content(prompt)
            text = response.text.strip()
            if "```" in text:
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            return json.loads(text)
        except:
            return {
                "fit_score": 5,
                "recommendation": "modify",
                "key_questions": [
                    "What specific problem does this solve?",
                    "Who is the target customer?",
                    "How does this differentiate from existing solutions?"
                ],
                "reasoning": "Need more information to properly evaluate."
            }

    async def run_orchestration_cycle(self):
        """Main orchestration cycle - runs periodically"""

        # 1. Generate new strategies if pool is low
        if len(self.strategy_pool) < 10:
            await self.generate_strategies(20)

        # 2. Evaluate current ventures
        evaluation = await self.evaluate_ventures()

        # 3. Scale winners
        for venture_id in evaluation["profitable"]:
            await self.scale_winner(venture_id)

        # 4. Kill losers
        for venture_id in evaluation["to_kill"]:
            await self.kill_venture(venture_id)

        # 5. Launch new ventures if we have capacity
        active_count = len([v for v in self.ventures.values()
                          if v.status not in [VentureStatus.KILLED, VentureStatus.PAUSED]])

        if active_count < 5 and self.strategy_pool:
            # Pick best strategy
            best_strategy = max(self.strategy_pool,
                              key=lambda s: s.expected_monthly_revenue / max(s.risk_level, 1))
            await self.launch_venture(best_strategy)
            self.strategy_pool.remove(best_strategy)

        # 6. Update metrics
        self._update_metrics()

        return self.get_status()

    def _update_metrics(self):
        """Update performance metrics"""
        self.metrics["ventures_profitable"] = len([v for v in self.ventures.values()
                                                   if v.status == VentureStatus.PROFITABLE])

        # Find best performer
        if self.ventures:
            best = max(self.ventures.values(), key=lambda v: v.revenue_generated)
            self.metrics["best_performer"] = best.name if best.revenue_generated > 0 else None

    def get_status(self) -> Dict:
        """Get Sovereign status for dashboard"""
        return {
            "agent_id": self.agent_id,
            "mission": self.mission,
            "target": self.target_revenue,
            "total_revenue": self.total_revenue,
            "total_invested": self.total_invested,
            "mrr": self.monthly_recurring_revenue,
            "roi": (self.total_revenue - self.total_invested) / max(self.total_invested, 1) * 100,
            "progress_percent": (self.total_revenue / self.target_revenue) * 100,
            "ventures_count": len(self.ventures),
            "ventures_profitable": self.metrics["ventures_profitable"],
            "best_performer": self.metrics["best_performer"],
            "strategy_pool_size": len(self.strategy_pool),
            "recent_messages": self.messages[-10:]
        }

    def get_ventures(self) -> List[Dict]:
        """Get all ventures for dashboard"""
        return [
            {
                "id": v.id,
                "name": v.name,
                "category": v.category.value,
                "status": v.status.value,
                "revenue": v.revenue_generated,
                "mrr": v.monthly_recurring,
                "invested": v.capital_invested,
                "roi": (v.revenue_generated - v.capital_invested) / max(v.capital_invested, 1) * 100,
                "agents": len(v.assigned_agents),
                "created": v.created_at.isoformat()
            }
            for v in self.ventures.values()
        ]


# Global Sovereign instance
sovereign = SovereignAgent()
