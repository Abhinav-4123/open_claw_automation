"""
THE ORACLE - Strategy Architect
Continuously generates and evaluates legitimate money-making strategies
"""
import os
import json
import asyncio
from typing import Dict, List, Optional
from datetime import datetime
from dataclasses import dataclass, field

import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))


@dataclass
class MarketOpportunity:
    """A market opportunity identified by Oracle"""
    id: str
    title: str
    market: str
    problem: str
    solution: str
    target_audience: str
    revenue_model: str
    competition_level: str  # low, medium, high
    market_size: str
    timing_score: int  # 1-10, how good is the timing
    ai_automation_potential: int  # 1-10, can AI automate this?
    confidence: float


@dataclass
class TrendAnalysis:
    """Analysis of current market trends"""
    timestamp: datetime
    hot_markets: List[str]
    emerging_technologies: List[str]
    declining_industries: List[str]
    opportunities: List[Dict]


class OracleAgent:
    """
    The Oracle - Strategy Architect

    Responsibilities:
    - Analyze market trends continuously
    - Generate 100+ potential strategies
    - Evaluate and rank opportunities
    - Identify timing for market entry
    - Assess AI automation potential
    """

    def __init__(self):
        self.model = genai.GenerativeModel('gemini-2.0-flash')
        self.agent_id = f"oracle_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        self.opportunities: List[MarketOpportunity] = []
        self.trend_history: List[TrendAnalysis] = []
        self.last_analysis: Optional[datetime] = None

        # Strategy categories with weights
        self.category_weights = {
            "saas": 0.25,
            "api_services": 0.20,
            "consulting": 0.15,
            "digital_products": 0.15,
            "affiliate": 0.10,
            "content": 0.10,
            "marketplace": 0.05
        }

    async def analyze_market_trends(self) -> TrendAnalysis:
        """Analyze current market trends"""

        prompt = """Analyze current market trends for online business opportunities in 2024-2025.

Provide:
1. Hot markets (growing demand)
2. Emerging technologies creating opportunities
3. Declining industries to avoid
4. Specific opportunities for AI-powered businesses

Return JSON:
{
    "hot_markets": ["market1", "market2", ...],
    "emerging_technologies": ["tech1", "tech2", ...],
    "declining_industries": ["industry1", ...],
    "opportunities": [
        {
            "title": "Opportunity name",
            "market": "Market segment",
            "why_now": "Why this is timely",
            "ai_angle": "How AI can be applied"
        }
    ]
}

Focus on realistic, actionable opportunities. Max 5 items per category."""

        try:
            response = self.model.generate_content(prompt)
            text = response.text.strip()
            if "```" in text:
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]

            data = json.loads(text)

            analysis = TrendAnalysis(
                timestamp=datetime.now(),
                hot_markets=data.get("hot_markets", []),
                emerging_technologies=data.get("emerging_technologies", []),
                declining_industries=data.get("declining_industries", []),
                opportunities=data.get("opportunities", [])
            )

            self.trend_history.append(analysis)
            self.last_analysis = datetime.now()

            return analysis

        except Exception as e:
            return TrendAnalysis(
                timestamp=datetime.now(),
                hot_markets=["AI/ML", "Cybersecurity", "Remote Work Tools"],
                emerging_technologies=["LLMs", "AI Agents", "No-Code"],
                declining_industries=["Traditional Consulting", "Manual Data Entry"],
                opportunities=[{
                    "title": "AI Security Scanner",
                    "market": "Cybersecurity",
                    "why_now": "Rising security concerns",
                    "ai_angle": "Automated vulnerability detection"
                }]
            )

    async def generate_opportunities(self, count: int = 50) -> List[MarketOpportunity]:
        """Generate specific business opportunities"""

        # Get recent trends
        if not self.trend_history or (datetime.now() - self.last_analysis).hours > 1:
            await self.analyze_market_trends()

        trends = self.trend_history[-1] if self.trend_history else None
        trends_context = json.dumps({
            "hot_markets": trends.hot_markets if trends else [],
            "technologies": trends.emerging_technologies if trends else []
        })

        prompt = f"""Generate {count} specific, actionable business opportunities.

Current Trends: {trends_context}

For each opportunity provide:
- Clear problem being solved
- Target audience
- Revenue model (subscription, usage, one-time, commission)
- Competition level
- How AI/automation applies

Return JSON array:
[
    {{
        "title": "Business name/concept",
        "market": "Target market",
        "problem": "Problem being solved",
        "solution": "Your solution",
        "target_audience": "Who pays",
        "revenue_model": "How you make money",
        "competition": "low|medium|high",
        "market_size": "small|medium|large",
        "timing_score": 8,
        "ai_potential": 9
    }}
]

Focus on:
1. Can be built by a small team or solo
2. Can leverage AI for automation
3. Has clear path to revenue
4. Reasonable competition level"""

        try:
            response = self.model.generate_content(prompt)
            text = response.text.strip()
            if "```" in text:
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]

            data = json.loads(text)

            opportunities = []
            for i, opp in enumerate(data):
                opportunity = MarketOpportunity(
                    id=f"opp_{datetime.now().strftime('%H%M%S')}_{i}",
                    title=opp.get("title", f"Opportunity {i+1}"),
                    market=opp.get("market", "General"),
                    problem=opp.get("problem", ""),
                    solution=opp.get("solution", ""),
                    target_audience=opp.get("target_audience", ""),
                    revenue_model=opp.get("revenue_model", "subscription"),
                    competition_level=opp.get("competition", "medium"),
                    market_size=opp.get("market_size", "medium"),
                    timing_score=int(opp.get("timing_score", 5)),
                    ai_automation_potential=int(opp.get("ai_potential", 5)),
                    confidence=0.7
                )
                opportunities.append(opportunity)

            self.opportunities = opportunities
            return opportunities

        except Exception as e:
            return self._fallback_opportunities()

    def _fallback_opportunities(self) -> List[MarketOpportunity]:
        """Fallback opportunities if API fails"""
        return [
            MarketOpportunity(
                id="opp_fallback_1",
                title="AI Code Review SaaS",
                market="Developer Tools",
                problem="Manual code reviews are slow",
                solution="AI-powered instant code review",
                target_audience="Development teams",
                revenue_model="subscription",
                competition_level="medium",
                market_size="large",
                timing_score=9,
                ai_automation_potential=10,
                confidence=0.85
            ),
            MarketOpportunity(
                id="opp_fallback_2",
                title="AI Meeting Summarizer",
                market="Productivity",
                problem="No one reads meeting notes",
                solution="Auto-generate actionable summaries",
                target_audience="Remote teams",
                revenue_model="subscription",
                competition_level="high",
                market_size="large",
                timing_score=8,
                ai_automation_potential=9,
                confidence=0.75
            )
        ]

    def rank_opportunities(self) -> List[MarketOpportunity]:
        """Rank opportunities by potential"""

        def score(opp: MarketOpportunity) -> float:
            # Scoring formula
            timing_weight = 0.3
            ai_weight = 0.3
            competition_penalty = {"low": 0, "medium": 0.1, "high": 0.25}
            market_bonus = {"small": 0, "medium": 0.1, "large": 0.2}

            base_score = (
                opp.timing_score * timing_weight +
                opp.ai_automation_potential * ai_weight
            ) / 10

            score = base_score
            score -= competition_penalty.get(opp.competition_level, 0.1)
            score += market_bonus.get(opp.market_size, 0)
            score *= opp.confidence

            return score

        return sorted(self.opportunities, key=score, reverse=True)

    def get_top_opportunities(self, count: int = 10) -> List[Dict]:
        """Get top ranked opportunities"""
        ranked = self.rank_opportunities()[:count]

        return [
            {
                "id": opp.id,
                "title": opp.title,
                "market": opp.market,
                "problem": opp.problem,
                "solution": opp.solution,
                "revenue_model": opp.revenue_model,
                "competition": opp.competition_level,
                "timing": opp.timing_score,
                "ai_potential": opp.ai_automation_potential,
                "confidence": opp.confidence
            }
            for opp in ranked
        ]

    def get_status(self) -> Dict:
        """Get Oracle status"""
        return {
            "agent_id": self.agent_id,
            "opportunities_count": len(self.opportunities),
            "last_analysis": self.last_analysis.isoformat() if self.last_analysis else None,
            "trend_analyses": len(self.trend_history),
            "top_markets": self.trend_history[-1].hot_markets[:5] if self.trend_history else []
        }


# Global Oracle instance
oracle = OracleAgent()
