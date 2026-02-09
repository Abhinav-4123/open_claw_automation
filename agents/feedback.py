"""
Feedback Agent - Collects and analyzes user feedback
"""
import os
import json
from typing import List, Dict, Any
from datetime import datetime

from .base import BaseAgent, Tool
from memory.database import get_memory


class FeedbackAgent(BaseAgent):
    """
    Feedback Collection Agent.

    Responsibilities:
    - Collect responses from outreach
    - Analyze sentiment
    - Extract actionable insights
    - Report back to orchestrator
    """

    def __init__(self, source: str = "twitter_replies", **kwargs):
        self.source = source
        super().__init__(role=f"Feedback-{source}", **kwargs)

    def get_system_prompt(self) -> str:
        return f"""You are a customer feedback analyst for {os.getenv('PRODUCT_NAME', 'TestGuard AI')}.

## Your Source
{self.source}

## Your Goal
Collect, analyze, and categorize all feedback to help improve the product.

## Your Tools
1. **collect_responses** - Gather all responses from outreach
2. **analyze_sentiment** - Determine if feedback is positive/negative/neutral
3. **extract_insights** - Pull out actionable insights
4. **store_feedback** - Save feedback to shared memory
5. **generate_report** - Create a summary report

## Analysis Framework

### Sentiment Categories:
- **Positive**: Interest, enthusiasm, questions about pricing/features
- **Negative**: Objections, complaints, "not interested"
- **Neutral**: Questions, requests for more info

### Insight Categories:
- **Feature Requests**: Things people want that don't exist
- **Pain Points**: Problems they're experiencing
- **Objections**: Reasons they say no
- **Competitors**: Other solutions they mention
- **Pricing Feedback**: Comments about cost/value

## Rules
- Be objective - negative feedback is valuable
- Extract specific quotes for context
- Flag urgent issues (bugs, angry customers)
- Prioritize feedback that appears multiple times

Current time: {datetime.now().isoformat()}
"""

    def get_tools(self) -> List[Tool]:
        return [
            Tool(
                name="collect_responses",
                description="Collect all responses from a specific source",
                func=self._collect_responses,
                parameters={
                    "type": "object",
                    "properties": {
                        "since_hours": {
                            "type": "integer",
                            "description": "Collect responses from the last N hours",
                            "default": 24
                        }
                    }
                }
            ),
            Tool(
                name="analyze_sentiment",
                description="Analyze the sentiment of a piece of feedback",
                func=self._analyze_sentiment,
                parameters={
                    "type": "object",
                    "properties": {
                        "text": {
                            "type": "string",
                            "description": "The feedback text to analyze"
                        }
                    },
                    "required": ["text"]
                }
            ),
            Tool(
                name="extract_insights",
                description="Extract actionable insights from feedback",
                func=self._extract_insights,
                parameters={
                    "type": "object",
                    "properties": {
                        "feedback_list": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "List of feedback texts to analyze"
                        }
                    },
                    "required": ["feedback_list"]
                }
            ),
            Tool(
                name="store_feedback",
                description="Store analyzed feedback in shared memory",
                func=self._store_feedback,
                parameters={
                    "type": "object",
                    "properties": {
                        "user_handle": {"type": "string"},
                        "raw_feedback": {"type": "string"},
                        "sentiment": {"type": "string", "enum": ["positive", "negative", "neutral"]},
                        "key_points": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "actionable": {"type": "boolean"}
                    },
                    "required": ["user_handle", "raw_feedback", "sentiment", "key_points"]
                }
            ),
            Tool(
                name="generate_report",
                description="Generate a feedback summary report",
                func=self._generate_report,
                parameters={
                    "type": "object",
                    "properties": {}
                }
            )
        ]

    async def _collect_responses(self, since_hours: int = 24) -> str:
        """Collect responses from the source"""
        # In production, this would query platform APIs
        # Simulated responses for demonstration

        sample_responses = [
            {
                "user": "@dev_mike",
                "text": "This looks interesting! What's the pricing?",
                "timestamp": datetime.now().isoformat()
            },
            {
                "user": "@startup_ceo",
                "text": "We already use Cypress, how is this different?",
                "timestamp": datetime.now().isoformat()
            },
            {
                "user": "@qa_lead",
                "text": "Not interested right now, but maybe next quarter.",
                "timestamp": datetime.now().isoformat()
            },
            {
                "user": "@indie_dev",
                "text": "Love the idea! Can it test mobile apps too?",
                "timestamp": datetime.now().isoformat()
            },
            {
                "user": "@angry_user",
                "text": "Stop spamming me with DMs.",
                "timestamp": datetime.now().isoformat()
            }
        ]

        return json.dumps({
            "source": self.source,
            "responses": sample_responses,
            "count": len(sample_responses)
        }, indent=2)

    async def _analyze_sentiment(self, text: str) -> str:
        """Analyze sentiment of text"""
        # Simple rule-based for demo; in production use the LLM
        text_lower = text.lower()

        if any(word in text_lower for word in ["love", "interesting", "great", "pricing", "demo"]):
            sentiment = "positive"
        elif any(word in text_lower for word in ["not interested", "spam", "stop", "no thanks"]):
            sentiment = "negative"
        else:
            sentiment = "neutral"

        return json.dumps({
            "text": text,
            "sentiment": sentiment,
            "confidence": 0.85
        })

    async def _extract_insights(self, feedback_list: List[str]) -> str:
        """Extract insights from feedback"""
        insights = {
            "feature_requests": [],
            "pain_points": [],
            "objections": [],
            "competitors_mentioned": [],
            "positive_signals": []
        }

        for feedback in feedback_list:
            feedback_lower = feedback.lower()

            if "can it" in feedback_lower or "does it" in feedback_lower:
                insights["feature_requests"].append(feedback)
            if "already use" in feedback_lower:
                insights["competitors_mentioned"].append(feedback)
            if "not interested" in feedback_lower or "maybe later" in feedback_lower:
                insights["objections"].append(feedback)
            if "pricing" in feedback_lower or "love" in feedback_lower:
                insights["positive_signals"].append(feedback)

        return json.dumps(insights, indent=2)

    async def _store_feedback(
        self,
        user_handle: str,
        raw_feedback: str,
        sentiment: str,
        key_points: List[str],
        actionable: bool = False
    ) -> str:
        """Store feedback in database"""
        feedback_id = self.memory.store_feedback(
            source=self.source,
            user_handle=user_handle,
            raw_feedback=raw_feedback,
            sentiment=sentiment,
            key_points=key_points,
            actionable=actionable
        )
        return f"Feedback stored with ID: {feedback_id}"

    async def _generate_report(self) -> str:
        """Generate feedback report"""
        actionable = self.memory.get_actionable_feedback()

        report = {
            "agent_id": self.agent_id,
            "source": self.source,
            "actionable_feedback_count": len(actionable),
            "actionable_items": [
                {
                    "id": f.id,
                    "user": f.user_handle,
                    "feedback": f.raw_feedback,
                    "key_points": f.key_points
                }
                for f in actionable[:10]
            ],
            "generated_at": datetime.now().isoformat()
        }

        return json.dumps(report, indent=2)
