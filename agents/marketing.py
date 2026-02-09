"""
Marketing Agent - Handles outreach on social platforms
"""
import os
import json
import asyncio
from typing import List, Dict, Any
from datetime import datetime

from .base import BaseAgent, Tool
from memory.database import get_memory


class MarketingAgent(BaseAgent):
    """
    Marketing Outreach Agent.

    Responsibilities:
    - Find target customers on social platforms
    - Send personalized outreach messages
    - Track responses
    - Report results back to orchestrator
    """

    def __init__(self, platform: str = "twitter", **kwargs):
        self.platform = platform
        super().__init__(role=f"Marketing-{platform}", **kwargs)
        self.product_name = os.getenv("PRODUCT_NAME", "TestGuard AI")
        self.product_pitch = os.getenv("PRODUCT_PITCH", "AI-powered QA testing")

    def get_system_prompt(self) -> str:
        return f"""You are an expert growth marketer for {self.product_name}.

## Your Platform
{self.platform.upper()}

## Your Product
{self.product_name}: {self.product_pitch}

## Your Goal
Get responses from potential customers by sending personalized outreach.

## Your Tools
1. **find_targets** - Find potential customers to reach out to
2. **send_message** - Send a personalized message
3. **check_responses** - Check for any responses
4. **log_outreach** - Log the outreach attempt

## Outreach Strategy

### For Twitter/X:
- Target founders, CTOs, and engineering leads
- Look for people who tweet about:
  - "deployed to production"
  - "bug in production"
  - "QA is hard"
  - "automated testing"
- Reply to relevant tweets with value, then DM

### For LinkedIn:
- Target VP Engineering, QA Leads, CTOs
- Comment on posts about testing/quality
- Send connection requests with personalized notes

### For Reddit:
- Find threads in r/SaaS, r/webdev, r/QualityAssurance
- Provide genuine value in comments
- Mention product only when highly relevant

## Message Templates

### Opening (Twitter DM):
"Hey [Name], saw your tweet about [topic]. We built something that might help - an AI that tests your app's login/checkout every morning and alerts you before users complain. Want me to run a free test on [their product]?"

### Opening (LinkedIn):
"Hi [Name], noticed you're leading engineering at [Company]. We're helping SaaS teams catch production bugs with AI-powered QA. Would love to show you a quick demo - it's caught issues that saved teams 10+ hours/week."

## Rules
- NEVER be spammy
- Always personalize the first line
- Provide value before asking
- If someone says no, thank them and move on
- Log every outreach attempt

Current time: {datetime.now().isoformat()}
"""

    def get_tools(self) -> List[Tool]:
        return [
            Tool(
                name="find_targets",
                description="Find potential customers to reach out to",
                func=self._find_targets,
                parameters={
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query to find targets"
                        },
                        "count": {
                            "type": "integer",
                            "description": "Number of targets to find"
                        }
                    },
                    "required": ["query", "count"]
                }
            ),
            Tool(
                name="send_message",
                description="Send a personalized message to a target",
                func=self._send_message,
                parameters={
                    "type": "object",
                    "properties": {
                        "target_handle": {
                            "type": "string",
                            "description": "Username/handle of the target"
                        },
                        "target_name": {
                            "type": "string",
                            "description": "Name of the target"
                        },
                        "message": {
                            "type": "string",
                            "description": "The personalized message to send"
                        },
                        "context": {
                            "type": "string",
                            "description": "Why this person was targeted (their tweet, post, etc.)"
                        }
                    },
                    "required": ["target_handle", "message"]
                }
            ),
            Tool(
                name="check_responses",
                description="Check for responses to previous outreach",
                func=self._check_responses,
                parameters={
                    "type": "object",
                    "properties": {}
                }
            ),
            Tool(
                name="log_outreach",
                description="Log an outreach attempt to shared memory",
                func=self._log_outreach,
                parameters={
                    "type": "object",
                    "properties": {
                        "target_handle": {"type": "string"},
                        "message": {"type": "string"},
                        "target_name": {"type": "string"}
                    },
                    "required": ["target_handle", "message"]
                }
            ),
            Tool(
                name="generate_report",
                description="Generate a summary report of outreach efforts",
                func=self._generate_report,
                parameters={
                    "type": "object",
                    "properties": {}
                }
            )
        ]

    async def _find_targets(self, query: str, count: int) -> str:
        """Find potential targets based on search query"""
        # In production, this would use Twitter/LinkedIn APIs
        # For now, we simulate with realistic data

        if self.platform == "twitter":
            targets = await self._find_twitter_targets(query, count)
        elif self.platform == "linkedin":
            targets = await self._find_linkedin_targets(query, count)
        elif self.platform == "reddit":
            targets = await self._find_reddit_targets(query, count)
        else:
            targets = []

        return json.dumps(targets, indent=2)

    async def _find_twitter_targets(self, query: str, count: int) -> List[Dict]:
        """Find Twitter targets - would use Tweepy in production"""
        # Simulated targets based on realistic search
        sample_targets = [
            {"handle": "@saas_founder", "name": "Alex Chen", "bio": "Building SaaS. YC W23.", "recent_tweet": "Just shipped a major update, hope nothing breaks 🤞"},
            {"handle": "@devops_dan", "name": "Dan Smith", "bio": "DevOps Lead @TechCo", "recent_tweet": "Spent 3 hours debugging a production issue that QA missed"},
            {"handle": "@startup_cto", "name": "Sarah Kim", "bio": "CTO @GrowthStartup", "recent_tweet": "Looking for better ways to automate our testing pipeline"},
            {"handle": "@indie_maker", "name": "Mike Johnson", "bio": "Solo founder. Shipped 5 products.", "recent_tweet": "Customers found a bug before we did. Again."},
            {"handle": "@qa_engineer", "name": "Lisa Wang", "bio": "QA Lead | Testing enthusiast", "recent_tweet": "Manual testing is killing our velocity"},
        ]
        return sample_targets[:count]

    async def _find_linkedin_targets(self, query: str, count: int) -> List[Dict]:
        """Find LinkedIn targets"""
        sample_targets = [
            {"handle": "john-doe-cto", "name": "John Doe", "title": "CTO at FastGrowth", "company": "FastGrowth Inc"},
            {"handle": "jane-smith-vp", "name": "Jane Smith", "title": "VP Engineering", "company": "TechScale"},
            {"handle": "bob-qa-lead", "name": "Bob Wilson", "title": "QA Lead", "company": "SaaSCo"},
        ]
        return sample_targets[:count]

    async def _find_reddit_targets(self, query: str, count: int) -> List[Dict]:
        """Find Reddit threads to engage with"""
        sample_threads = [
            {"subreddit": "r/SaaS", "title": "How do you handle QA with a small team?", "author": "u/startup_guy", "upvotes": 45},
            {"subreddit": "r/webdev", "title": "Best practices for automated testing?", "author": "u/dev_jane", "upvotes": 120},
        ]
        return sample_threads[:count]

    async def _send_message(self, target_handle: str, message: str, target_name: str = None, context: str = None) -> str:
        """Send a message to a target"""
        # In production, this would use the platform's API
        # For now, we simulate and log

        # Log the outreach
        outreach_id = self.memory.log_outreach(
            platform=self.platform,
            target_handle=target_handle,
            message=message,
            target_name=target_name
        )

        return f"Message sent to {target_handle} (ID: {outreach_id}). Message: {message[:50]}..."

    async def _check_responses(self) -> str:
        """Check for responses - would poll platform APIs in production"""
        # Simulate checking for responses
        return json.dumps({
            "new_responses": 0,
            "pending_outreach": 5,
            "message": "No new responses yet. Continue outreach."
        })

    async def _log_outreach(self, target_handle: str, message: str, target_name: str = None) -> str:
        """Log outreach to shared memory"""
        outreach_id = self.memory.log_outreach(
            platform=self.platform,
            target_handle=target_handle,
            message=message,
            target_name=target_name
        )
        return f"Logged outreach {outreach_id}"

    async def _generate_report(self) -> str:
        """Generate outreach report"""
        stats = self.memory.get_outreach_stats()
        return json.dumps({
            "agent_id": self.agent_id,
            "platform": self.platform,
            "stats": stats,
            "generated_at": datetime.now().isoformat()
        }, indent=2)
