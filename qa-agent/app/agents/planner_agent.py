"""
NEXUS QA - Planner Agent
Uses LLM to create contextual test plans based on discovered information.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from .base import BaseAgent, TaskContext, AgentResult

logger = logging.getLogger(__name__)


class PlannerAgent(BaseAgent):
    """
    Planner Agent - Creates contextual security test plans.

    Phase 3 responsibilities:
    - Analyze product profile from PM Agent
    - Review discovered journeys from Explorer Agent
    - Consider API inventory from DevTools Agent
    - Generate prioritized test plan
    - Map attack surfaces per product type
    """

    agent_type = "planner"

    PLANNING_PROMPT = """You are a Senior Security Architect creating a comprehensive security test plan.

## Context

**Product Analysis:**
{product_profile}

**User Journeys Discovered:**
{journeys}

**API Inventory:**
{api_inventory}

## Your Task

Create a prioritized security test plan that is contextual to this specific application.

Consider:
1. The type of application (e-commerce needs payment security, SaaS needs auth security, etc.)
2. The discovered user journeys and their criticality
3. The APIs discovered and their authentication methods
4. Known attack surfaces for this product type

## Output Format

Return a JSON object with this structure:
{{
    "test_plan_id": "unique_id",
    "product_context": {{
        "type": "app type",
        "critical_assets": ["list of critical assets to protect"],
        "threat_model": "brief threat model summary"
    }},
    "test_phases": [
        {{
            "phase": 1,
            "name": "Authentication Security",
            "priority": "critical",
            "estimated_duration_minutes": 15,
            "tests": [
                {{
                    "id": "AUTH-001",
                    "name": "Test name",
                    "description": "What to test",
                    "target": "specific endpoint or journey",
                    "method": "how to test (automated/manual/both)",
                    "attack_type": "OWASP category if applicable",
                    "expected_result": "what a pass looks like"
                }}
            ]
        }}
    ],
    "api_specific_tests": [
        {{
            "endpoint": "/api/v1/users",
            "tests": ["IDOR check", "Rate limit test", "Auth bypass attempt"]
        }}
    ],
    "journey_specific_tests": [
        {{
            "journey": "checkout",
            "tests": ["Price manipulation", "Race condition", "Payment bypass"]
        }}
    ],
    "estimated_total_duration_minutes": 45,
    "risk_summary": "Brief summary of highest risk areas"
}}

Be specific and actionable. Prioritize based on actual risk."""

    def __init__(self, llm_provider=None):
        super().__init__()
        self.llm_provider = llm_provider

    async def execute(self, context: TaskContext) -> AgentResult:
        """Generate contextual test plan."""
        start_time = datetime.now()

        try:
            await self.report_progress(10, "Gathering context from previous phases")

            # Get data from previous phases
            product_profile = context.shared_data.get("product_profile", {})
            journeys = context.shared_data.get("journeys", [])
            api_inventory = context.shared_data.get("api_inventory", [])

            await self.report_progress(30, "Analyzing attack surfaces")

            # Build context for LLM
            product_summary = self._summarize_product(product_profile)
            journey_summary = self._summarize_journeys(journeys)
            api_summary = self._summarize_apis(api_inventory)

            await self.report_progress(50, "Generating test plan with LLM")

            # Generate plan with LLM
            plan = await self._generate_plan(
                product_summary,
                journey_summary,
                api_summary
            )

            await self.report_progress(80, "Validating and enriching plan")

            # Enrich plan with default tests if needed
            plan = self._enrich_plan(plan, product_profile, journeys, api_inventory)

            await self.report_progress(100, "Test plan complete")

            duration = (datetime.now() - start_time).total_seconds()
            return AgentResult(
                success=True,
                data=plan,
                duration_seconds=duration
            )

        except Exception as e:
            logger.exception(f"Planner Agent error: {e}")
            # Return fallback plan
            return AgentResult(
                success=True,  # Still return a plan
                data=self._get_fallback_plan(context),
                partial=True,
                error=str(e)
            )

    def _summarize_product(self, profile: Dict) -> str:
        """Summarize product profile for prompt."""
        if not profile:
            return "Product profile not available"

        return f"""
- Type: {profile.get('app_type', 'unknown')}
- Industry: {profile.get('industry', 'unknown')}
- Name: {profile.get('product_name', 'unknown')}
- Core Features: {', '.join(profile.get('core_features', [])[:10])}
- Auth Methods: {', '.join(profile.get('auth_methods', []))}
- Has Signup: {profile.get('has_signup', False)}
- Has Login: {profile.get('has_login', False)}
- Has Pricing/Payment: {profile.get('has_pricing', False)}
- Tech Hints: {', '.join(profile.get('tech_hints', [])[:5])}
"""

    def _summarize_journeys(self, journeys: List[Dict]) -> str:
        """Summarize journeys for prompt."""
        if not journeys:
            return "No user journeys discovered"

        lines = []
        for j in journeys[:10]:  # Top 10
            lines.append(
                f"- {j.get('name', 'Unknown')} ({j.get('priority', 'low')} priority): "
                f"{j.get('steps_count', 0)} steps, "
                f"forms: {len(j.get('forms', []))}"
            )
        return "\n".join(lines)

    def _summarize_apis(self, apis: List[Dict]) -> str:
        """Summarize API inventory for prompt."""
        if not apis:
            return "No APIs discovered"

        lines = []
        for api in apis[:15]:  # Top 15
            auth = "AUTH" if api.get("has_auth") else "NO_AUTH"
            lines.append(
                f"- {api.get('method', 'GET')} {api.get('path', '/')} [{auth}] "
                f"- statuses: {api.get('response_statuses', [])}"
            )
        return "\n".join(lines)

    async def _generate_plan(
        self,
        product_summary: str,
        journey_summary: str,
        api_summary: str
    ) -> Dict:
        """Generate test plan using LLM."""
        if not self.llm_provider:
            from ..llm_provider import LLMProvider
            self.llm_provider = LLMProvider()

        prompt = self.PLANNING_PROMPT.format(
            product_profile=product_summary,
            journeys=journey_summary,
            api_inventory=api_summary
        )

        try:
            response = await self.llm_provider.chat_simple(prompt)

            # Parse JSON from response
            response_text = response.strip()

            # Handle markdown code blocks
            if "```json" in response_text:
                response_text = response_text.split("```json")[1].split("```")[0]
            elif "```" in response_text:
                response_text = response_text.split("```")[1].split("```")[0]

            plan = json.loads(response_text)
            plan["generated_by"] = "llm"
            return plan

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse LLM plan: {e}")
            return self._get_fallback_plan(None)
        except Exception as e:
            logger.warning(f"LLM planning failed: {e}")
            return self._get_fallback_plan(None)

    def _enrich_plan(
        self,
        plan: Dict,
        product_profile: Dict,
        journeys: List[Dict],
        api_inventory: List[Dict]
    ) -> Dict:
        """Enrich plan with additional tests based on context."""

        # Ensure test_phases exists
        if "test_phases" not in plan:
            plan["test_phases"] = []

        # Add authentication tests if login exists
        if product_profile.get("has_login") or product_profile.get("has_signup"):
            auth_phase = self._find_or_create_phase(plan, "Authentication")
            auth_phase["tests"].extend([
                {
                    "id": "AUTH-AUTO-001",
                    "name": "Brute Force Protection",
                    "description": "Test rate limiting on login",
                    "target": "login endpoint",
                    "method": "automated",
                    "attack_type": "OWASP A07:2021",
                    "auto_added": True
                },
                {
                    "id": "AUTH-AUTO-002",
                    "name": "Session Security",
                    "description": "Verify session token security",
                    "target": "session cookies",
                    "method": "automated",
                    "attack_type": "OWASP A07:2021",
                    "auto_added": True
                }
            ])

        # Add payment tests if pricing exists
        if product_profile.get("has_pricing"):
            payment_phase = self._find_or_create_phase(plan, "Payment Security")
            payment_phase["tests"].extend([
                {
                    "id": "PAY-AUTO-001",
                    "name": "Price Manipulation",
                    "description": "Test for price tampering in requests",
                    "target": "checkout API",
                    "method": "manual",
                    "attack_type": "Business Logic",
                    "auto_added": True
                }
            ])

        # Add API-specific tests
        if "api_specific_tests" not in plan:
            plan["api_specific_tests"] = []

        for api in api_inventory[:10]:
            if not api.get("has_auth"):
                plan["api_specific_tests"].append({
                    "endpoint": api.get("path", "/"),
                    "tests": ["Authentication requirement check"],
                    "concern": "Endpoint may be unprotected",
                    "auto_added": True
                })

        return plan

    def _find_or_create_phase(self, plan: Dict, phase_name: str) -> Dict:
        """Find existing phase or create new one."""
        for phase in plan.get("test_phases", []):
            if phase_name.lower() in phase.get("name", "").lower():
                return phase

        # Create new phase
        new_phase = {
            "phase": len(plan.get("test_phases", [])) + 1,
            "name": phase_name,
            "priority": "high",
            "estimated_duration_minutes": 10,
            "tests": []
        }
        plan["test_phases"].append(new_phase)
        return new_phase

    def _get_fallback_plan(self, context: Optional[TaskContext]) -> Dict:
        """Get fallback plan when LLM fails."""
        return {
            "test_plan_id": f"fallback_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "generated_by": "fallback",
            "product_context": {
                "type": "unknown",
                "critical_assets": ["user_data", "authentication", "sessions"],
                "threat_model": "Standard web application threat model"
            },
            "test_phases": [
                {
                    "phase": 1,
                    "name": "Infrastructure Security",
                    "priority": "critical",
                    "estimated_duration_minutes": 10,
                    "tests": [
                        {
                            "id": "INF-001",
                            "name": "Security Headers",
                            "description": "Check all security headers",
                            "target": "all responses",
                            "method": "automated"
                        },
                        {
                            "id": "INF-002",
                            "name": "TLS Configuration",
                            "description": "Verify TLS/SSL setup",
                            "target": "HTTPS connection",
                            "method": "automated"
                        }
                    ]
                },
                {
                    "phase": 2,
                    "name": "Authentication Security",
                    "priority": "critical",
                    "estimated_duration_minutes": 15,
                    "tests": [
                        {
                            "id": "AUTH-001",
                            "name": "Session Management",
                            "description": "Test session security",
                            "target": "session cookies",
                            "method": "automated"
                        },
                        {
                            "id": "AUTH-002",
                            "name": "Password Policy",
                            "description": "Check password requirements",
                            "target": "signup/password forms",
                            "method": "automated"
                        }
                    ]
                },
                {
                    "phase": 3,
                    "name": "Injection Testing",
                    "priority": "high",
                    "estimated_duration_minutes": 15,
                    "tests": [
                        {
                            "id": "INJ-001",
                            "name": "XSS Detection",
                            "description": "Test for cross-site scripting",
                            "target": "all input fields",
                            "method": "automated"
                        },
                        {
                            "id": "INJ-002",
                            "name": "SQL Injection",
                            "description": "Test for SQL injection",
                            "target": "database queries",
                            "method": "automated"
                        }
                    ]
                },
                {
                    "phase": 4,
                    "name": "Data Security",
                    "priority": "high",
                    "estimated_duration_minutes": 10,
                    "tests": [
                        {
                            "id": "DATA-001",
                            "name": "Sensitive Data Exposure",
                            "description": "Check for exposed sensitive data",
                            "target": "responses and storage",
                            "method": "automated"
                        }
                    ]
                }
            ],
            "api_specific_tests": [],
            "journey_specific_tests": [],
            "estimated_total_duration_minutes": 50,
            "risk_summary": "Using standard security test plan"
        }
