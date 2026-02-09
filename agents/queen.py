"""
Queen Agent - The Supreme Orchestrator
Creates and manages all other agents, drives daily product improvements
"""
import os
import json
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, field

import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))


@dataclass
class DailyGoal:
    """A daily improvement goal"""
    id: str
    title: str
    description: str
    assigned_to: str
    status: str = "pending"
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    result: Optional[Dict] = None


@dataclass
class SecurityFramework:
    """Security compliance framework"""
    name: str
    description: str
    controls: List[str]
    priority: str


class QueenAgent:
    """
    The Queen Agent - Supreme Orchestrator of the AI Company.

    Responsibilities:
    - Create and manage Product Manager & Programme Manager agents
    - Define daily improvement goals (minimum 4 features/day)
    - Track security compliance frameworks (VAPT, ISO 27001, OWASP)
    - Orchestrate the entire product development lifecycle
    - Monitor and optimize agent performance
    """

    def __init__(self):
        self.model = genai.GenerativeModel('gemini-2.0-flash')
        self.agent_id = f"queen_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.daily_goals: List[DailyGoal] = []
        self.managed_agents: Dict[str, Dict] = {}
        self.security_frameworks = self._init_security_frameworks()
        self.metrics = {
            "features_shipped_today": 0,
            "total_features_shipped": 0,
            "security_issues_fixed": 0,
            "compliance_score": 0,
            "daily_goal": 4  # Minimum 4 features per day
        }

    def _init_security_frameworks(self) -> Dict[str, SecurityFramework]:
        """Initialize security compliance frameworks"""
        return {
            "vapt": SecurityFramework(
                name="VAPT (Vulnerability Assessment & Penetration Testing)",
                description="Comprehensive security testing methodology",
                controls=[
                    "Network vulnerability scanning",
                    "Web application penetration testing",
                    "API security testing",
                    "Authentication & authorization testing",
                    "Input validation testing",
                    "Session management testing",
                    "Error handling review",
                    "Cryptography assessment"
                ],
                priority="critical"
            ),
            "iso27001": SecurityFramework(
                name="ISO 27001",
                description="Information Security Management System",
                controls=[
                    "A.5 Information security policies",
                    "A.6 Organization of information security",
                    "A.7 Human resource security",
                    "A.8 Asset management",
                    "A.9 Access control",
                    "A.10 Cryptography",
                    "A.11 Physical and environmental security",
                    "A.12 Operations security",
                    "A.13 Communications security",
                    "A.14 System acquisition, development and maintenance",
                    "A.15 Supplier relationships",
                    "A.16 Information security incident management",
                    "A.17 Business continuity management",
                    "A.18 Compliance"
                ],
                priority="high"
            ),
            "owasp_top10": SecurityFramework(
                name="OWASP Top 10 (2021)",
                description="Most critical web application security risks",
                controls=[
                    "A01:2021 - Broken Access Control",
                    "A02:2021 - Cryptographic Failures",
                    "A03:2021 - Injection (SQL, NoSQL, OS, LDAP)",
                    "A04:2021 - Insecure Design",
                    "A05:2021 - Security Misconfiguration",
                    "A06:2021 - Vulnerable and Outdated Components",
                    "A07:2021 - Identification and Authentication Failures",
                    "A08:2021 - Software and Data Integrity Failures",
                    "A09:2021 - Security Logging and Monitoring Failures",
                    "A10:2021 - Server-Side Request Forgery (SSRF)"
                ],
                priority="critical"
            ),
            "pci_dss": SecurityFramework(
                name="PCI DSS",
                description="Payment Card Industry Data Security Standard",
                controls=[
                    "Build and maintain secure network",
                    "Protect cardholder data",
                    "Maintain vulnerability management program",
                    "Implement strong access control measures",
                    "Regularly monitor and test networks",
                    "Maintain information security policy"
                ],
                priority="high"
            ),
            "soc2": SecurityFramework(
                name="SOC 2 Type II",
                description="Service Organization Control",
                controls=[
                    "Security - Protection against unauthorized access",
                    "Availability - System availability for operation",
                    "Processing Integrity - System processing is complete and accurate",
                    "Confidentiality - Information designated as confidential is protected",
                    "Privacy - Personal information is collected, used, retained appropriately"
                ],
                priority="high"
            )
        }

    async def create_managed_agent(self, agent_type: str, role: str) -> Dict:
        """Create a managed agent (Product Manager, Programme Manager, etc.)"""

        prompt = f"""Design a {agent_type} agent with role: {role}

Create a detailed agent specification with:
1. Key responsibilities (5-7 items)
2. Daily tasks it should perform
3. Metrics it should track
4. How it interfaces with other agents

Return JSON:
{{
    "name": "{agent_type}",
    "role": "{role}",
    "responsibilities": ["list"],
    "daily_tasks": ["list"],
    "metrics": ["list"],
    "interfaces": ["list"]
}}"""

        try:
            response = self.model.generate_content(prompt)
            text = response.text.strip()
            if "```" in text:
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            spec = json.loads(text)
        except:
            spec = {
                "name": agent_type,
                "role": role,
                "responsibilities": [f"Manage {agent_type} tasks"],
                "daily_tasks": ["Review progress", "Plan next steps"],
                "metrics": ["tasks_completed"],
                "interfaces": ["queen", "other_agents"]
            }

        agent = {
            "id": f"{agent_type}_{datetime.now().strftime('%H%M%S')}",
            "type": agent_type,
            "spec": spec,
            "status": "active",
            "created_at": datetime.now().isoformat(),
            "tasks_completed": 0
        }

        self.managed_agents[agent["id"]] = agent
        return agent

    async def generate_daily_goals(self, product_context: str) -> List[DailyGoal]:
        """Generate minimum 4 daily improvement goals"""

        frameworks_context = "\n".join([
            f"- {f.name}: {', '.join(f.controls[:3])}..."
            for f in self.security_frameworks.values()
        ])

        prompt = f"""As the Queen Agent, generate exactly 4 high-impact daily improvement goals.

Product Context: {product_context}

Security Frameworks to consider:
{frameworks_context}

Generate 4 specific, actionable goals that will improve the product today.
Mix of: features, security fixes, UX improvements, and performance.

Return JSON:
{{
    "goals": [
        {{
            "title": "Short title",
            "description": "Detailed description of what to build/fix",
            "type": "feature|security|ux|performance",
            "assigned_to": "product_manager|programme_manager|coder|marketing",
            "priority": "critical|high|medium",
            "security_framework": "vapt|iso27001|owasp_top10|none"
        }}
    ]
}}"""

        try:
            response = self.model.generate_content(prompt)
            text = response.text.strip()
            if "```" in text:
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            data = json.loads(text)

            goals = []
            for i, g in enumerate(data.get("goals", [])[:4]):
                goal = DailyGoal(
                    id=f"goal_{datetime.now().strftime('%Y%m%d')}_{i+1}",
                    title=g.get("title", f"Goal {i+1}"),
                    description=g.get("description", ""),
                    assigned_to=g.get("assigned_to", "product_manager")
                )
                goals.append(goal)

            self.daily_goals = goals
            return goals

        except:
            # Fallback goals
            return [
                DailyGoal(id="goal_1", title="Add user authentication",
                         description="Implement email signup/login", assigned_to="coder"),
                DailyGoal(id="goal_2", title="Security scan integration",
                         description="Add OWASP ZAP integration", assigned_to="coder"),
                DailyGoal(id="goal_3", title="Dashboard improvements",
                         description="Add real-time metrics", assigned_to="product_manager"),
                DailyGoal(id="goal_4", title="API documentation",
                         description="Generate OpenAPI spec", assigned_to="coder")
            ]

    async def analyze_security_requirements(self, target_app: str) -> Dict:
        """Analyze what security tests/fixes are required"""

        prompt = f"""Analyze security requirements for: {target_app}

Based on these frameworks:
1. VAPT - Vulnerability Assessment & Penetration Testing
2. ISO 27001 - Information Security Management
3. OWASP Top 10 - Web Application Security
4. PCI DSS - Payment Card Security (if applicable)
5. SOC 2 - Service Organization Control

Provide a comprehensive security analysis plan:

Return JSON:
{{
    "risk_level": "critical|high|medium|low",
    "immediate_actions": [
        {{
            "action": "Description",
            "framework": "owasp|iso27001|vapt",
            "priority": "critical|high|medium"
        }}
    ],
    "security_tests_required": [
        {{
            "test_name": "Name",
            "category": "injection|auth|config|crypto|etc",
            "tools": ["suggested", "tools"]
        }}
    ],
    "compliance_gaps": ["list of potential gaps"],
    "remediation_timeline": "estimated time"
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
                "risk_level": "high",
                "immediate_actions": [
                    {"action": "Run VAPT scan", "framework": "vapt", "priority": "critical"},
                    {"action": "Review access controls", "framework": "iso27001", "priority": "high"},
                    {"action": "Test for OWASP Top 10", "framework": "owasp", "priority": "critical"}
                ],
                "security_tests_required": [
                    {"test_name": "SQL Injection Test", "category": "injection", "tools": ["sqlmap", "shannon"]},
                    {"test_name": "XSS Testing", "category": "xss", "tools": ["xsstrike", "shannon"]},
                    {"test_name": "Auth Bypass Test", "category": "auth", "tools": ["burp", "shannon"]}
                ],
                "compliance_gaps": ["Unknown - requires full assessment"],
                "remediation_timeline": "2-4 weeks"
            }

    async def run_daily_cycle(self, product_context: str):
        """Run the daily improvement cycle"""

        # 1. Generate daily goals
        goals = await self.generate_daily_goals(product_context)

        # 2. Ensure we have Product Manager and Programme Manager
        if "product_manager" not in [a.get("type") for a in self.managed_agents.values()]:
            await self.create_managed_agent("product_manager", "Product Strategy & Feature Prioritization")

        if "programme_manager" not in [a.get("type") for a in self.managed_agents.values()]:
            await self.create_managed_agent("programme_manager", "Execution & Delivery Management")

        # 3. Assign goals to agents
        for goal in goals:
            # Find matching agent
            for agent in self.managed_agents.values():
                if agent["type"] == goal.assigned_to:
                    goal.status = "assigned"
                    break

        return {
            "daily_goals": [{"id": g.id, "title": g.title, "assigned_to": g.assigned_to} for g in goals],
            "managed_agents": list(self.managed_agents.keys()),
            "target_features": self.metrics["daily_goal"]
        }

    def get_status(self) -> Dict:
        """Get Queen agent status"""
        return {
            "agent_id": self.agent_id,
            "managed_agents": len(self.managed_agents),
            "daily_goals": len(self.daily_goals),
            "goals_completed": len([g for g in self.daily_goals if g.status == "completed"]),
            "metrics": self.metrics,
            "security_frameworks": list(self.security_frameworks.keys())
        }


# Global Queen instance
queen = QueenAgent()
