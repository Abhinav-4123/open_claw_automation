"""
Coder Agent - Fixes bugs, implements features, reviews code
"""
import os
import json
import asyncio
from typing import List, Dict, Any
from datetime import datetime

import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))


class CoderAgent:
    """
    The Coder Agent - Handles all technical implementation tasks.

    Capabilities:
    - Fix bugs based on user reports
    - Implement new features
    - Review and improve code
    - Write tests
    - Deploy changes
    """

    def __init__(self):
        self.model = genai.GenerativeModel('gemini-2.0-flash')
        self.agent_id = f"coder_{datetime.now().strftime('%H%M%S')}"
        self.tasks_completed = 0
        self.current_task = None

    async def analyze_issue(self, issue_description: str, attachments: List[str] = None) -> Dict:
        """Analyze an issue reported by user or other agents"""

        context = f"Issue: {issue_description}"
        if attachments:
            context += f"\n\nAttachments/Context:\n" + "\n".join(attachments)

        prompt = f"""Analyze this technical issue and provide a plan to fix it:

{context}

Respond with a JSON object:
{{
    "issue_type": "bug|feature|improvement|documentation",
    "severity": "critical|high|medium|low",
    "affected_components": ["list", "of", "components"],
    "root_cause": "Brief analysis of the root cause",
    "solution_plan": [
        {{"step": 1, "action": "description", "file": "path/to/file"}},
        ...
    ],
    "estimated_complexity": "simple|moderate|complex",
    "risks": ["potential", "risks"]
}}

Return ONLY the JSON."""

        response = self.model.generate_content(prompt)

        try:
            text = response.text.strip()
            if "```" in text:
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            return json.loads(text)
        except:
            return {
                "issue_type": "bug",
                "severity": "medium",
                "affected_components": ["unknown"],
                "root_cause": issue_description,
                "solution_plan": [{"step": 1, "action": "Investigate further", "file": "unknown"}],
                "estimated_complexity": "moderate",
                "risks": ["Requires more information"]
            }

    async def generate_fix(self, issue_analysis: Dict, file_content: str = None) -> Dict:
        """Generate code fix based on analysis"""

        prompt = f"""Based on this issue analysis, generate the code fix:

Analysis:
{json.dumps(issue_analysis, indent=2)}

{"Current file content:" + file_content if file_content else ""}

Provide:
1. The specific code changes needed
2. Any new files to create
3. Tests to add

Respond with JSON:
{{
    "changes": [
        {{
            "file": "path/to/file",
            "action": "modify|create|delete",
            "old_code": "code to replace (if modify)",
            "new_code": "new code"
        }}
    ],
    "tests": [
        {{
            "file": "path/to/test",
            "code": "test code"
        }}
    ],
    "deployment_notes": "Any special deployment instructions"
}}

Return ONLY the JSON."""

        response = self.model.generate_content(prompt)

        try:
            text = response.text.strip()
            if "```" in text:
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            return json.loads(text)
        except:
            return {
                "changes": [],
                "tests": [],
                "deployment_notes": "Could not generate fix automatically. Manual review needed."
            }

    async def review_code(self, code: str, context: str = "") -> Dict:
        """Review code and provide feedback"""

        prompt = f"""Review this code and provide feedback:

Context: {context}

Code:
```
{code}
```

Provide a JSON response:
{{
    "overall_quality": "excellent|good|needs_improvement|poor",
    "score": 0-100,
    "issues": [
        {{
            "severity": "critical|warning|info",
            "line": "line number or range",
            "issue": "description",
            "suggestion": "how to fix"
        }}
    ],
    "positive_aspects": ["list", "of", "good", "things"],
    "refactoring_suggestions": ["optional", "improvements"]
}}

Return ONLY the JSON."""

        response = self.model.generate_content(prompt)

        try:
            text = response.text.strip()
            if "```" in text:
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            return json.loads(text)
        except:
            return {
                "overall_quality": "needs_review",
                "score": 50,
                "issues": [],
                "positive_aspects": [],
                "refactoring_suggestions": []
            }

    async def implement_feature(self, feature_request: str, context: Dict = None) -> Dict:
        """Implement a new feature based on request"""

        prompt = f"""Implement this feature:

Request: {feature_request}

{"Additional context: " + json.dumps(context) if context else ""}

Provide a complete implementation plan and code:

{{
    "feature_name": "name",
    "description": "what it does",
    "files": [
        {{
            "path": "path/to/file",
            "action": "create|modify",
            "code": "full code content",
            "description": "what this file does"
        }}
    ],
    "dependencies": ["any", "new", "dependencies"],
    "configuration": {{"any": "config needed"}},
    "testing_plan": "how to test this feature"
}}

Return ONLY the JSON."""

        response = self.model.generate_content(prompt)

        try:
            text = response.text.strip()
            if "```" in text:
                text = text.split("```")[1]
                if text.startswith("json"):
                    text = text[4:]
            return json.loads(text)
        except:
            return {
                "feature_name": feature_request[:50],
                "description": feature_request,
                "files": [],
                "dependencies": [],
                "configuration": {},
                "testing_plan": "Manual testing required"
            }

    async def process_user_request(self, request: str, request_type: str, attachments: List[str] = None) -> Dict:
        """Process any user request related to code"""

        self.current_task = {
            "request": request,
            "type": request_type,
            "started_at": datetime.now().isoformat(),
            "status": "processing"
        }

        result = {}

        if request_type == "bug_fix":
            analysis = await self.analyze_issue(request, attachments)
            fix = await self.generate_fix(analysis)
            result = {
                "analysis": analysis,
                "fix": fix,
                "status": "fix_generated"
            }

        elif request_type == "feature":
            implementation = await self.implement_feature(request, {"attachments": attachments})
            result = {
                "implementation": implementation,
                "status": "implementation_ready"
            }

        elif request_type == "review":
            code = attachments[0] if attachments else request
            review = await self.review_code(code, request)
            result = {
                "review": review,
                "status": "review_complete"
            }

        else:
            # Generic request
            analysis = await self.analyze_issue(request, attachments)
            result = {
                "analysis": analysis,
                "status": "analyzed"
            }

        self.tasks_completed += 1
        self.current_task["status"] = "completed"
        self.current_task["result"] = result

        return result


# Global coder instance
coder = CoderAgent()
