"""
NEXUS QA - AI-Driven Deep Security Scanner
Multi-agent system for comprehensive application security testing.

Architecture:
1. Planner Agent - Analyzes app, creates comprehensive test plan
2. Explorer Agent - VLM-based UI understanding for intelligent navigation
3. API Analyzer - Maps all APIs, creates test strategies
4. Security Tester - Executes actual penetration tests
5. Reporter Agent - Compiles findings into actionable report
"""

import asyncio
import base64
import json
import logging
import os
import re
import uuid
import ipaddress
import httpx
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Callable
from pathlib import Path
from urllib.parse import urlparse, urljoin, parse_qs

from playwright.async_api import Browser, Page, BrowserContext, async_playwright, Locator

logger = logging.getLogger(__name__)

# Gemini API for VLM analysis
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"


def is_safe_url(url: str) -> bool:
    """Validate URL to prevent SSRF attacks."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
        blocked_hosts = ['localhost', '127.0.0.1', '0.0.0.0', 'metadata.google.internal', '169.254.169.254']
        if hostname.lower() in blocked_hosts:
            return False
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_link_local:
                return False
        except ValueError:
            pass
        if parsed.scheme not in ('http', 'https'):
            return False
        return True
    except Exception:
        return False


class ScanEventType(str, Enum):
    """Types of events during a live scan."""
    SCAN_STARTED = "scan_started"
    PHASE_CHANGED = "phase_changed"

    # Planning
    PLAN_STARTED = "plan_started"
    PLAN_NOTE = "plan_note"
    PLAN_COMPLETE = "plan_complete"

    # Exploration
    PAGE_ANALYZED = "page_analyzed"
    UI_ELEMENT_FOUND = "ui_element_found"
    ACTION_DECIDED = "action_decided"
    ACTION_EXECUTED = "action_executed"

    # Journey
    JOURNEY_DISCOVERED = "journey_discovered"
    JOURNEY_STEP = "journey_step"
    JOURNEY_STEP_COMPLETED = "journey_step_completed"
    JOURNEY_COMPLETED = "journey_completed"

    # Module Discovery
    MODULE_DISCOVERED = "module_discovered"
    FEATURE_DISCOVERED = "feature_discovered"

    # API
    API_DISCOVERED = "api_discovered"
    API_ANALYZED = "api_analyzed"
    API_TEST_PLANNED = "api_test_planned"
    API_TEST_EXECUTED = "api_test_executed"

    # Security Testing
    SECURITY_TEST_STARTED = "security_test_started"
    SECURITY_TEST_EXECUTED = "security_test_executed"
    VULNERABILITY_FOUND = "vulnerability_found"
    FINDING_DETECTED = "finding_detected"

    # Screenshots
    SCREENSHOT_CAPTURED = "screenshot_captured"

    # Auth
    LOGIN_REQUIRED = "login_required"
    LOGIN_ATTEMPTED = "login_attempted"
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"

    # Progress
    STATS_UPDATE = "stats_update"
    CONTEXT_NOTE = "context_note"
    AI_ANALYSIS = "ai_analysis"

    # Completion
    SCAN_COMPLETE = "scan_complete"
    SCAN_ERROR = "scan_error"


@dataclass
class ScanEvent:
    """A single event during the scan."""
    type: ScanEventType
    timestamp: str
    message: str
    data: Dict[str, Any] = field(default_factory=dict)
    screenshot_base64: Optional[str] = None

    def to_sse(self) -> str:
        """Format as Server-Sent Event."""
        payload = {
            "type": self.type.value,
            "timestamp": self.timestamp,
            "message": self.message,
            "data": self.data,
        }
        if self.screenshot_base64:
            payload["image_base64"] = self.screenshot_base64
        return f"data: {json.dumps(payload)}\n\n"


@dataclass
class TestPlan:
    """AI-generated test plan for the application."""
    id: str
    app_description: str
    identified_features: List[str]
    user_journeys: List[Dict[str, Any]]
    api_endpoints: List[Dict[str, Any]]
    security_tests: List[Dict[str, Any]]
    notes: List[str]
    priority_areas: List[str]
    estimated_duration_minutes: int
    created_at: str


@dataclass
class DiscoveredAPI:
    """A discovered API endpoint with test strategy."""
    id: str
    method: str
    url: str
    path: str
    host: str
    params: Dict[str, Any]
    request_headers: Dict[str, str]
    request_body: Optional[str]
    response_status: int
    response_headers: Dict[str, str]
    response_body_sample: Optional[str]
    content_type: str
    auth_required: bool
    test_strategy: List[str]
    vulnerabilities_found: List[str]
    timestamp: str


@dataclass
class SecurityTest:
    """A security test to execute."""
    id: str
    name: str
    category: str  # xss, sqli, auth_bypass, idor, ssrf, etc.
    target_url: str
    method: str
    payload: str
    expected_behavior: str
    actual_result: Optional[str] = None
    vulnerable: bool = False
    evidence: Optional[str] = None


@dataclass
class DiscoveredJourney:
    """A discovered user journey."""
    id: str
    name: str
    description: str
    start_url: str
    steps: List[Dict] = field(default_factory=list)
    status: str = "discovered"
    screenshot_base64: Optional[str] = None
    started_at: Optional[str] = None
    completed_at: Optional[str] = None


@dataclass
class DiscoveredModule:
    """A discovered application module."""
    id: str
    name: str
    url: str
    description: str
    features: List[str] = field(default_factory=list)
    screenshot_base64: Optional[str] = None
    discovered_at: str = ""


class LiveScanSession:
    """Manages an AI-driven deep security scanning session."""

    def __init__(self, scan_id: str, url: str):
        self.scan_id = scan_id
        self.url = self._normalize_url(url)
        self.base_domain = urlparse(self.url).netloc

        # Status
        self.status = "initializing"
        self.phase = "starting"
        self.progress = 0
        self.started_at = datetime.now().isoformat()
        self.completed_at: Optional[str] = None

        # Event system
        self.event_queue: asyncio.Queue = asyncio.Queue()
        self.events: List[ScanEvent] = []

        # AI-generated plan
        self.test_plan: Optional[TestPlan] = None
        self.plan_notes: List[str] = []

        # Discovery
        self.modules: Dict[str, DiscoveredModule] = {}
        self.journeys: Dict[str, DiscoveredJourney] = {}
        self.current_journey: Optional[DiscoveredJourney] = None
        self.apis: Dict[str, DiscoveredAPI] = {}
        self.security_tests: List[SecurityTest] = []

        # Exploration state
        self.visited_urls: Set[str] = set()
        self.explored_elements: Set[str] = set()
        self.pending_urls: List[str] = []
        self.page_screenshots: Dict[str, str] = {}

        # Findings
        self.findings: List[Dict] = []
        self.vulnerabilities: List[Dict] = []

        # Browser
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None

        # Auth
        self.credentials: Optional[Dict] = None
        self.awaiting_credentials = False
        self.is_authenticated = False

        # Stats
        self.stats = {
            "pages_visited": 0,
            "buttons_clicked": 0,
            "forms_filled": 0,
            "api_calls_captured": 0,
            "screenshots_taken": 0,
            "journeys_completed": 0,
            "modules_discovered": 0,
            "security_tests_run": 0,
            "vulnerabilities_found": 0,
            "ai_analyses": 0,
        }

    def _normalize_url(self, url: str) -> str:
        """Ensure URL has proper scheme and validate."""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        url = url.rstrip('/')
        if not is_safe_url(url):
            raise ValueError(f"URL targets internal or restricted resources")
        return url

    async def emit_event(self, event_type: ScanEventType, message: str,
                        data: Dict = None, screenshot: str = None):
        """Emit an event to the SSE stream."""
        event = ScanEvent(
            type=event_type,
            timestamp=datetime.now().isoformat(),
            message=message,
            data=data or {},
            screenshot_base64=screenshot
        )
        self.events.append(event)
        await self.event_queue.put(event)

    async def event_stream(self):
        """Generator for Server-Sent Events stream."""
        for event in self.events[-50:]:
            yield event.to_sse()

        while self.status not in ("completed", "failed"):
            try:
                event = await asyncio.wait_for(self.event_queue.get(), timeout=30.0)
                yield event.to_sse()
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"
            except Exception as e:
                logger.error(f"Event stream error: {e}")
                break

        yield f"data: {{\"type\": \"stream_end\", \"status\": \"{self.status}\"}}\n\n"

    async def capture_screenshot(self, label: str = "screenshot") -> Optional[str]:
        """Capture screenshot and return base64."""
        if not self.page:
            return None
        try:
            screenshot_bytes = await self.page.screenshot(full_page=False)
            screenshot_base64 = base64.b64encode(screenshot_bytes).decode('utf-8')
            self.stats["screenshots_taken"] += 1
            return screenshot_base64
        except Exception as e:
            logger.error(f"Screenshot failed: {e}")
            return None

    def provide_credentials(self, credentials: Dict):
        """Receive credentials from user."""
        self.credentials = {
            'email': credentials.get('email') or credentials.get('username', ''),
            'password': credentials.get('password', ''),
        }
        self.awaiting_credentials = False

    def get_status(self) -> Dict:
        """Get current scan status."""
        return {
            "scan_id": self.scan_id,
            "url": self.url,
            "status": self.status,
            "phase": self.phase,
            "progress": self.progress,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "awaiting_credentials": self.awaiting_credentials,
            "is_authenticated": self.is_authenticated,
            "stats": self.stats,
            "test_plan": asdict(self.test_plan) if self.test_plan else None,
            "modules": [asdict(m) for m in self.modules.values()],
            "journeys": [
                {
                    "id": j.id,
                    "name": j.name,
                    "description": j.description,
                    "status": j.status,
                    "steps": j.steps,
                    "screenshot": j.screenshot_base64
                }
                for j in self.journeys.values()
            ],
            "apis_discovered": len(self.apis),
            "findings": self.findings,
            "vulnerabilities": self.vulnerabilities,
        }


class AIAgent:
    """Base class for AI agents."""

    def __init__(self, session: LiveScanSession):
        self.session = session
        self.api_key = GEMINI_API_KEY

    async def analyze_with_vision(self, screenshot_base64: str, prompt: str) -> str:
        """Use Gemini Vision to analyze a screenshot."""
        if not self.api_key:
            return "VLM not configured - using heuristic analysis"

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    f"{GEMINI_API_URL}?key={self.api_key}",
                    json={
                        "contents": [{
                            "parts": [
                                {"text": prompt},
                                {
                                    "inline_data": {
                                        "mime_type": "image/png",
                                        "data": screenshot_base64
                                    }
                                }
                            ]
                        }],
                        "generationConfig": {
                            "temperature": 0.1,
                            "maxOutputTokens": 2048
                        }
                    }
                )

                if response.status_code == 200:
                    result = response.json()
                    self.session.stats["ai_analyses"] += 1
                    return result.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                else:
                    logger.error(f"VLM API error: {response.status_code}")
                    return "VLM analysis failed"
        except Exception as e:
            logger.error(f"VLM error: {e}")
            return f"VLM error: {str(e)}"

    async def analyze_with_text(self, prompt: str) -> str:
        """Use Gemini for text analysis."""
        if not self.api_key:
            return "LLM not configured"

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    f"{GEMINI_API_URL}?key={self.api_key}",
                    json={
                        "contents": [{"parts": [{"text": prompt}]}],
                        "generationConfig": {
                            "temperature": 0.2,
                            "maxOutputTokens": 4096
                        }
                    }
                )

                if response.status_code == 200:
                    result = response.json()
                    self.session.stats["ai_analyses"] += 1
                    return result.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                return "LLM analysis failed"
        except Exception as e:
            logger.error(f"LLM error: {e}")
            return f"LLM error: {str(e)}"


class PlannerAgent(AIAgent):
    """Creates comprehensive test plan by analyzing the application."""

    async def create_test_plan(self, initial_screenshot: str, page_html: str, captured_apis: List[Dict]) -> TestPlan:
        """Analyze app and create detailed test plan."""
        await self.session.emit_event(
            ScanEventType.PLAN_STARTED,
            "AI Planner analyzing application structure...",
            {"phase": "planning"}
        )

        # Analyze with VLM
        vision_prompt = """Analyze this web application screenshot and identify:

1. APPLICATION TYPE: What kind of app is this? (SaaS, e-commerce, dashboard, etc.)
2. VISIBLE FEATURES: List all visible UI elements, buttons, forms, navigation items
3. USER JOURNEYS: What user flows are possible from this screen?
4. SECURITY SURFACES: What areas need security testing? (login, forms, file uploads, etc.)
5. PRIORITY AREAS: What should be tested first?

Respond in JSON format:
{
    "app_type": "...",
    "features": ["feature1", "feature2"],
    "ui_elements": [{"type": "button/link/form", "text": "...", "action": "..."}],
    "user_journeys": [{"name": "...", "steps": ["step1", "step2"]}],
    "security_surfaces": ["login", "api", "forms"],
    "priority": ["high priority area 1", "area 2"]
}"""

        vision_analysis = await self.analyze_with_vision(initial_screenshot, vision_prompt)

        await self.session.emit_event(
            ScanEventType.AI_ANALYSIS,
            "VLM completed initial analysis",
            {"analysis_type": "vision", "result_length": len(vision_analysis)}
        )

        # Parse vision results
        try:
            # Try to extract JSON from response
            json_match = re.search(r'\{[\s\S]*\}', vision_analysis)
            if json_match:
                vision_data = json.loads(json_match.group())
            else:
                vision_data = {"features": [], "user_journeys": [], "security_surfaces": []}
        except:
            vision_data = {"features": [], "user_journeys": [], "security_surfaces": []}

        # Analyze captured APIs
        api_analysis_prompt = f"""Analyze these captured API calls and create a security test strategy:

APIs Captured:
{json.dumps(captured_apis[:20], indent=2)}

For each API endpoint, identify:
1. What data it handles
2. Authentication requirements
3. Security tests to run (SQLi, XSS, IDOR, auth bypass, etc.)
4. Test payloads to use

Respond in JSON:
{{
    "api_summary": "...",
    "endpoints": [
        {{"path": "/api/...", "method": "POST", "tests": ["sqli", "xss"], "priority": "high"}}
    ],
    "test_strategies": [
        {{"category": "authentication", "tests": ["brute force", "session fixation"]}}
    ]
}}"""

        api_analysis = await self.analyze_with_text(api_analysis_prompt)

        try:
            json_match = re.search(r'\{[\s\S]*\}', api_analysis)
            if json_match:
                api_data = json.loads(json_match.group())
            else:
                api_data = {"endpoints": [], "test_strategies": []}
        except:
            api_data = {"endpoints": [], "test_strategies": []}

        # Generate comprehensive plan notes
        notes = [
            f"Application Type: {vision_data.get('app_type', 'Web Application')}",
            f"Identified {len(vision_data.get('features', []))} features",
            f"Found {len(captured_apis)} API endpoints to test",
            f"Priority areas: {', '.join(vision_data.get('priority', ['login', 'forms']))}",
        ]

        for note in notes:
            await self.session.emit_event(
                ScanEventType.PLAN_NOTE,
                note,
                {"note": note}
            )
            await asyncio.sleep(0.3)

        # Create test plan
        plan = TestPlan(
            id=f"plan_{uuid.uuid4().hex[:8]}",
            app_description=vision_data.get('app_type', 'Web Application'),
            identified_features=vision_data.get('features', []),
            user_journeys=vision_data.get('user_journeys', []),
            api_endpoints=api_data.get('endpoints', []),
            security_tests=api_data.get('test_strategies', []),
            notes=notes,
            priority_areas=vision_data.get('priority', []),
            estimated_duration_minutes=30 + len(captured_apis) * 2,
            created_at=datetime.now().isoformat()
        )

        await self.session.emit_event(
            ScanEventType.PLAN_COMPLETE,
            f"Test plan created: {len(plan.user_journeys)} journeys, {len(plan.api_endpoints)} APIs to test",
            {
                "plan_id": plan.id,
                "journeys_count": len(plan.user_journeys),
                "apis_count": len(plan.api_endpoints),
                "estimated_minutes": plan.estimated_duration_minutes
            }
        )

        return plan


class ExplorerAgent(AIAgent):
    """Uses VLM to intelligently navigate and explore the application."""

    async def analyze_page_and_decide_action(self, screenshot: str, current_url: str, visited: Set[str]) -> Dict:
        """Analyze current page and decide next action."""
        prompt = f"""You are a security tester exploring a web application.

Current URL: {current_url}
Pages already visited: {len(visited)}

Analyze this screenshot and decide the NEXT ACTION to take.
Goal: Systematically explore ALL features, forms, and functionality.

Consider:
1. What interactive elements are visible? (buttons, links, forms, tabs, menus)
2. What areas haven't been explored yet?
3. What might reveal more functionality? (dropdowns, hamburger menus, settings)
4. Are there forms that need to be filled?

Respond in JSON:
{{
    "page_description": "Brief description of current page",
    "visible_elements": [
        {{"type": "button/link/form/input", "text": "...", "selector_hint": "..."}}
    ],
    "recommended_action": {{
        "action": "click/fill/navigate/scroll",
        "target": "element description or selector",
        "reason": "why this action"
    }},
    "discovered_features": ["feature1", "feature2"],
    "potential_security_concerns": ["concern1"]
}}"""

        analysis = await self.analyze_with_vision(screenshot, prompt)

        try:
            json_match = re.search(r'\{[\s\S]*\}', analysis)
            if json_match:
                return json.loads(json_match.group())
        except:
            pass

        return {
            "page_description": "Unable to analyze",
            "recommended_action": {"action": "continue", "target": "next element", "reason": "fallback"},
            "visible_elements": [],
            "discovered_features": []
        }

    async def find_and_click_element(self, page: Page, target_description: str) -> bool:
        """Use AI to find and click an element based on description."""
        # Get page content for context
        try:
            # Try common selectors based on description
            selectors_to_try = [
                f'button:has-text("{target_description}")',
                f'a:has-text("{target_description}")',
                f'[aria-label*="{target_description}" i]',
                f'[title*="{target_description}" i]',
                f':text("{target_description}")',
            ]

            for selector in selectors_to_try:
                try:
                    elem = page.locator(selector).first
                    if await elem.is_visible(timeout=2000):
                        await elem.click()
                        self.session.stats["buttons_clicked"] += 1
                        return True
                except:
                    continue

            return False
        except:
            return False


class APIAnalyzerAgent(AIAgent):
    """Analyzes discovered APIs and creates test strategies."""

    async def analyze_api(self, api: DiscoveredAPI) -> List[str]:
        """Analyze an API and determine security tests to run."""
        prompt = f"""Analyze this API endpoint for security testing:

Endpoint: {api.method} {api.path}
Request Headers: {json.dumps(dict(list(api.request_headers.items())[:10]))}
Request Body: {api.request_body[:500] if api.request_body else 'None'}
Response Status: {api.response_status}
Content-Type: {api.content_type}

Determine:
1. What security tests should be run? (SQLi, XSS, IDOR, auth bypass, etc.)
2. What payloads should be tested?
3. What parameters are injectable?
4. Is authentication properly enforced?

Respond with a list of specific test cases in JSON:
{{
    "auth_required": true/false,
    "injectable_params": ["param1", "param2"],
    "tests": [
        {{"category": "sqli", "payload": "' OR 1=1--", "target_param": "id"}},
        {{"category": "xss", "payload": "<script>alert(1)</script>", "target_param": "name"}}
    ],
    "risk_level": "high/medium/low"
}}"""

        analysis = await self.analyze_with_text(prompt)

        try:
            json_match = re.search(r'\{[\s\S]*\}', analysis)
            if json_match:
                data = json.loads(json_match.group())
                return data.get("tests", [])
        except:
            pass

        return []


class SecurityTesterAgent(AIAgent):
    """Executes actual security tests against the application."""

    async def run_header_checks(self, response_headers: Dict[str, str], url: str) -> List[Dict]:
        """Check for missing security headers."""
        findings = []

        required_headers = {
            "strict-transport-security": ("Missing HSTS Header", "medium", "CWE-523"),
            "x-content-type-options": ("Missing X-Content-Type-Options", "low", "CWE-16"),
            "x-frame-options": ("Missing X-Frame-Options", "medium", "CWE-1021"),
            "content-security-policy": ("Missing CSP Header", "medium", "CWE-1021"),
            "x-xss-protection": ("Missing X-XSS-Protection", "low", "CWE-79"),
        }

        headers_lower = {k.lower(): v for k, v in response_headers.items()}

        for header, (title, severity, cwe) in required_headers.items():
            if header not in headers_lower:
                findings.append({
                    "id": f"HDR-{len(findings)+1}",
                    "title": title,
                    "severity": severity,
                    "cwe": cwe,
                    "url": url,
                    "evidence": f"Missing header: {header}"
                })

        return findings

    async def test_xss(self, page: Page, form_selector: str) -> List[Dict]:
        """Test for XSS vulnerabilities in forms."""
        findings = []
        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><img src=x onerror=alert(1)>',
            "'-alert(1)-'",
            '<svg onload=alert(1)>',
        ]

        try:
            inputs = await page.locator(f'{form_selector} input[type="text"], {form_selector} textarea').all()

            for payload in xss_payloads[:2]:  # Test first 2 payloads
                for input_elem in inputs[:3]:  # Test first 3 inputs
                    try:
                        await input_elem.fill(payload)
                        self.session.stats["security_tests_run"] += 1
                    except:
                        continue
        except:
            pass

        return findings

    async def test_sql_injection(self, api_url: str, method: str, params: Dict) -> List[Dict]:
        """Test for SQL injection vulnerabilities."""
        findings = []
        sqli_payloads = ["' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT NULL--"]

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                for param_name, param_value in params.items():
                    for payload in sqli_payloads:
                        test_params = params.copy()
                        test_params[param_name] = payload

                        try:
                            if method.upper() == "GET":
                                resp = await client.get(api_url, params=test_params)
                            else:
                                resp = await client.post(api_url, data=test_params)

                            self.session.stats["security_tests_run"] += 1

                            # Check for SQL error indicators
                            error_indicators = ["sql", "syntax", "mysql", "postgresql", "oracle", "sqlite"]
                            response_text = resp.text.lower()

                            if any(ind in response_text for ind in error_indicators):
                                findings.append({
                                    "id": f"SQLI-{len(findings)+1}",
                                    "title": "Potential SQL Injection",
                                    "severity": "critical",
                                    "cwe": "CWE-89",
                                    "url": api_url,
                                    "parameter": param_name,
                                    "payload": payload,
                                    "evidence": "SQL error message in response"
                                })
                        except:
                            continue
        except:
            pass

        return findings


class DeepExploratoryScanner:
    """AI-driven deep security scanner using multiple agents."""

    def __init__(self, session: LiveScanSession):
        self.session = session
        self.playwright = None
        self.planner = PlannerAgent(session)
        self.explorer = ExplorerAgent(session)
        self.api_analyzer = APIAnalyzerAgent(session)
        self.security_tester = SecurityTesterAgent(session)
        self.captured_requests: List[Dict] = []
        self.max_exploration_time = 3600  # 1 hour max
        self.start_time = None

    async def run(self):
        """Run the complete AI-driven deep scan."""
        self.start_time = datetime.now()

        try:
            # Phase 1: Initialize
            await self._phase_initialize()

            # Phase 2: Initial reconnaissance and AI planning
            await self._phase_reconnaissance_and_planning()

            # Phase 3: Handle authentication
            await self._phase_authentication()

            # Phase 4: AI-driven deep exploration
            await self._phase_ai_exploration()

            # Phase 5: API security testing
            await self._phase_api_testing()

            # Phase 6: Form and input testing
            await self._phase_form_testing()

            # Phase 7: Generate report
            await self._phase_finalize()

        except Exception as e:
            logger.error(f"Scan failed: {e}")
            self.session.status = "failed"
            await self.session.emit_event(
                ScanEventType.SCAN_ERROR,
                f"Scan failed: {str(e)}",
                {"error": str(e)}
            )
        finally:
            await self._cleanup()

    async def _phase_initialize(self):
        """Initialize browser and setup request interception."""
        self.session.phase = "initializing"
        self.session.progress = 5

        await self.session.emit_event(
            ScanEventType.PHASE_CHANGED,
            "Phase 1: Initializing AI-driven scanner",
            {"phase": "initialize", "progress": 5}
        )

        self.playwright = await async_playwright().start()
        self.session.browser = await self.playwright.chromium.launch(
            headless=True,
            args=['--no-sandbox', '--disable-dev-shm-usage']
        )

        self.session.context = await self.session.browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        )

        # Intercept all requests
        await self.session.context.route("**/*", self._intercept_request)

        self.session.page = await self.session.context.new_page()

    async def _intercept_request(self, route, request):
        """Intercept and log all requests."""
        try:
            url = request.url

            # Skip static assets
            if any(ext in url for ext in ['.png', '.jpg', '.gif', '.css', '.woff', '.ico', '.svg']):
                await route.continue_()
                return

            # Capture API calls
            if '/api/' in url or request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                self.captured_requests.append({
                    "method": request.method,
                    "url": url,
                    "path": urlparse(url).path,
                    "headers": dict(request.headers),
                    "post_data": request.post_data,
                    "timestamp": datetime.now().isoformat()
                })
                self.session.stats["api_calls_captured"] += 1

            await route.continue_()
        except:
            try:
                await route.continue_()
            except:
                pass

    async def _phase_reconnaissance_and_planning(self):
        """Load page, analyze with AI, and create test plan."""
        self.session.phase = "planning"
        self.session.progress = 10

        await self.session.emit_event(
            ScanEventType.PHASE_CHANGED,
            "Phase 2: AI reconnaissance and test planning",
            {"phase": "planning", "progress": 10}
        )

        # Navigate to target
        try:
            await self.session.page.goto(self.session.url, wait_until="networkidle", timeout=30000)
        except:
            await self.session.page.goto(self.session.url, wait_until="domcontentloaded", timeout=15000)

        await asyncio.sleep(2)
        self.session.visited_urls.add(self.session.page.url)
        self.session.stats["pages_visited"] += 1

        # Capture initial screenshot
        screenshot = await self.session.capture_screenshot("Initial Page")

        await self.session.emit_event(
            ScanEventType.SCREENSHOT_CAPTURED,
            "Initial page screenshot captured",
            {"title": "Initial Page", "url": self.session.page.url},
            screenshot
        )

        # Get page HTML for analysis
        page_html = await self.session.page.content()

        # Create AI-driven test plan
        self.session.test_plan = await self.planner.create_test_plan(
            screenshot,
            page_html[:5000],  # First 5000 chars
            self.captured_requests
        )

        # Check for login
        has_login = await self._detect_login_form()
        if has_login:
            self.session.awaiting_credentials = True
            await self.session.emit_event(
                ScanEventType.LOGIN_REQUIRED,
                "Login form detected - credentials required for authenticated testing",
                {"has_login_form": True}
            )

    async def _phase_authentication(self):
        """Handle authentication with provided or without credentials."""
        if not self.session.awaiting_credentials:
            return

        self.session.phase = "authentication"
        self.session.progress = 15

        await self.session.emit_event(
            ScanEventType.PHASE_CHANGED,
            "Phase 3: Authentication handling",
            {"phase": "authentication", "progress": 15}
        )

        # Wait for credentials (max 2 minutes)
        max_wait = 120
        waited = 0

        while self.session.awaiting_credentials and waited < max_wait:
            await asyncio.sleep(3)
            waited += 3

            if waited % 30 == 0:
                await self.session.emit_event(
                    ScanEventType.CONTEXT_NOTE,
                    f"Waiting for credentials... ({waited}s). Will continue unauthenticated scan after {max_wait}s",
                    {"waited": waited}
                )

        if self.session.credentials:
            await self._perform_login()
        else:
            await self.session.emit_event(
                ScanEventType.CONTEXT_NOTE,
                "Continuing with unauthenticated scan - testing public areas only",
                {}
            )
            self.session.awaiting_credentials = False

    async def _perform_login(self):
        """Attempt login with provided credentials."""
        journey = DiscoveredJourney(
            id=f"journey_{uuid.uuid4().hex[:8]}",
            name="Authentication",
            description="Login flow testing",
            start_url=self.session.page.url,
            status="in_progress",
            started_at=datetime.now().isoformat()
        )
        self.session.journeys[journey.id] = journey
        self.session.current_journey = journey

        await self.session.emit_event(
            ScanEventType.JOURNEY_DISCOVERED,
            "Starting Authentication journey",
            {"journey_id": journey.id, "name": journey.name},
            await self.session.capture_screenshot("Login Start")
        )

        await self.session.emit_event(
            ScanEventType.LOGIN_ATTEMPTED,
            "Attempting login with provided credentials",
            {}
        )

        try:
            creds = self.session.credentials
            email = creds.get('email', '')
            password = creds.get('password', '')

            # Fill email
            email_selectors = ['input[type="email"]', 'input[name*="email"]', 'input[name*="user"]']
            for selector in email_selectors:
                try:
                    elem = self.session.page.locator(selector).first
                    if await elem.is_visible(timeout=2000):
                        await elem.fill(email)
                        journey.steps.append({"action": "fill", "element": "email", "step": len(journey.steps)+1})
                        await self.session.emit_event(
                            ScanEventType.JOURNEY_STEP_COMPLETED,
                            f"Filled email field",
                            {"journey_id": journey.id, "step": {"action": "fill", "element": "email"}}
                        )
                        break
                except:
                    continue

            await asyncio.sleep(0.5)

            # Fill password
            try:
                pwd_elem = self.session.page.locator('input[type="password"]').first
                if await pwd_elem.is_visible(timeout=2000):
                    await pwd_elem.fill(password)
                    journey.steps.append({"action": "fill", "element": "password", "step": len(journey.steps)+1})
                    await self.session.emit_event(
                        ScanEventType.JOURNEY_STEP_COMPLETED,
                        f"Filled password field",
                        {"journey_id": journey.id, "step": {"action": "fill", "element": "password"}}
                    )
            except:
                pass

            await asyncio.sleep(0.5)

            # Click submit
            submit_selectors = ['button[type="submit"]', 'input[type="submit"]', 'button:has-text("Sign in")', 'button:has-text("Log in")']
            for selector in submit_selectors:
                try:
                    elem = self.session.page.locator(selector).first
                    if await elem.is_visible(timeout=2000):
                        await elem.click()
                        journey.steps.append({"action": "click", "element": "submit", "step": len(journey.steps)+1})
                        await self.session.emit_event(
                            ScanEventType.JOURNEY_STEP_COMPLETED,
                            f"Clicked submit button",
                            {"journey_id": journey.id, "step": {"action": "click", "element": "submit"}}
                        )
                        break
                except:
                    continue

            await asyncio.sleep(3)
            await self.session.page.wait_for_load_state("networkidle", timeout=10000)

            # Check login success
            if not await self._detect_login_form():
                self.session.is_authenticated = True
                self.session.awaiting_credentials = False

                await self.session.emit_event(
                    ScanEventType.LOGIN_SUCCESS,
                    "Successfully authenticated",
                    {}
                )

                journey.status = "completed"
                journey.completed_at = datetime.now().isoformat()
            else:
                await self.session.emit_event(
                    ScanEventType.LOGIN_FAILED,
                    "Login may have failed - continuing with available access",
                    {}
                )
                journey.status = "failed"

            await self.session.emit_event(
                ScanEventType.JOURNEY_COMPLETED,
                f"Authentication journey {journey.status}",
                {"journey_id": journey.id, "success": journey.status == "completed"},
                await self.session.capture_screenshot("After Login")
            )

        except Exception as e:
            logger.error(f"Login error: {e}")
            journey.status = "failed"

        self.session.current_journey = None
        self.session.stats["journeys_completed"] += 1

    async def _phase_ai_exploration(self):
        """AI-driven systematic exploration of the application."""
        self.session.phase = "deep_exploration"
        self.session.progress = 25

        await self.session.emit_event(
            ScanEventType.PHASE_CHANGED,
            "Phase 4: AI-driven deep exploration",
            {"phase": "deep_exploration", "progress": 25}
        )

        # Create exploration journey
        journey = DiscoveredJourney(
            id=f"journey_{uuid.uuid4().hex[:8]}",
            name="Application Discovery",
            description="Systematically exploring all application features",
            start_url=self.session.page.url,
            status="in_progress",
            started_at=datetime.now().isoformat()
        )
        self.session.journeys[journey.id] = journey
        self.session.current_journey = journey

        await self.session.emit_event(
            ScanEventType.JOURNEY_DISCOVERED,
            "Starting Application Discovery journey",
            {"journey_id": journey.id, "name": journey.name},
            await self.session.capture_screenshot("Exploration Start")
        )

        # Exploration loop - AI decides what to do
        exploration_count = 0
        max_explorations = 50

        while exploration_count < max_explorations:
            # Check time limit
            elapsed = (datetime.now() - self.start_time).total_seconds()
            if elapsed > self.max_exploration_time:
                await self.session.emit_event(
                    ScanEventType.CONTEXT_NOTE,
                    f"Time limit reached ({elapsed/60:.1f} min). Moving to security testing.",
                    {}
                )
                break

            # Take screenshot
            screenshot = await self.session.capture_screenshot(f"Exploration {exploration_count}")

            # AI analyzes and decides action
            analysis = await self.explorer.analyze_page_and_decide_action(
                screenshot,
                self.session.page.url,
                self.session.visited_urls
            )

            await self.session.emit_event(
                ScanEventType.PAGE_ANALYZED,
                f"AI Analysis: {analysis.get('page_description', 'Analyzing...')[:100]}",
                {"analysis": analysis, "exploration_count": exploration_count},
                screenshot
            )

            # Discover features
            for feature in analysis.get("discovered_features", []):
                await self.session.emit_event(
                    ScanEventType.FEATURE_DISCOVERED,
                    f"Discovered feature: {feature}",
                    {"feature": feature}
                )

            # Execute recommended action
            action = analysis.get("recommended_action", {})
            action_type = action.get("action", "continue")
            target = action.get("target", "")

            await self.session.emit_event(
                ScanEventType.ACTION_DECIDED,
                f"AI decided: {action_type} on '{target[:50]}'",
                {"action": action}
            )

            if action_type == "click" and target:
                success = await self.explorer.find_and_click_element(self.session.page, target)
                if success:
                    await asyncio.sleep(1)

                    # Record step
                    journey.steps.append({
                        "action": "click",
                        "target": target,
                        "url": self.session.page.url,
                        "step": len(journey.steps) + 1
                    })

                    await self.session.emit_event(
                        ScanEventType.ACTION_EXECUTED,
                        f"Clicked: {target[:50]}",
                        {"action": "click", "target": target},
                        await self.session.capture_screenshot(f"After click: {target[:20]}")
                    )

                    # Check for new page
                    if self.session.page.url not in self.session.visited_urls:
                        self.session.visited_urls.add(self.session.page.url)
                        self.session.stats["pages_visited"] += 1

                        # Discover module
                        module = DiscoveredModule(
                            id=f"mod_{uuid.uuid4().hex[:8]}",
                            name=await self.session.page.title() or target[:30],
                            url=self.session.page.url,
                            description=analysis.get("page_description", ""),
                            features=analysis.get("discovered_features", []),
                            discovered_at=datetime.now().isoformat()
                        )
                        module.screenshot_base64 = await self.session.capture_screenshot(f"Module: {module.name}")
                        self.session.modules[module.id] = module
                        self.session.stats["modules_discovered"] += 1

                        await self.session.emit_event(
                            ScanEventType.MODULE_DISCOVERED,
                            f"Discovered module: {module.name}",
                            {"id": module.id, "name": module.name, "url": module.url},
                            module.screenshot_base64
                        )

            elif action_type == "navigate" and target:
                try:
                    full_url = urljoin(self.session.url, target) if not target.startswith('http') else target
                    if is_safe_url(full_url) and self.session.base_domain in full_url:
                        await self.session.page.goto(full_url, wait_until="networkidle", timeout=15000)
                        self.session.visited_urls.add(full_url)
                        self.session.stats["pages_visited"] += 1
                except:
                    pass

            exploration_count += 1

            # Update progress
            self.session.progress = 25 + int((exploration_count / max_explorations) * 30)

            # Emit stats
            await self.session.emit_event(
                ScanEventType.STATS_UPDATE,
                f"Exploration progress: {exploration_count}/{max_explorations}",
                self.session.stats
            )

            await asyncio.sleep(0.5)

        # Complete journey
        journey.status = "completed"
        journey.completed_at = datetime.now().isoformat()
        self.session.stats["journeys_completed"] += 1

        await self.session.emit_event(
            ScanEventType.JOURNEY_COMPLETED,
            f"Application Discovery completed: {len(self.session.modules)} modules found",
            {"journey_id": journey.id, "modules_found": len(self.session.modules)},
            await self.session.capture_screenshot("Exploration Complete")
        )

        self.session.current_journey = None

    async def _phase_api_testing(self):
        """Test discovered APIs for security vulnerabilities."""
        self.session.phase = "api_testing"
        self.session.progress = 60

        await self.session.emit_event(
            ScanEventType.PHASE_CHANGED,
            f"Phase 5: API Security Testing ({len(self.captured_requests)} endpoints)",
            {"phase": "api_testing", "progress": 60, "api_count": len(self.captured_requests)}
        )

        # Deduplicate APIs by path
        unique_apis = {}
        for req in self.captured_requests:
            path = req.get("path", "")
            if path not in unique_apis:
                unique_apis[path] = req

        await self.session.emit_event(
            ScanEventType.CONTEXT_NOTE,
            f"Testing {len(unique_apis)} unique API endpoints",
            {"unique_apis": len(unique_apis)}
        )

        tested = 0
        for path, api in list(unique_apis.items())[:30]:  # Test up to 30 APIs
            await self.session.emit_event(
                ScanEventType.API_ANALYZED,
                f"Analyzing: {api['method']} {path}",
                {"method": api["method"], "path": path}
            )

            # Get AI test strategy
            api_obj = DiscoveredAPI(
                id=f"api_{uuid.uuid4().hex[:8]}",
                method=api["method"],
                url=api["url"],
                path=path,
                host=urlparse(api["url"]).netloc,
                params={},
                request_headers=api.get("headers", {}),
                request_body=api.get("post_data"),
                response_status=200,
                response_headers={},
                response_body_sample=None,
                content_type=api.get("headers", {}).get("content-type", ""),
                auth_required=False,
                test_strategy=[],
                vulnerabilities_found=[],
                timestamp=api["timestamp"]
            )

            # Run security header checks
            findings = await self.security_tester.run_header_checks(
                api.get("headers", {}),
                api["url"]
            )

            for finding in findings:
                self.session.findings.append(finding)
                await self.session.emit_event(
                    ScanEventType.FINDING_DETECTED,
                    f"Finding: {finding['title']}",
                    finding
                )

            self.session.apis[api_obj.id] = api_obj
            tested += 1

            # Update progress
            self.session.progress = 60 + int((tested / len(unique_apis)) * 15)

            await asyncio.sleep(0.2)

    async def _phase_form_testing(self):
        """Test forms for XSS and input validation issues."""
        self.session.phase = "form_testing"
        self.session.progress = 75

        await self.session.emit_event(
            ScanEventType.PHASE_CHANGED,
            "Phase 6: Form and Input Security Testing",
            {"phase": "form_testing", "progress": 75}
        )

        # Find all forms
        try:
            forms = await self.session.page.locator('form').all()

            await self.session.emit_event(
                ScanEventType.CONTEXT_NOTE,
                f"Found {len(forms)} forms to test",
                {"form_count": len(forms)}
            )

            for i, form in enumerate(forms[:10]):
                try:
                    form_id = await form.get_attribute('id') or f"form_{i}"

                    await self.session.emit_event(
                        ScanEventType.SECURITY_TEST_STARTED,
                        f"Testing form: {form_id}",
                        {"form_id": form_id, "test": "xss"}
                    )

                    # Test XSS
                    xss_findings = await self.security_tester.test_xss(self.session.page, f'form#{form_id}' if form_id != f"form_{i}" else 'form')

                    for finding in xss_findings:
                        self.session.findings.append(finding)
                        self.session.stats["vulnerabilities_found"] += 1

                        await self.session.emit_event(
                            ScanEventType.VULNERABILITY_FOUND,
                            f"Vulnerability: {finding['title']}",
                            finding
                        )
                except:
                    continue
        except:
            pass

        # Check password fields
        try:
            password_fields = await self.session.page.locator('input[type="password"]').all()
            for field in password_fields:
                autocomplete = await field.get_attribute('autocomplete')
                if autocomplete not in ['off', 'new-password']:
                    finding = {
                        "id": f"FORM-{len(self.session.findings)+1}",
                        "title": "Password Autocomplete Enabled",
                        "severity": "low",
                        "cwe": "CWE-522",
                        "url": self.session.page.url,
                        "evidence": "Password field allows autocomplete"
                    }
                    self.session.findings.append(finding)

                    await self.session.emit_event(
                        ScanEventType.FINDING_DETECTED,
                        f"Finding: {finding['title']}",
                        finding
                    )
        except:
            pass

    async def _phase_finalize(self):
        """Generate final report and complete scan."""
        self.session.phase = "finalizing"
        self.session.progress = 95

        await self.session.emit_event(
            ScanEventType.PHASE_CHANGED,
            "Phase 7: Generating comprehensive security report",
            {"phase": "finalize", "progress": 95}
        )

        # Deduplicate findings
        unique_findings = {}
        for f in self.session.findings:
            key = f"{f.get('title')}_{f.get('url', '')}"
            if key not in unique_findings:
                unique_findings[key] = f

        self.session.findings = list(unique_findings.values())

        # Calculate summary
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.session.findings:
            sev = f.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

        elapsed_minutes = (datetime.now() - self.start_time).total_seconds() / 60

        self.session.status = "completed"
        self.session.completed_at = datetime.now().isoformat()
        self.session.progress = 100

        await self.session.emit_event(
            ScanEventType.SCAN_COMPLETE,
            f"Deep scan completed: {len(self.session.findings)} findings in {elapsed_minutes:.1f} minutes",
            {
                "stats": self.session.stats,
                "findings_count": len(self.session.findings),
                "severity_counts": severity_counts,
                "duration_minutes": elapsed_minutes,
                "modules_discovered": len(self.session.modules),
                "journeys_completed": len(self.session.journeys),
                "apis_tested": len(self.session.apis)
            },
            await self.session.capture_screenshot("Scan Complete")
        )

    async def _detect_login_form(self) -> bool:
        """Detect if current page has a login form."""
        try:
            password_count = await self.session.page.locator('input[type="password"]').count()
            return password_count > 0
        except:
            return False

    async def _cleanup(self):
        """Clean up resources."""
        try:
            if self.session.page:
                await self.session.page.close()
            if self.session.context:
                await self.session.context.close()
            if self.session.browser:
                await self.session.browser.close()
            if self.playwright:
                await self.playwright.stop()
        except:
            pass


# Global session storage
live_scan_sessions: Dict[str, LiveScanSession] = {}


def create_live_scan(url: str) -> LiveScanSession:
    """Create a new live scan session."""
    scan_id = f"live_{uuid.uuid4().hex[:12]}"
    session = LiveScanSession(scan_id, url)
    live_scan_sessions[scan_id] = session
    return session


def get_live_scan(scan_id: str) -> Optional[LiveScanSession]:
    """Get a live scan session."""
    return live_scan_sessions.get(scan_id)


async def run_deep_scan(session: LiveScanSession):
    """Run a deep exploratory scan."""
    scanner = DeepExploratoryScanner(session)
    await scanner.run()


# Backward compatibility
LiveScanner = DeepExploratoryScanner
