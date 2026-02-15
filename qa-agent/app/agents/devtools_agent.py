"""
NEXUS QA - DevTools Agent
Monitors network traffic, APIs, WebSockets, and callbacks using CDP.
"""

import asyncio
import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse, parse_qs

from playwright.async_api import async_playwright, Browser, Page, CDPSession

from .base import BaseAgent, TaskContext, AgentResult

logger = logging.getLogger(__name__)


class DevToolsAgent(BaseAgent):
    """
    DevTools Agent - Monitors all network activity and analyzes APIs.

    Phase 2 responsibilities (parallel with Explorer):
    - Open CDP (Chrome DevTools Protocol)
    - Monitor Network tab
    - Log all API calls
    - Detect WebSocket connections
    - Identify callback patterns
    - Monitor localStorage/sessionStorage
    - Analyze request/response patterns
    """

    agent_type = "devtools"

    # Known API patterns
    API_PATTERNS = [
        r'/api/',
        r'/v\d+/',
        r'/graphql',
        r'/rest/',
        r'\.json$',
        r'/ajax/',
        r'/xhr/',
    ]

    # Sensitive data patterns
    SENSITIVE_PATTERNS = {
        'auth_token': r'(bearer|token|jwt|auth)["\s:=]+["\']?([a-zA-Z0-9_-]{20,})',
        'api_key': r'(api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_-]{16,})',
        'password': r'(password|passwd|pwd)["\s:=]+["\']?([^"\'&\s]{4,})',
        'session': r'(session[_-]?id|sid)["\s:=]+["\']?([a-zA-Z0-9_-]{16,})',
    }

    def __init__(self, capture_duration: int = 30):
        super().__init__()
        self.capture_duration = capture_duration
        self.api_calls: List[Dict] = []
        self.websocket_connections: List[Dict] = []
        self.storage_data: Dict[str, Any] = {}
        self.cookies: List[Dict] = []
        self.sensitive_findings: List[Dict] = []
        self.browser: Optional[Browser] = None

    async def execute(self, context: TaskContext) -> AgentResult:
        """Monitor network traffic and analyze APIs."""
        start_time = datetime.now()
        url = context.url

        try:
            await self.report_progress(5, "Launching browser with DevTools")

            async with async_playwright() as p:
                self.browser = await p.chromium.launch(
                    headless=True,
                    args=['--no-sandbox', '--disable-setuid-sandbox']
                )

                browser_context = await self.browser.new_context(
                    viewport={'width': 1920, 'height': 1080}
                )

                page = await browser_context.new_page()

                await self.report_progress(10, "Setting up CDP listeners")

                # Set up CDP session for network monitoring
                cdp = await page.context.new_cdp_session(page)

                # Enable network monitoring
                await cdp.send('Network.enable')
                await cdp.send('Runtime.enable')

                # Set up event listeners
                cdp.on('Network.requestWillBeSent', lambda e: asyncio.create_task(
                    self._handle_request(e)
                ))
                cdp.on('Network.responseReceived', lambda e: asyncio.create_task(
                    self._handle_response(e, cdp)
                ))
                cdp.on('Network.webSocketCreated', lambda e: asyncio.create_task(
                    self._handle_websocket_created(e)
                ))
                cdp.on('Network.webSocketFrameReceived', lambda e: asyncio.create_task(
                    self._handle_websocket_message(e, 'received')
                ))
                cdp.on('Network.webSocketFrameSent', lambda e: asyncio.create_task(
                    self._handle_websocket_message(e, 'sent')
                ))

                await self.report_progress(20, "Navigating and capturing traffic")

                # Navigate to page
                try:
                    await page.goto(url, wait_until='networkidle', timeout=30000)
                except:
                    await page.goto(url, wait_until='domcontentloaded', timeout=30000)

                await self.report_progress(40, "Interacting with page to trigger APIs")

                # Interact with page to trigger more API calls
                await self._interact_with_page(page)

                await self.report_progress(60, "Capturing storage data")

                # Capture storage data
                self.storage_data = await self._capture_storage(page)

                # Capture cookies
                self.cookies = await browser_context.cookies()

                await self.report_progress(70, "Analyzing captured data")

                # Wait a bit more to capture any delayed requests
                await asyncio.sleep(3)

                # Analyze patterns
                api_analysis = self._analyze_apis()
                security_analysis = self._analyze_security()

                await self.report_progress(90, "Building API inventory")

                # Build result
                result = {
                    "url": url,
                    "apis": api_analysis["endpoints"],
                    "api_summary": api_analysis["summary"],
                    "websockets": self.websocket_connections,
                    "storage": self.storage_data,
                    "cookies_analysis": self._analyze_cookies(),
                    "sensitive_findings": self.sensitive_findings,
                    "security_concerns": security_analysis,
                    "total_requests": len(self.api_calls),
                    "captured_at": datetime.now().isoformat()
                }

                await self.report_progress(100, "DevTools analysis complete")
                await self.browser.close()

                duration = (datetime.now() - start_time).total_seconds()
                return AgentResult(
                    success=True,
                    data=result,
                    duration_seconds=duration
                )

        except Exception as e:
            logger.exception(f"DevTools Agent error: {e}")
            if self.browser:
                await self.browser.close()
            return AgentResult(
                success=False,
                error=str(e),
                partial=True,
                data={
                    "url": url,
                    "apis": self._analyze_apis()["endpoints"],
                    "total_requests": len(self.api_calls),
                    "error": str(e)
                }
            )

    async def _handle_request(self, event: Dict):
        """Handle outgoing network request."""
        request = event.get('request', {})
        request_id = event.get('requestId', '')

        call_info = {
            "request_id": request_id,
            "url": request.get('url', ''),
            "method": request.get('method', 'GET'),
            "headers": request.get('headers', {}),
            "post_data": request.get('postData', ''),
            "timestamp": datetime.now().isoformat(),
            "type": event.get('type', 'Other'),
            "initiator": event.get('initiator', {}).get('type', 'unknown')
        }

        # Check if this is an API call
        url = call_info["url"]
        is_api = any(re.search(pattern, url) for pattern in self.API_PATTERNS)
        call_info["is_api"] = is_api

        # Check for sensitive data in request
        self._check_sensitive_data(call_info, "request")

        self.api_calls.append(call_info)

    async def _handle_response(self, event: Dict, cdp: CDPSession):
        """Handle network response."""
        response = event.get('response', {})
        request_id = event.get('requestId', '')

        # Find matching request
        for call in self.api_calls:
            if call.get('request_id') == request_id:
                call['response_status'] = response.get('status', 0)
                call['response_headers'] = response.get('headers', {})
                call['response_mime_type'] = response.get('mimeType', '')

                # Try to get response body for API calls
                if call.get('is_api'):
                    try:
                        body_result = await cdp.send(
                            'Network.getResponseBody',
                            {'requestId': request_id}
                        )
                        body = body_result.get('body', '')
                        call['response_body'] = body[:2000]  # Limit size
                        call['response_body_truncated'] = len(body) > 2000

                        # Check for sensitive data in response
                        self._check_sensitive_data(
                            {"body": body, "url": call["url"]},
                            "response"
                        )
                    except:
                        pass
                break

    async def _handle_websocket_created(self, event: Dict):
        """Handle WebSocket connection creation."""
        self.websocket_connections.append({
            "url": event.get('url', ''),
            "request_id": event.get('requestId', ''),
            "timestamp": datetime.now().isoformat(),
            "messages": []
        })

    async def _handle_websocket_message(self, event: Dict, direction: str):
        """Handle WebSocket message."""
        request_id = event.get('requestId', '')
        payload = event.get('response', {}).get('payloadData', '')

        for ws in self.websocket_connections:
            if ws.get('request_id') == request_id:
                ws['messages'].append({
                    "direction": direction,
                    "data": payload[:500],  # Limit size
                    "timestamp": datetime.now().isoformat()
                })
                break

    async def _interact_with_page(self, page: Page):
        """Interact with page to trigger API calls."""
        try:
            # Scroll to trigger lazy loading
            await page.evaluate("""() => {
                window.scrollTo(0, document.body.scrollHeight / 2);
            }""")
            await asyncio.sleep(1)

            await page.evaluate("""() => {
                window.scrollTo(0, document.body.scrollHeight);
            }""")
            await asyncio.sleep(1)

            # Click any "load more" buttons
            load_more = await page.query_selector(
                'button:has-text("load more"), button:has-text("show more"), '
                '[class*="load-more"], [class*="show-more"]'
            )
            if load_more:
                try:
                    await load_more.click()
                    await asyncio.sleep(2)
                except:
                    pass

            # Hover over navigation to trigger dropdowns
            nav_items = await page.query_selector_all('nav a, header a')
            for item in nav_items[:5]:  # First 5 nav items
                try:
                    await item.hover()
                    await asyncio.sleep(0.3)
                except:
                    pass

        except Exception as e:
            logger.debug(f"Interaction error: {e}")

    async def _capture_storage(self, page: Page) -> Dict[str, Any]:
        """Capture localStorage and sessionStorage."""
        try:
            storage = await page.evaluate("""() => {
                const local = {};
                const session = {};

                try {
                    for (let i = 0; i < localStorage.length; i++) {
                        const key = localStorage.key(i);
                        local[key] = localStorage.getItem(key)?.slice(0, 500);
                    }
                } catch(e) {}

                try {
                    for (let i = 0; i < sessionStorage.length; i++) {
                        const key = sessionStorage.key(i);
                        session[key] = sessionStorage.getItem(key)?.slice(0, 500);
                    }
                } catch(e) {}

                return { localStorage: local, sessionStorage: session };
            }""")
            return storage
        except:
            return {"localStorage": {}, "sessionStorage": {}}

    def _check_sensitive_data(self, data: Dict, context: str):
        """Check for sensitive data in requests/responses."""
        content = json.dumps(data, default=str).lower()

        for data_type, pattern in self.SENSITIVE_PATTERNS.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                self.sensitive_findings.append({
                    "type": data_type,
                    "context": context,
                    "url": data.get("url", "unknown"),
                    "matches_count": len(matches),
                    "timestamp": datetime.now().isoformat()
                })

    def _analyze_apis(self) -> Dict[str, Any]:
        """Analyze captured API calls."""
        api_endpoints: Dict[str, Dict] = {}

        for call in self.api_calls:
            if not call.get("is_api"):
                continue

            url = call.get("url", "")
            parsed = urlparse(url)

            # Normalize path (replace IDs with placeholder)
            path = re.sub(r'/\d+', '/{id}', parsed.path)
            path = re.sub(r'/[a-f0-9-]{36}', '/{uuid}', path)

            endpoint_key = f"{call.get('method', 'GET')} {parsed.netloc}{path}"

            if endpoint_key not in api_endpoints:
                api_endpoints[endpoint_key] = {
                    "method": call.get("method", "GET"),
                    "path": path,
                    "host": parsed.netloc,
                    "full_url_example": url,
                    "query_params": list(parse_qs(parsed.query).keys()),
                    "request_headers": list(call.get("headers", {}).keys()),
                    "response_statuses": [],
                    "content_types": [],
                    "call_count": 0,
                    "has_auth": False,
                    "sample_response": None
                }

            endpoint = api_endpoints[endpoint_key]
            endpoint["call_count"] += 1

            # Track response statuses
            status = call.get("response_status")
            if status and status not in endpoint["response_statuses"]:
                endpoint["response_statuses"].append(status)

            # Track content types
            mime = call.get("response_mime_type", "")
            if mime and mime not in endpoint["content_types"]:
                endpoint["content_types"].append(mime)

            # Check for auth headers
            headers = call.get("headers", {})
            if any(h.lower() in ["authorization", "x-api-key", "x-auth-token"]
                   for h in headers.keys()):
                endpoint["has_auth"] = True

            # Store sample response
            if not endpoint["sample_response"] and call.get("response_body"):
                endpoint["sample_response"] = call["response_body"][:500]

        # Build summary
        endpoints_list = list(api_endpoints.values())

        return {
            "endpoints": endpoints_list,
            "summary": {
                "total_endpoints": len(endpoints_list),
                "authenticated_endpoints": sum(1 for e in endpoints_list if e["has_auth"]),
                "methods": list(set(e["method"] for e in endpoints_list)),
                "hosts": list(set(e["host"] for e in endpoints_list))
            }
        }

    def _analyze_cookies(self) -> Dict[str, Any]:
        """Analyze captured cookies for security."""
        analysis = {
            "total": len(self.cookies),
            "secure": 0,
            "http_only": 0,
            "same_site_strict": 0,
            "same_site_lax": 0,
            "same_site_none": 0,
            "session_cookies": 0,
            "persistent_cookies": 0,
            "issues": []
        }

        for cookie in self.cookies:
            if cookie.get("secure"):
                analysis["secure"] += 1
            else:
                analysis["issues"].append(f"Cookie '{cookie.get('name')}' missing Secure flag")

            if cookie.get("httpOnly"):
                analysis["http_only"] += 1
            else:
                analysis["issues"].append(f"Cookie '{cookie.get('name')}' missing HttpOnly flag")

            same_site = cookie.get("sameSite", "").lower()
            if same_site == "strict":
                analysis["same_site_strict"] += 1
            elif same_site == "lax":
                analysis["same_site_lax"] += 1
            elif same_site == "none":
                analysis["same_site_none"] += 1

            if cookie.get("expires", -1) == -1:
                analysis["session_cookies"] += 1
            else:
                analysis["persistent_cookies"] += 1

        return analysis

    def _analyze_security(self) -> List[Dict]:
        """Analyze security concerns in API calls."""
        concerns = []

        # Check for sensitive data in URLs
        for call in self.api_calls:
            url = call.get("url", "")

            # Check for tokens/keys in URL
            if re.search(r'[?&](token|key|api_key|auth|password)=', url, re.I):
                concerns.append({
                    "type": "sensitive_data_in_url",
                    "severity": "high",
                    "url": url[:100],
                    "description": "Sensitive parameter in URL query string"
                })

            # Check for HTTP (not HTTPS)
            if url.startswith("http://") and "localhost" not in url:
                concerns.append({
                    "type": "insecure_transport",
                    "severity": "high",
                    "url": url[:100],
                    "description": "API call over HTTP instead of HTTPS"
                })

        # Check for CORS issues
        for call in self.api_calls:
            response_headers = call.get("response_headers", {})
            acao = response_headers.get("access-control-allow-origin", "")
            if acao == "*":
                concerns.append({
                    "type": "cors_wildcard",
                    "severity": "medium",
                    "url": call.get("url", "")[:100],
                    "description": "CORS allows any origin (*)"
                })

        # Check for verbose errors
        for call in self.api_calls:
            body = call.get("response_body", "").lower()
            if call.get("response_status", 0) >= 400:
                if any(kw in body for kw in ["stack trace", "exception", "error at", "traceback"]):
                    concerns.append({
                        "type": "verbose_error",
                        "severity": "medium",
                        "url": call.get("url", "")[:100],
                        "description": "Verbose error message may leak implementation details"
                    })

        return concerns[:20]  # Limit to 20 concerns
