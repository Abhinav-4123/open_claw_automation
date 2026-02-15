"""
NEXUS QA - Explorer Agent
Deep crawling agent that maps user journeys by exploring the web application.
"""

import asyncio
import base64
import logging
import re
from collections import deque
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

from playwright.async_api import async_playwright, Browser, Page, ElementHandle

from .base import BaseAgent, TaskContext, AgentResult

logger = logging.getLogger(__name__)


class ExplorerAgent(BaseAgent):
    """
    Explorer Agent - Deep crawls and maps user journeys.

    Phase 2 responsibilities:
    - BFS crawl of all internal links
    - Form discovery and classification
    - Interactive element detection
    - State machine building
    - Journey recording
    """

    agent_type = "explorer"

    # Journey patterns to detect
    JOURNEY_PATTERNS = {
        "authentication": {
            "keywords": ["login", "signin", "sign-in", "log-in", "authenticate"],
            "forms": ["login", "signin"],
            "priority": "critical"
        },
        "registration": {
            "keywords": ["signup", "register", "sign-up", "create-account", "join"],
            "forms": ["signup", "register", "registration"],
            "priority": "critical"
        },
        "password_reset": {
            "keywords": ["forgot", "reset", "recover", "password"],
            "forms": ["forgot", "reset", "recover"],
            "priority": "high"
        },
        "checkout": {
            "keywords": ["checkout", "cart", "payment", "order", "purchase", "buy"],
            "forms": ["checkout", "payment", "billing"],
            "priority": "critical"
        },
        "profile": {
            "keywords": ["profile", "account", "settings", "preferences"],
            "forms": ["profile", "settings", "account"],
            "priority": "medium"
        },
        "search": {
            "keywords": ["search", "find", "query"],
            "forms": ["search"],
            "priority": "medium"
        },
        "contact": {
            "keywords": ["contact", "support", "help", "feedback"],
            "forms": ["contact", "feedback", "support"],
            "priority": "low"
        },
        "subscription": {
            "keywords": ["subscribe", "newsletter", "pricing", "plan"],
            "forms": ["subscribe", "newsletter"],
            "priority": "medium"
        }
    }

    def __init__(self, max_depth: int = 3, max_pages: int = 50):
        super().__init__()
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited_urls: Set[str] = set()
        self.discovered_pages: List[Dict] = []
        self.discovered_forms: List[Dict] = []
        self.discovered_journeys: List[Dict] = []
        self.browser: Optional[Browser] = None

    async def execute(self, context: TaskContext) -> AgentResult:
        """Execute deep exploration of the web application."""
        start_time = datetime.now()
        url = context.url
        base_domain = urlparse(url).netloc

        try:
            await self.report_progress(5, "Launching browser for exploration")

            async with async_playwright() as p:
                self.browser = await p.chromium.launch(
                    headless=True,
                    args=['--no-sandbox', '--disable-setuid-sandbox']
                )

                page = await self.browser.new_page(
                    viewport={'width': 1920, 'height': 1080}
                )

                await self.report_progress(10, "Starting BFS crawl")

                # BFS crawl
                await self._bfs_crawl(page, url, base_domain)

                await self.report_progress(70, "Classifying user journeys")

                # Classify discovered pages/forms into journeys
                self._classify_journeys()

                await self.report_progress(90, "Generating exploration report")

                # Build result
                result = {
                    "url": url,
                    "pages_discovered": len(self.discovered_pages),
                    "forms_discovered": len(self.discovered_forms),
                    "journeys": self.discovered_journeys,
                    "pages": self.discovered_pages[:20],  # Top 20 pages
                    "forms": self.discovered_forms,
                    "sitemap": self._build_sitemap(),
                    "explored_at": datetime.now().isoformat()
                }

                await self.report_progress(100, "Exploration complete")
                await self.browser.close()

                duration = (datetime.now() - start_time).total_seconds()
                return AgentResult(
                    success=True,
                    data=result,
                    duration_seconds=duration
                )

        except Exception as e:
            logger.exception(f"Explorer Agent error: {e}")
            if self.browser:
                await self.browser.close()
            return AgentResult(
                success=False,
                error=str(e),
                partial=True,
                data={
                    "url": url,
                    "pages_discovered": len(self.discovered_pages),
                    "forms_discovered": len(self.discovered_forms),
                    "journeys": self.discovered_journeys,
                    "error": str(e)
                }
            )

    async def _bfs_crawl(self, page: Page, start_url: str, base_domain: str):
        """Breadth-first crawl of the website."""
        queue = deque([(start_url, 0)])  # (url, depth)
        self.visited_urls = set()

        while queue and len(self.visited_urls) < self.max_pages:
            url, depth = queue.popleft()

            if url in self.visited_urls or depth > self.max_depth:
                continue

            # Check same domain
            if urlparse(url).netloc != base_domain:
                continue

            self.visited_urls.add(url)

            # Update progress
            progress = 10 + (len(self.visited_urls) / self.max_pages) * 50
            await self.report_progress(progress, f"Crawling: {url[:50]}...")

            try:
                page_info = await self._explore_page(page, url, depth)
                if page_info:
                    self.discovered_pages.append(page_info)

                    # Add discovered links to queue
                    for link in page_info.get("internal_links", []):
                        if link not in self.visited_urls:
                            queue.append((link, depth + 1))

            except Exception as e:
                logger.warning(f"Failed to explore {url}: {e}")
                continue

    async def _explore_page(self, page: Page, url: str, depth: int) -> Optional[Dict]:
        """Explore a single page and extract information."""
        try:
            await page.goto(url, wait_until='domcontentloaded', timeout=15000)
            await asyncio.sleep(1)  # Brief wait for dynamic content

            # Extract page data
            page_data = await page.evaluate("""() => {
                const title = document.title || '';

                // Get all links
                const links = [...document.querySelectorAll('a[href]')].map(a => {
                    try {
                        const href = a.href;
                        const text = a.textContent?.trim().slice(0, 50) || '';
                        return { href, text };
                    } catch { return null; }
                }).filter(Boolean);

                // Get internal links
                const currentHost = window.location.hostname;
                const internalLinks = links.filter(l => {
                    try {
                        return new URL(l.href).hostname === currentHost;
                    } catch { return false; }
                }).map(l => l.href);

                // Get forms
                const forms = [...document.querySelectorAll('form')].map(f => ({
                    id: f.id,
                    action: f.action,
                    method: f.method?.toUpperCase() || 'GET',
                    inputs: [...f.querySelectorAll('input, textarea, select')].map(i => ({
                        type: i.type || 'text',
                        name: i.name,
                        id: i.id,
                        placeholder: i.placeholder,
                        required: i.required
                    }))
                }));

                // Get buttons
                const buttons = [...document.querySelectorAll('button, input[type="submit"], [role="button"]')]
                    .map(b => ({
                        text: b.textContent?.trim().slice(0, 50) || b.value || '',
                        type: b.type || 'button',
                        id: b.id
                    }));

                // Get interactive elements
                const interactiveCount = document.querySelectorAll(
                    'button, a, input, select, textarea, [onclick], [role="button"]'
                ).length;

                // Check for modals/dialogs
                const hasModals = document.querySelectorAll(
                    '[role="dialog"], .modal, [class*="modal"], [class*="popup"]'
                ).length > 0;

                return {
                    title,
                    links: links.slice(0, 100),
                    internalLinks: [...new Set(internalLinks)].slice(0, 50),
                    forms,
                    buttons: buttons.slice(0, 20),
                    interactiveCount,
                    hasModals,
                    hasLogin: !!document.querySelector('[type="password"]'),
                    hasCaptcha: !!document.querySelector('[class*="captcha"], [class*="recaptcha"]'),
                    bodyText: document.body?.innerText?.slice(0, 500) || ''
                };
            }""")

            # Take screenshot for journey documentation
            screenshot = None
            try:
                screenshot_bytes = await page.screenshot(type='png')
                screenshot = base64.b64encode(screenshot_bytes).decode()
            except:
                pass

            # Extract and store forms
            for form in page_data.get("forms", []):
                form_info = {
                    "url": url,
                    "page_title": page_data.get("title", ""),
                    **form,
                    "journey_type": self._classify_form(form, url)
                }
                self.discovered_forms.append(form_info)

            return {
                "url": url,
                "depth": depth,
                "title": page_data.get("title", ""),
                "internal_links": page_data.get("internalLinks", []),
                "forms_count": len(page_data.get("forms", [])),
                "buttons_count": len(page_data.get("buttons", [])),
                "interactive_elements": page_data.get("interactiveCount", 0),
                "has_login": page_data.get("hasLogin", False),
                "has_captcha": page_data.get("hasCaptcha", False),
                "has_modals": page_data.get("hasModals", False),
                "buttons": page_data.get("buttons", []),
                "screenshot": screenshot,
                "page_category": self._categorize_page(url, page_data)
            }

        except Exception as e:
            logger.debug(f"Page exploration error for {url}: {e}")
            return None

    def _classify_form(self, form: Dict, url: str) -> str:
        """Classify what type of form this is."""
        # Check form inputs
        input_types = [i.get("type", "").lower() for i in form.get("inputs", [])]
        input_names = [i.get("name", "").lower() for i in form.get("inputs", [])]
        input_placeholders = [i.get("placeholder", "").lower() for i in form.get("inputs", [])]

        all_text = " ".join(input_names + input_placeholders + [url.lower()])

        # Check for authentication
        if "password" in input_types:
            if any(k in all_text for k in ["signup", "register", "create", "join"]):
                return "registration"
            elif any(k in all_text for k in ["forgot", "reset", "recover"]):
                return "password_reset"
            else:
                return "authentication"

        # Check for search
        if any(k in all_text for k in ["search", "query", "find"]):
            return "search"

        # Check for contact/feedback
        if any(k in all_text for k in ["message", "contact", "feedback", "subject"]):
            return "contact"

        # Check for payment
        if any(k in all_text for k in ["card", "payment", "cvv", "billing"]):
            return "checkout"

        # Check for subscription
        if any(k in all_text for k in ["subscribe", "email", "newsletter"]):
            return "subscription"

        return "other"

    def _categorize_page(self, url: str, page_data: Dict) -> str:
        """Categorize the page type."""
        url_lower = url.lower()
        title_lower = page_data.get("title", "").lower()
        body_text = page_data.get("bodyText", "").lower()

        combined = f"{url_lower} {title_lower} {body_text}"

        for journey_type, patterns in self.JOURNEY_PATTERNS.items():
            if any(kw in combined for kw in patterns["keywords"]):
                return journey_type

        # Check for common page types
        if any(k in combined for k in ["dashboard", "admin", "panel"]):
            return "dashboard"
        if any(k in combined for k in ["about", "team", "company"]):
            return "about"
        if any(k in combined for k in ["blog", "news", "article"]):
            return "content"
        if any(k in combined for k in ["docs", "documentation", "api"]):
            return "documentation"
        if any(k in combined for k in ["pricing", "plans", "subscribe"]):
            return "pricing"

        return "general"

    def _classify_journeys(self):
        """Classify discovered pages and forms into user journeys."""
        journey_map: Dict[str, Dict] = {}

        # Group pages by category
        for page in self.discovered_pages:
            category = page.get("page_category", "general")
            if category not in journey_map:
                journey_map[category] = {
                    "id": f"journey_{category}",
                    "name": self._get_journey_name(category),
                    "type": category,
                    "priority": self._get_journey_priority(category),
                    "pages": [],
                    "forms": [],
                    "entry_points": [],
                    "requires_auth": False
                }

            journey_map[category]["pages"].append({
                "url": page.get("url"),
                "title": page.get("title"),
                "depth": page.get("depth")
            })

            if page.get("depth", 0) == 0 or len(journey_map[category]["entry_points"]) == 0:
                journey_map[category]["entry_points"].append(page.get("url"))

        # Add forms to journeys
        for form in self.discovered_forms:
            form_type = form.get("journey_type", "other")
            if form_type in journey_map:
                journey_map[form_type]["forms"].append(form)
                # Check if auth required (has password field in non-auth context)
                if form_type not in ["authentication", "registration"]:
                    if any(i.get("type") == "password" for i in form.get("inputs", [])):
                        journey_map[form_type]["requires_auth"] = True

        # Convert to list
        self.discovered_journeys = [
            {**j, "steps_count": len(j["pages"]) + len(j["forms"])}
            for j in journey_map.values()
            if j["pages"] or j["forms"]  # Only non-empty journeys
        ]

        # Sort by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        self.discovered_journeys.sort(
            key=lambda j: priority_order.get(j.get("priority", "low"), 3)
        )

    def _get_journey_name(self, category: str) -> str:
        """Get human-readable journey name."""
        names = {
            "authentication": "User Login Flow",
            "registration": "User Registration Flow",
            "password_reset": "Password Recovery Flow",
            "checkout": "Checkout/Payment Flow",
            "profile": "User Profile Management",
            "search": "Search Functionality",
            "contact": "Contact/Support Flow",
            "subscription": "Newsletter/Subscription Flow",
            "dashboard": "Dashboard Navigation",
            "pricing": "Pricing/Plans Exploration",
            "documentation": "Documentation Access",
            "general": "General Navigation"
        }
        return names.get(category, f"{category.title()} Flow")

    def _get_journey_priority(self, category: str) -> str:
        """Get journey priority for testing."""
        if category in self.JOURNEY_PATTERNS:
            return self.JOURNEY_PATTERNS[category]["priority"]

        priority_map = {
            "dashboard": "high",
            "pricing": "medium",
            "documentation": "low",
            "about": "low",
            "content": "low"
        }
        return priority_map.get(category, "low")

    def _build_sitemap(self) -> Dict:
        """Build a sitemap structure from discovered pages."""
        sitemap = {
            "root": urlparse(list(self.visited_urls)[0]).netloc if self.visited_urls else "",
            "total_pages": len(self.discovered_pages),
            "by_depth": {},
            "by_category": {}
        }

        for page in self.discovered_pages:
            depth = page.get("depth", 0)
            category = page.get("page_category", "general")

            # Group by depth
            if depth not in sitemap["by_depth"]:
                sitemap["by_depth"][depth] = []
            sitemap["by_depth"][depth].append(page.get("url"))

            # Group by category
            if category not in sitemap["by_category"]:
                sitemap["by_category"][category] = []
            sitemap["by_category"][category].append(page.get("url"))

        return sitemap
