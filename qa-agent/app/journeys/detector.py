"""
NEXUS QA - Journey Detector
Automatically detect user journeys from web applications using crawling and LLM analysis.
"""

import asyncio
import aiohttp
import re
import json
from datetime import datetime
from typing import List, Dict, Optional, Any, Set
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin
import uuid

from .mapper import JourneyMapper, JOURNEY_TEMPLATES


@dataclass
class DetectedStep:
    """A detected step in a user journey."""
    id: str
    name: str
    url: str
    action_type: str  # navigate, click, form_submit, input
    element_selector: Optional[str] = None
    input_type: Optional[str] = None  # text, password, email, etc.
    is_required: bool = False
    order: int = 0


@dataclass
class DetectedJourney:
    """A detected user journey."""
    journey_id: str
    name: str
    category: str
    description: str
    url: str
    steps: List[DetectedStep]
    confidence: float  # 0-1 confidence score
    detected_at: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "journey_id": self.journey_id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "url": self.url,
            "steps": [
                {
                    "id": s.id,
                    "name": s.name,
                    "url": s.url,
                    "action_type": s.action_type,
                    "element_selector": s.element_selector,
                    "input_type": s.input_type,
                    "is_required": s.is_required,
                    "order": s.order
                }
                for s in self.steps
            ],
            "confidence": self.confidence,
            "detected_at": self.detected_at.isoformat()
        }


class JourneyDetector:
    """
    Detect user journeys from web applications.

    Categories:
    - Authentication & Onboarding (login, signup, password reset)
    - Dashboard & Analytics (view, filter, export)
    - Project Management (create, tasks, collaboration)
    - Payments & Billing (checkout, subscriptions)
    - User Profile & Settings (update, preferences)
    - Public API & Webhooks (keys, integrations)
    """

    # Patterns for detecting different journey types
    JOURNEY_PATTERNS = {
        "authentication": {
            "login": [
                r'login', r'signin', r'sign-in', r'sign_in',
                r'authenticate', r'auth'
            ],
            "signup": [
                r'signup', r'sign-up', r'sign_up', r'register',
                r'create.?account', r'join'
            ],
            "password_reset": [
                r'forgot.?password', r'reset.?password',
                r'recover', r'password.?recovery'
            ],
            "logout": [
                r'logout', r'signout', r'sign-out', r'sign_out'
            ],
            "mfa": [
                r'2fa', r'two.?factor', r'mfa', r'verification',
                r'authenticator', r'otp'
            ]
        },
        "profile": {
            "view_profile": [
                r'profile', r'account', r'my.?account', r'settings'
            ],
            "edit_profile": [
                r'edit.?profile', r'update.?profile', r'settings'
            ],
            "change_password": [
                r'change.?password', r'update.?password'
            ],
            "preferences": [
                r'preferences', r'notifications', r'privacy'
            ]
        },
        "payments": {
            "checkout": [
                r'checkout', r'cart', r'basket', r'order'
            ],
            "payment": [
                r'payment', r'pay', r'billing', r'purchase'
            ],
            "subscription": [
                r'subscription', r'plan', r'pricing', r'upgrade'
            ]
        },
        "dashboard": {
            "overview": [
                r'dashboard', r'overview', r'home', r'main'
            ],
            "analytics": [
                r'analytics', r'stats', r'statistics', r'reports'
            ],
            "export": [
                r'export', r'download', r'csv', r'pdf'
            ]
        },
        "content": {
            "create": [
                r'create', r'new', r'add', r'compose'
            ],
            "edit": [
                r'edit', r'modify', r'update'
            ],
            "delete": [
                r'delete', r'remove', r'trash'
            ],
            "list": [
                r'list', r'all', r'browse', r'search'
            ]
        },
        "api": {
            "api_keys": [
                r'api.?key', r'access.?token', r'credentials'
            ],
            "webhooks": [
                r'webhook', r'integration', r'connect'
            ],
            "documentation": [
                r'docs', r'documentation', r'api.?reference'
            ]
        }
    }

    # Form field patterns
    FORM_PATTERNS = {
        "email": [r'email', r'e-mail', r'mail'],
        "password": [r'password', r'passwd', r'pwd'],
        "username": [r'username', r'user', r'login'],
        "name": [r'name', r'fullname', r'first.?name', r'last.?name'],
        "phone": [r'phone', r'mobile', r'tel'],
        "address": [r'address', r'street', r'city', r'zip', r'postal'],
        "card": [r'card', r'credit', r'payment', r'cvv', r'expiry'],
        "search": [r'search', r'query', r'q'],
    }

    def __init__(self, max_depth: int = 3, timeout: int = 30):
        self.max_depth = max_depth
        self.timeout = timeout
        self.mapper = JourneyMapper()
        self._visited_urls: Set[str] = set()

    async def detect(self, url: str) -> List[DetectedJourney]:
        """
        Detect user journeys from a URL.

        Args:
            url: The URL to analyze

        Returns:
            List of detected journeys
        """
        self._visited_urls.clear()
        journeys = []

        # Fetch and analyze the page
        page_data = await self._fetch_page(url)
        if not page_data:
            return journeys

        # Detect journeys from the page
        detected = await self._analyze_page(url, page_data)
        journeys.extend(detected)

        # Crawl linked pages (up to max_depth)
        await self._crawl_for_journeys(url, page_data, journeys, depth=1)

        # Deduplicate and merge similar journeys
        journeys = self._merge_journeys(journeys)

        return journeys

    async def _fetch_page(self, url: str) -> Optional[Dict[str, Any]]:
        """Fetch a page and extract relevant data."""
        if url in self._visited_urls:
            return None

        self._visited_urls.add(url)

        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout)
            ) as session:
                async with session.get(url, ssl=False) as response:
                    if response.status != 200:
                        return None

                    html = await response.text()

                    return {
                        "url": str(response.url),
                        "html": html,
                        "title": self._extract_title(html),
                        "links": self._extract_links(html, str(response.url)),
                        "forms": self._extract_forms(html),
                        "buttons": self._extract_buttons(html),
                        "nav_items": self._extract_nav(html),
                    }
        except Exception as e:
            print(f"Error fetching {url}: {e}")
            return None

    def _extract_title(self, html: str) -> str:
        """Extract page title."""
        match = re.search(r'<title>([^<]+)</title>', html, re.IGNORECASE)
        return match.group(1).strip() if match else ""

    def _extract_links(self, html: str, base_url: str) -> List[Dict[str, str]]:
        """Extract links from HTML."""
        links = []
        parsed_base = urlparse(base_url)

        for match in re.finditer(r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>([^<]*)</a>', html, re.IGNORECASE):
            href = match.group(1)
            text = match.group(2).strip()

            # Normalize URL
            if href.startswith('/'):
                href = f"{parsed_base.scheme}://{parsed_base.netloc}{href}"
            elif not href.startswith('http'):
                href = urljoin(base_url, href)

            # Only include same-domain links
            if urlparse(href).netloc == parsed_base.netloc:
                links.append({"url": href, "text": text})

        return links

    def _extract_forms(self, html: str) -> List[Dict[str, Any]]:
        """Extract forms and their fields."""
        forms = []

        for form_match in re.finditer(r'<form[^>]*>(.*?)</form>', html, re.IGNORECASE | re.DOTALL):
            form_html = form_match.group(0)

            # Extract form attributes
            action = re.search(r'action=["\']([^"\']+)["\']', form_html)
            method = re.search(r'method=["\']([^"\']+)["\']', form_html)
            form_id = re.search(r'id=["\']([^"\']+)["\']', form_html)

            # Extract input fields
            inputs = []
            for input_match in re.finditer(
                r'<input[^>]*(?:type=["\']([^"\']+)["\'])?[^>]*(?:name=["\']([^"\']+)["\'])?[^>]*>',
                form_html, re.IGNORECASE
            ):
                input_type = input_match.group(1) or "text"
                input_name = input_match.group(2) or ""

                if input_name:
                    inputs.append({
                        "type": input_type.lower(),
                        "name": input_name,
                        "field_type": self._classify_field(input_name)
                    })

            # Extract submit buttons
            submit_text = ""
            submit_match = re.search(r'<(?:button|input)[^>]*type=["\']submit["\'][^>]*>([^<]*)', form_html)
            if submit_match:
                submit_text = submit_match.group(1).strip()

            forms.append({
                "action": action.group(1) if action else "",
                "method": (method.group(1) if method else "GET").upper(),
                "id": form_id.group(1) if form_id else "",
                "inputs": inputs,
                "submit_text": submit_text,
                "form_type": self._classify_form(inputs)
            })

        return forms

    def _extract_buttons(self, html: str) -> List[Dict[str, str]]:
        """Extract buttons and clickable elements."""
        buttons = []

        for match in re.finditer(r'<button[^>]*>([^<]*)</button>', html, re.IGNORECASE):
            text = match.group(1).strip()
            if text:
                buttons.append({"text": text, "type": "button"})

        # Also look for link-styled buttons
        for match in re.finditer(r'<a[^>]*class=["\'][^"\']*btn[^"\']*["\'][^>]*>([^<]*)</a>', html, re.IGNORECASE):
            text = match.group(1).strip()
            if text:
                buttons.append({"text": text, "type": "link_button"})

        return buttons

    def _extract_nav(self, html: str) -> List[str]:
        """Extract navigation items."""
        nav_items = []

        nav_match = re.search(r'<nav[^>]*>(.*?)</nav>', html, re.IGNORECASE | re.DOTALL)
        if nav_match:
            for link_match in re.finditer(r'<a[^>]*>([^<]+)</a>', nav_match.group(1)):
                text = link_match.group(1).strip()
                if text:
                    nav_items.append(text)

        return nav_items

    def _classify_field(self, field_name: str) -> str:
        """Classify a form field based on its name."""
        field_lower = field_name.lower()

        for field_type, patterns in self.FORM_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, field_lower):
                    return field_type

        return "unknown"

    def _classify_form(self, inputs: List[Dict]) -> str:
        """Classify a form based on its inputs."""
        field_types = [i["field_type"] for i in inputs]

        if "password" in field_types and "email" in field_types:
            if len(inputs) <= 3:
                return "login"
            return "signup"

        if "password" in field_types and len([t for t in field_types if t == "password"]) >= 2:
            return "change_password"

        if "card" in field_types:
            return "payment"

        if "search" in field_types:
            return "search"

        if "email" in field_types and len(inputs) == 1:
            return "newsletter"

        return "generic"

    async def _analyze_page(self, url: str, page_data: Dict[str, Any]) -> List[DetectedJourney]:
        """Analyze a page and detect journeys."""
        journeys = []

        # Analyze URL patterns
        url_journeys = self._detect_from_url(url, page_data)
        journeys.extend(url_journeys)

        # Analyze forms
        form_journeys = self._detect_from_forms(url, page_data)
        journeys.extend(form_journeys)

        # Analyze navigation
        nav_journeys = self._detect_from_navigation(url, page_data)
        journeys.extend(nav_journeys)

        return journeys

    def _detect_from_url(self, url: str, page_data: Dict[str, Any]) -> List[DetectedJourney]:
        """Detect journeys from URL patterns."""
        journeys = []
        url_lower = url.lower()

        for category, subcategories in self.JOURNEY_PATTERNS.items():
            for journey_type, patterns in subcategories.items():
                for pattern in patterns:
                    if re.search(pattern, url_lower):
                        journey = self._create_journey(
                            category=category,
                            journey_type=journey_type,
                            url=url,
                            page_data=page_data,
                            confidence=0.7
                        )
                        if journey:
                            journeys.append(journey)
                        break

        return journeys

    def _detect_from_forms(self, url: str, page_data: Dict[str, Any]) -> List[DetectedJourney]:
        """Detect journeys from form analysis."""
        journeys = []

        for form in page_data.get("forms", []):
            form_type = form["form_type"]

            if form_type == "login":
                journey = self._create_journey(
                    category="authentication",
                    journey_type="login",
                    url=url,
                    page_data=page_data,
                    confidence=0.9,
                    form=form
                )
                if journey:
                    journeys.append(journey)

            elif form_type == "signup":
                journey = self._create_journey(
                    category="authentication",
                    journey_type="signup",
                    url=url,
                    page_data=page_data,
                    confidence=0.9,
                    form=form
                )
                if journey:
                    journeys.append(journey)

            elif form_type == "change_password":
                journey = self._create_journey(
                    category="profile",
                    journey_type="change_password",
                    url=url,
                    page_data=page_data,
                    confidence=0.85,
                    form=form
                )
                if journey:
                    journeys.append(journey)

            elif form_type == "payment":
                journey = self._create_journey(
                    category="payments",
                    journey_type="payment",
                    url=url,
                    page_data=page_data,
                    confidence=0.9,
                    form=form
                )
                if journey:
                    journeys.append(journey)

        return journeys

    def _detect_from_navigation(self, url: str, page_data: Dict[str, Any]) -> List[DetectedJourney]:
        """Detect journeys from navigation elements."""
        journeys = []

        nav_items = page_data.get("nav_items", [])

        for item in nav_items:
            item_lower = item.lower()

            for category, subcategories in self.JOURNEY_PATTERNS.items():
                for journey_type, patterns in subcategories.items():
                    for pattern in patterns:
                        if re.search(pattern, item_lower):
                            journey = self._create_journey(
                                category=category,
                                journey_type=journey_type,
                                url=url,
                                page_data=page_data,
                                confidence=0.5
                            )
                            if journey:
                                journeys.append(journey)
                            break

        return journeys

    def _create_journey(
        self,
        category: str,
        journey_type: str,
        url: str,
        page_data: Dict[str, Any],
        confidence: float,
        form: Optional[Dict] = None
    ) -> Optional[DetectedJourney]:
        """Create a journey from detected data."""

        # Get template for this journey type
        template = self.mapper.get_template(category, journey_type)

        steps = []

        # Add form fields as steps
        if form:
            for i, inp in enumerate(form.get("inputs", [])):
                if inp["type"] not in ["hidden", "submit"]:
                    steps.append(DetectedStep(
                        id=f"step_{i+1}",
                        name=f"Enter {inp['field_type']}",
                        url=url,
                        action_type="input",
                        element_selector=f"input[name='{inp['name']}']",
                        input_type=inp["type"],
                        is_required=True,
                        order=i+1
                    ))

            # Add submit step
            steps.append(DetectedStep(
                id=f"step_{len(steps)+1}",
                name=form.get("submit_text") or "Submit",
                url=url,
                action_type="form_submit",
                order=len(steps)+1
            ))

        # If no form, use template steps
        if not steps and template:
            for i, step_name in enumerate(template.get("steps", [])):
                steps.append(DetectedStep(
                    id=f"step_{i+1}",
                    name=step_name,
                    url=url,
                    action_type="navigate",
                    order=i+1
                ))

        if not steps:
            return None

        return DetectedJourney(
            journey_id=f"journey_{uuid.uuid4().hex[:8]}",
            name=template.get("name", f"{journey_type.replace('_', ' ').title()} Flow") if template else f"{journey_type.replace('_', ' ').title()} Flow",
            category=category.replace("_", " ").title(),
            description=template.get("description", "") if template else "",
            url=url,
            steps=steps,
            confidence=confidence
        )

    async def _crawl_for_journeys(
        self,
        base_url: str,
        page_data: Dict[str, Any],
        journeys: List[DetectedJourney],
        depth: int
    ):
        """Crawl linked pages for more journeys."""
        if depth > self.max_depth:
            return

        links = page_data.get("links", [])[:20]  # Limit links per page

        for link in links:
            link_url = link["url"]

            if link_url in self._visited_urls:
                continue

            # Check if link looks relevant
            link_text_lower = link.get("text", "").lower()
            link_url_lower = link_url.lower()

            is_relevant = any(
                re.search(pattern, link_text_lower) or re.search(pattern, link_url_lower)
                for patterns in self.JOURNEY_PATTERNS.values()
                for sub_patterns in patterns.values()
                for pattern in sub_patterns
            )

            if is_relevant:
                child_data = await self._fetch_page(link_url)
                if child_data:
                    child_journeys = await self._analyze_page(link_url, child_data)
                    journeys.extend(child_journeys)

                    # Continue crawling
                    await self._crawl_for_journeys(base_url, child_data, journeys, depth + 1)

    def _merge_journeys(self, journeys: List[DetectedJourney]) -> List[DetectedJourney]:
        """Merge duplicate or similar journeys."""
        merged = {}

        for journey in journeys:
            key = f"{journey.category}_{journey.name}"

            if key not in merged:
                merged[key] = journey
            else:
                # Keep the one with higher confidence or more steps
                existing = merged[key]
                if (journey.confidence > existing.confidence or
                    len(journey.steps) > len(existing.steps)):
                    merged[key] = journey

        return list(merged.values())


async def detect_journeys(url: str, max_depth: int = 2) -> List[Dict[str, Any]]:
    """
    Convenience function to detect journeys from a URL.

    Args:
        url: The URL to analyze
        max_depth: Maximum crawl depth

    Returns:
        List of detected journey dictionaries
    """
    detector = JourneyDetector(max_depth=max_depth)
    journeys = await detector.detect(url)
    return [j.to_dict() for j in journeys]
