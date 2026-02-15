"""
NEXUS QA - PM Agent
Product Manager agent that uses VLM to understand the web application.
Analyzes screenshots, identifies app type, features, and user personas.
"""

import asyncio
import base64
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from playwright.async_api import async_playwright, Browser, Page

from .base import BaseAgent, TaskContext, AgentResult

logger = logging.getLogger(__name__)


class PMAgent(BaseAgent):
    """
    Product Manager Agent - Uses VLM to understand the product.

    Phase 1 responsibilities:
    - Take full-page screenshots
    - Analyze with Vision Language Model
    - Identify app type (SaaS, E-commerce, Social, etc.)
    - Extract core features
    - Identify user personas
    - Map navigation structure
    """

    agent_type = "pm"

    VLM_PROMPT = """You are a Senior Product Manager analyzing a web application.

Analyze this screenshot and provide a comprehensive product analysis.

Return your analysis in the following JSON format:
{
    "app_type": "one of: saas, e-commerce, social, fintech, healthcare, education, productivity, media, marketplace, other",
    "industry": "specific industry like: retail, finance, healthcare, tech, etc.",
    "product_name": "identified product/brand name if visible",
    "tagline": "any visible tagline or value proposition",
    "core_features": ["list", "of", "main", "features", "visible"],
    "navigation_items": ["menu", "items", "visible"],
    "user_personas": ["likely", "user", "types"],
    "auth_methods": ["login methods visible: email, google, github, etc."],
    "has_pricing": true/false,
    "has_dashboard": true/false,
    "has_signup": true/false,
    "has_login": true/false,
    "tech_hints": ["any visible tech: React, Vue, etc."],
    "accessibility_score": "good/medium/poor based on visual structure",
    "mobile_friendly": true/false,
    "key_ctas": ["primary call-to-action buttons"],
    "trust_signals": ["badges, certifications, testimonials visible"],
    "analysis_summary": "2-3 sentence summary of what this product does and who it's for"
}

Be thorough but concise. Only include what you can actually observe."""

    def __init__(self, llm_provider=None):
        super().__init__()
        self.llm_provider = llm_provider
        self.browser: Optional[Browser] = None
        self.screenshots: List[bytes] = []

    async def execute(self, context: TaskContext) -> AgentResult:
        """Analyze the product using VLM."""
        start_time = datetime.now()
        url = context.url

        try:
            await self.report_progress(5, "Launching browser")

            async with async_playwright() as p:
                # Launch browser
                self.browser = await p.chromium.launch(
                    headless=True,
                    args=['--no-sandbox', '--disable-setuid-sandbox']
                )

                page = await self.browser.new_page(
                    viewport={'width': 1920, 'height': 1080}
                )

                await self.report_progress(15, "Navigating to URL")

                # Navigate to the URL
                try:
                    await page.goto(url, wait_until='networkidle', timeout=30000)
                except Exception as e:
                    logger.warning(f"Navigation timeout, continuing anyway: {e}")
                    await page.goto(url, wait_until='domcontentloaded', timeout=30000)

                await asyncio.sleep(2)  # Wait for dynamic content

                await self.report_progress(30, "Taking screenshots")

                # Take multiple screenshots
                screenshots_data = await self._capture_screenshots(page)

                await self.report_progress(50, "Analyzing with VLM")

                # Analyze with VLM
                analysis = await self._analyze_with_vlm(screenshots_data, url)

                await self.report_progress(80, "Extracting page metadata")

                # Extract additional page data
                page_data = await self._extract_page_data(page)

                # Merge VLM analysis with page data
                result = {
                    **analysis,
                    "url": url,
                    "page_title": page_data.get("title", ""),
                    "meta_description": page_data.get("description", ""),
                    "total_links": page_data.get("total_links", 0),
                    "total_forms": page_data.get("total_forms", 0),
                    "total_buttons": page_data.get("total_buttons", 0),
                    "screenshots": len(screenshots_data),
                    "analyzed_at": datetime.now().isoformat()
                }

                await self.report_progress(100, "Product analysis complete")

                await self.browser.close()

                duration = (datetime.now() - start_time).total_seconds()
                return AgentResult(
                    success=True,
                    data=result,
                    duration_seconds=duration
                )

        except Exception as e:
            logger.exception(f"PM Agent error: {e}")
            if self.browser:
                await self.browser.close()
            return AgentResult(
                success=False,
                error=str(e),
                partial=True,
                data={"url": url, "error": str(e)}
            )

    async def _capture_screenshots(self, page: Page) -> List[Dict[str, Any]]:
        """Capture multiple screenshots of the page."""
        screenshots = []

        # 1. Full page above fold
        try:
            screenshot = await page.screenshot(type='png')
            screenshots.append({
                "name": "homepage_above_fold",
                "data": screenshot,
                "base64": base64.b64encode(screenshot).decode()
            })
            self.screenshots.append(screenshot)
        except Exception as e:
            logger.warning(f"Failed to capture above fold: {e}")

        # 2. Full page scroll
        try:
            full_screenshot = await page.screenshot(type='png', full_page=True)
            screenshots.append({
                "name": "homepage_full",
                "data": full_screenshot,
                "base64": base64.b64encode(full_screenshot).decode()
            })
        except Exception as e:
            logger.warning(f"Failed to capture full page: {e}")

        # 3. Try to find and screenshot key areas
        try:
            # Look for navigation
            nav = await page.query_selector('nav, header, [role="navigation"]')
            if nav:
                nav_screenshot = await nav.screenshot(type='png')
                screenshots.append({
                    "name": "navigation",
                    "data": nav_screenshot,
                    "base64": base64.b64encode(nav_screenshot).decode()
                })
        except Exception as e:
            logger.debug(f"Nav screenshot failed: {e}")

        return screenshots

    async def _analyze_with_vlm(
        self,
        screenshots: List[Dict],
        url: str
    ) -> Dict[str, Any]:
        """Analyze screenshots with Vision Language Model."""

        # Get LLM provider
        if not self.llm_provider:
            from ..llm_provider import LLMProvider
            self.llm_provider = LLMProvider()

        # Use the first (above fold) screenshot for primary analysis
        if not screenshots:
            return self._get_fallback_analysis(url)

        primary_screenshot = screenshots[0]

        try:
            # Call VLM with image
            response = await self.llm_provider.analyze_image(
                image_base64=primary_screenshot["base64"],
                prompt=self.VLM_PROMPT,
                image_type="png"
            )

            # Parse JSON response
            import json
            # Try to extract JSON from response
            response_text = response.strip()

            # Handle markdown code blocks
            if "```json" in response_text:
                response_text = response_text.split("```json")[1].split("```")[0]
            elif "```" in response_text:
                response_text = response_text.split("```")[1].split("```")[0]

            analysis = json.loads(response_text)
            analysis["vlm_raw_response"] = response[:500]  # Keep first 500 chars
            return analysis

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse VLM JSON: {e}")
            return self._get_fallback_analysis(url, raw_response=response)
        except Exception as e:
            logger.warning(f"VLM analysis failed: {e}")
            return self._get_fallback_analysis(url)

    def _get_fallback_analysis(
        self,
        url: str,
        raw_response: str = ""
    ) -> Dict[str, Any]:
        """Fallback analysis when VLM fails."""
        return {
            "app_type": "unknown",
            "industry": "unknown",
            "product_name": url.split("//")[1].split("/")[0] if "//" in url else url,
            "core_features": [],
            "navigation_items": [],
            "user_personas": ["general_user"],
            "auth_methods": [],
            "has_pricing": False,
            "has_dashboard": False,
            "has_signup": False,
            "has_login": False,
            "tech_hints": [],
            "accessibility_score": "unknown",
            "mobile_friendly": True,
            "key_ctas": [],
            "trust_signals": [],
            "analysis_summary": "VLM analysis unavailable - using fallback",
            "vlm_raw_response": raw_response[:500] if raw_response else "",
            "fallback": True
        }

    async def _extract_page_data(self, page: Page) -> Dict[str, Any]:
        """Extract metadata and element counts from page."""
        try:
            data = await page.evaluate("""() => {
                const title = document.title || '';
                const metaDesc = document.querySelector('meta[name="description"]');
                const links = document.querySelectorAll('a[href]');
                const forms = document.querySelectorAll('form');
                const buttons = document.querySelectorAll('button, input[type="submit"], [role="button"]');
                const inputs = document.querySelectorAll('input, textarea, select');

                // Get unique internal links
                const internalLinks = [...links].filter(a => {
                    try {
                        const url = new URL(a.href);
                        return url.hostname === window.location.hostname;
                    } catch { return false; }
                }).map(a => a.href);

                // Get form actions
                const formActions = [...forms].map(f => ({
                    action: f.action,
                    method: f.method,
                    inputs: [...f.querySelectorAll('input')].map(i => ({
                        type: i.type,
                        name: i.name,
                        id: i.id
                    }))
                }));

                return {
                    title: title,
                    description: metaDesc ? metaDesc.content : '',
                    total_links: links.length,
                    total_forms: forms.length,
                    total_buttons: buttons.length,
                    total_inputs: inputs.length,
                    internal_links: [...new Set(internalLinks)].slice(0, 50),
                    form_data: formActions.slice(0, 10)
                };
            }""")
            return data
        except Exception as e:
            logger.warning(f"Failed to extract page data: {e}")
            return {
                "title": "",
                "description": "",
                "total_links": 0,
                "total_forms": 0,
                "total_buttons": 0
            }
