"""
NEXUS QA - Journey Mapper
Maps detected journeys to standard templates and categories.
"""

from typing import Dict, List, Optional, Any


# Journey templates for common user flows
JOURNEY_TEMPLATES = {
    "authentication": {
        "login": {
            "name": "User Login",
            "description": "Standard user authentication flow",
            "steps": [
                "Navigate to login page",
                "Enter email/username",
                "Enter password",
                "Click login button",
                "Verify redirect to dashboard"
            ],
            "required_fields": ["email", "password"],
            "success_indicators": ["dashboard", "welcome", "logged in"],
            "failure_indicators": ["invalid", "incorrect", "error"]
        },
        "signup": {
            "name": "User Registration",
            "description": "New user account creation flow",
            "steps": [
                "Navigate to signup page",
                "Enter full name",
                "Enter email address",
                "Create password",
                "Confirm password",
                "Accept terms",
                "Click register button",
                "Verify email confirmation"
            ],
            "required_fields": ["name", "email", "password"],
            "success_indicators": ["verify", "confirmation", "welcome"],
            "failure_indicators": ["exists", "invalid", "error"]
        },
        "password_reset": {
            "name": "Password Reset",
            "description": "Forgot password recovery flow",
            "steps": [
                "Navigate to forgot password",
                "Enter email address",
                "Submit reset request",
                "Check email for link",
                "Click reset link",
                "Enter new password",
                "Confirm new password",
                "Verify reset success"
            ],
            "required_fields": ["email"],
            "success_indicators": ["sent", "check email", "reset successful"],
            "failure_indicators": ["not found", "error"]
        },
        "logout": {
            "name": "User Logout",
            "description": "User session termination flow",
            "steps": [
                "Click logout button",
                "Confirm logout (if required)",
                "Verify redirect to login page"
            ],
            "required_fields": [],
            "success_indicators": ["logged out", "login"],
            "failure_indicators": []
        },
        "mfa": {
            "name": "Multi-Factor Authentication",
            "description": "Two-factor authentication setup and verification",
            "steps": [
                "Navigate to MFA settings",
                "Choose MFA method",
                "Scan QR code / Enter phone",
                "Enter verification code",
                "Verify MFA enabled"
            ],
            "required_fields": ["verification_code"],
            "success_indicators": ["enabled", "verified", "success"],
            "failure_indicators": ["invalid code", "expired"]
        }
    },
    "profile": {
        "view_profile": {
            "name": "View Profile",
            "description": "View user profile information",
            "steps": [
                "Navigate to profile page",
                "View profile information",
                "View profile picture"
            ],
            "required_fields": [],
            "success_indicators": ["profile", "account"],
            "failure_indicators": []
        },
        "edit_profile": {
            "name": "Edit Profile",
            "description": "Update user profile information",
            "steps": [
                "Navigate to profile settings",
                "Click edit button",
                "Modify profile fields",
                "Save changes",
                "Verify update success"
            ],
            "required_fields": [],
            "success_indicators": ["saved", "updated", "success"],
            "failure_indicators": ["error", "failed"]
        },
        "change_password": {
            "name": "Change Password",
            "description": "Update user password",
            "steps": [
                "Navigate to security settings",
                "Enter current password",
                "Enter new password",
                "Confirm new password",
                "Save changes",
                "Verify password changed"
            ],
            "required_fields": ["current_password", "new_password", "confirm_password"],
            "success_indicators": ["changed", "updated", "success"],
            "failure_indicators": ["incorrect", "mismatch", "error"]
        },
        "preferences": {
            "name": "User Preferences",
            "description": "Configure user preferences and notifications",
            "steps": [
                "Navigate to preferences",
                "Modify notification settings",
                "Modify privacy settings",
                "Save preferences"
            ],
            "required_fields": [],
            "success_indicators": ["saved", "updated"],
            "failure_indicators": []
        }
    },
    "payments": {
        "checkout": {
            "name": "Checkout Process",
            "description": "E-commerce checkout flow",
            "steps": [
                "Review cart items",
                "Enter shipping address",
                "Select shipping method",
                "Enter payment details",
                "Review order summary",
                "Place order",
                "Verify order confirmation"
            ],
            "required_fields": ["address", "card"],
            "success_indicators": ["confirmed", "thank you", "order number"],
            "failure_indicators": ["declined", "error", "failed"]
        },
        "payment": {
            "name": "Payment Processing",
            "description": "Payment form submission",
            "steps": [
                "Enter card number",
                "Enter expiry date",
                "Enter CVV",
                "Enter billing address",
                "Submit payment",
                "Verify payment success"
            ],
            "required_fields": ["card_number", "expiry", "cvv"],
            "success_indicators": ["success", "approved", "thank you"],
            "failure_indicators": ["declined", "invalid", "error"]
        },
        "subscription": {
            "name": "Subscription Management",
            "description": "Subscribe or manage subscription plans",
            "steps": [
                "View available plans",
                "Select plan",
                "Enter payment details",
                "Confirm subscription",
                "Verify subscription active"
            ],
            "required_fields": ["card"],
            "success_indicators": ["subscribed", "active", "thank you"],
            "failure_indicators": ["failed", "error"]
        }
    },
    "dashboard": {
        "overview": {
            "name": "Dashboard Overview",
            "description": "Main dashboard view",
            "steps": [
                "Navigate to dashboard",
                "View summary metrics",
                "View recent activity"
            ],
            "required_fields": [],
            "success_indicators": [],
            "failure_indicators": []
        },
        "analytics": {
            "name": "Analytics & Reports",
            "description": "View analytics and generate reports",
            "steps": [
                "Navigate to analytics",
                "Select date range",
                "View charts and metrics",
                "Filter by criteria"
            ],
            "required_fields": [],
            "success_indicators": [],
            "failure_indicators": []
        },
        "export": {
            "name": "Data Export",
            "description": "Export data to various formats",
            "steps": [
                "Navigate to export section",
                "Select export format",
                "Select data range",
                "Click export button",
                "Download file"
            ],
            "required_fields": [],
            "success_indicators": ["download", "exported"],
            "failure_indicators": ["error", "failed"]
        }
    },
    "content": {
        "create": {
            "name": "Create Content",
            "description": "Create new content item",
            "steps": [
                "Click create/new button",
                "Fill in content details",
                "Add media (if applicable)",
                "Save/publish content",
                "Verify creation success"
            ],
            "required_fields": ["title"],
            "success_indicators": ["created", "saved", "published"],
            "failure_indicators": ["error", "failed"]
        },
        "edit": {
            "name": "Edit Content",
            "description": "Edit existing content",
            "steps": [
                "Navigate to content item",
                "Click edit button",
                "Modify content",
                "Save changes",
                "Verify update success"
            ],
            "required_fields": [],
            "success_indicators": ["updated", "saved"],
            "failure_indicators": ["error", "failed"]
        },
        "delete": {
            "name": "Delete Content",
            "description": "Delete content item",
            "steps": [
                "Navigate to content item",
                "Click delete button",
                "Confirm deletion",
                "Verify deletion success"
            ],
            "required_fields": [],
            "success_indicators": ["deleted", "removed"],
            "failure_indicators": ["error", "failed"]
        },
        "list": {
            "name": "Browse Content",
            "description": "List and search content",
            "steps": [
                "Navigate to content list",
                "Apply filters (optional)",
                "Search (optional)",
                "View results"
            ],
            "required_fields": [],
            "success_indicators": [],
            "failure_indicators": []
        }
    },
    "api": {
        "api_keys": {
            "name": "API Key Management",
            "description": "Create and manage API keys",
            "steps": [
                "Navigate to API settings",
                "Click create key",
                "Configure key permissions",
                "Generate key",
                "Copy and save key"
            ],
            "required_fields": [],
            "success_indicators": ["created", "generated"],
            "failure_indicators": ["error", "failed"]
        },
        "webhooks": {
            "name": "Webhook Configuration",
            "description": "Set up and manage webhooks",
            "steps": [
                "Navigate to webhooks",
                "Click add webhook",
                "Enter webhook URL",
                "Select events",
                "Save webhook",
                "Test webhook"
            ],
            "required_fields": ["url"],
            "success_indicators": ["saved", "active", "success"],
            "failure_indicators": ["invalid", "failed"]
        },
        "documentation": {
            "name": "API Documentation",
            "description": "View API documentation",
            "steps": [
                "Navigate to API docs",
                "Browse endpoints",
                "View examples"
            ],
            "required_fields": [],
            "success_indicators": [],
            "failure_indicators": []
        }
    }
}


class JourneyMapper:
    """Maps detected journeys to standard templates."""

    def __init__(self):
        self.templates = JOURNEY_TEMPLATES

    def get_template(
        self,
        category: str,
        journey_type: str
    ) -> Optional[Dict[str, Any]]:
        """Get a journey template by category and type."""
        category_templates = self.templates.get(category, {})
        return category_templates.get(journey_type)

    def get_all_templates(self) -> Dict[str, Dict[str, Any]]:
        """Get all journey templates."""
        return self.templates

    def get_categories(self) -> List[str]:
        """Get all journey categories."""
        return list(self.templates.keys())

    def get_journey_types(self, category: str) -> List[str]:
        """Get all journey types for a category."""
        category_templates = self.templates.get(category, {})
        return list(category_templates.keys())

    def match_journey(
        self,
        detected_steps: List[str],
        detected_fields: List[str]
    ) -> Optional[Dict[str, Any]]:
        """
        Match detected journey elements to a template.

        Args:
            detected_steps: List of detected step names
            detected_fields: List of detected form field types

        Returns:
            Best matching template or None
        """
        best_match = None
        best_score = 0

        for category, journeys in self.templates.items():
            for journey_type, template in journeys.items():
                score = self._calculate_match_score(
                    template,
                    detected_steps,
                    detected_fields
                )

                if score > best_score:
                    best_score = score
                    best_match = {
                        "category": category,
                        "journey_type": journey_type,
                        "template": template,
                        "score": score
                    }

        return best_match if best_score > 0.3 else None

    def _calculate_match_score(
        self,
        template: Dict[str, Any],
        detected_steps: List[str],
        detected_fields: List[str]
    ) -> float:
        """Calculate how well detected elements match a template."""
        score = 0
        max_score = 0

        # Match required fields
        required_fields = template.get("required_fields", [])
        if required_fields:
            max_score += 1
            matched_fields = sum(1 for f in required_fields if f in detected_fields)
            score += matched_fields / len(required_fields)

        # Match steps
        template_steps = template.get("steps", [])
        if template_steps:
            max_score += 1
            # Simple word overlap scoring
            template_words = set(
                word.lower()
                for step in template_steps
                for word in step.split()
            )
            detected_words = set(
                word.lower()
                for step in detected_steps
                for word in step.split()
            )

            if template_words:
                overlap = len(template_words & detected_words) / len(template_words)
                score += overlap

        return score / max_score if max_score > 0 else 0

    def get_coverage(
        self,
        journey_type: str,
        category: str,
        completed_steps: List[str]
    ) -> float:
        """
        Calculate journey coverage percentage.

        Args:
            journey_type: The journey type
            category: The journey category
            completed_steps: List of completed step names

        Returns:
            Coverage percentage (0-100)
        """
        template = self.get_template(category, journey_type)
        if not template:
            return 0

        template_steps = template.get("steps", [])
        if not template_steps:
            return 100 if completed_steps else 0

        # Simple matching based on step keywords
        matched = 0
        for template_step in template_steps:
            template_words = set(template_step.lower().split())
            for completed_step in completed_steps:
                completed_words = set(completed_step.lower().split())
                if template_words & completed_words:
                    matched += 1
                    break

        return (matched / len(template_steps)) * 100
