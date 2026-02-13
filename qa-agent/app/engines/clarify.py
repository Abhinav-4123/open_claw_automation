"""
NEXUS QA - Clarification Engine
Intelligent system to pause and ask humans when uncertain.
"""

import uuid
import json
from datetime import datetime
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from enum import Enum


class ClarificationType(Enum):
    """Types of clarification requests."""
    AMBIGUOUS_ELEMENT = "ambiguous_element"
    MISSING_CREDENTIALS = "missing_credentials"
    UNEXPECTED_STATE = "unexpected_state"
    CAPTCHA_DETECTED = "captcha_detected"
    MFA_REQUIRED = "mfa_required"
    POPUP_MODAL = "popup_modal"
    MULTIPLE_PATHS = "multiple_paths"
    CONFIRMATION_NEEDED = "confirmation_needed"
    ERROR_ENCOUNTERED = "error_encountered"
    DATA_INPUT_NEEDED = "data_input_needed"


@dataclass
class ClarificationRequest:
    """A clarification request to the user."""
    id: str
    type: ClarificationType
    question: str
    context: Dict[str, Any]
    options: List[str]
    journey_id: Optional[str] = None
    scan_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    status: str = "pending"  # pending, responded, expired
    response: Optional[str] = None
    responded_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "question": self.question,
            "context": self.context,
            "options": self.options,
            "journey_id": self.journey_id,
            "scan_id": self.scan_id,
            "created_at": self.created_at.isoformat(),
            "status": self.status,
            "response": self.response,
            "responded_at": self.responded_at.isoformat() if self.responded_at else None
        }


class ClarificationEngine:
    """
    Engine for managing clarification requests during automated testing.

    Handles scenarios where the automated system needs human input:
    - Ambiguous UI elements (multiple possible actions)
    - Missing credentials for authentication
    - Unexpected page states
    - CAPTCHA challenges
    - MFA verification codes
    - Confirmation dialogs
    """

    # Templates for common clarification scenarios
    CLARIFICATION_TEMPLATES = {
        ClarificationType.AMBIGUOUS_ELEMENT: {
            "question_template": "Multiple {element_type} elements found. Which one should I interact with?",
            "default_options": ["First occurrence", "Last occurrence", "Skip this step"]
        },
        ClarificationType.MISSING_CREDENTIALS: {
            "question_template": "Credentials are required for {action}. Please provide:",
            "default_options": ["Enter credentials", "Use test account", "Skip authentication"]
        },
        ClarificationType.UNEXPECTED_STATE: {
            "question_template": "The page is showing '{actual_state}' but expected '{expected_state}'. How should I proceed?",
            "default_options": ["Continue anyway", "Retry", "Skip this step", "Abort test"]
        },
        ClarificationType.CAPTCHA_DETECTED: {
            "question_template": "A CAPTCHA has been detected on {page}. Please solve it manually.",
            "default_options": ["I've solved it", "Skip page", "Abort test"]
        },
        ClarificationType.MFA_REQUIRED: {
            "question_template": "Multi-factor authentication is required. Please provide the verification code.",
            "default_options": ["Enter code", "Skip MFA", "Use backup code"]
        },
        ClarificationType.POPUP_MODAL: {
            "question_template": "A popup/modal appeared: '{modal_title}'. How should I handle it?",
            "default_options": ["Close it", "Accept", "Dismiss", "Interact with it"]
        },
        ClarificationType.MULTIPLE_PATHS: {
            "question_template": "Multiple navigation paths detected from this point. Which path should I follow?",
            "default_options": []  # Will be populated with detected paths
        },
        ClarificationType.CONFIRMATION_NEEDED: {
            "question_template": "Action '{action}' requires confirmation. Should I proceed?",
            "default_options": ["Yes, proceed", "No, cancel", "Skip"]
        },
        ClarificationType.ERROR_ENCOUNTERED: {
            "question_template": "Error encountered: {error_message}. How should I proceed?",
            "default_options": ["Retry", "Skip this step", "Abort test"]
        },
        ClarificationType.DATA_INPUT_NEEDED: {
            "question_template": "Test data is needed for field '{field_name}'. Please provide a value:",
            "default_options": ["Use generated data", "Enter custom value"]
        }
    }

    def __init__(self):
        self._pending_requests: Dict[str, ClarificationRequest] = {}
        self._request_history: List[ClarificationRequest] = []

    def create_clarification(
        self,
        clarification_type: ClarificationType,
        context: Dict[str, Any],
        custom_question: Optional[str] = None,
        custom_options: Optional[List[str]] = None,
        journey_id: Optional[str] = None,
        scan_id: Optional[str] = None
    ) -> ClarificationRequest:
        """
        Create a new clarification request.

        Args:
            clarification_type: The type of clarification needed
            context: Context information for the clarification
            custom_question: Custom question (overrides template)
            custom_options: Custom options (overrides template)
            journey_id: Associated journey ID
            scan_id: Associated scan ID

        Returns:
            ClarificationRequest object
        """
        template = self.CLARIFICATION_TEMPLATES.get(clarification_type, {})

        # Build question
        if custom_question:
            question = custom_question
        else:
            question_template = template.get(
                "question_template",
                "Clarification needed. Please select an option:"
            )
            question = question_template.format(**context)

        # Build options
        if custom_options:
            options = custom_options
        else:
            options = template.get("default_options", [])
            if not options and "paths" in context:
                options = context["paths"]

        request = ClarificationRequest(
            id=f"clarify_{uuid.uuid4().hex[:8]}",
            type=clarification_type,
            question=question,
            context=context,
            options=options,
            journey_id=journey_id,
            scan_id=scan_id
        )

        self._pending_requests[request.id] = request
        return request

    def get_pending_clarifications(self) -> List[ClarificationRequest]:
        """Get all pending clarification requests."""
        return [r for r in self._pending_requests.values() if r.status == "pending"]

    def get_clarification(self, clarification_id: str) -> Optional[ClarificationRequest]:
        """Get a specific clarification request."""
        return self._pending_requests.get(clarification_id)

    def respond_to_clarification(
        self,
        clarification_id: str,
        response: str
    ) -> bool:
        """
        Respond to a clarification request.

        Args:
            clarification_id: The clarification ID
            response: The user's response

        Returns:
            True if successful
        """
        request = self._pending_requests.get(clarification_id)
        if not request:
            return False

        request.response = response
        request.responded_at = datetime.now()
        request.status = "responded"

        self._request_history.append(request)

        return True

    def expire_clarification(self, clarification_id: str) -> bool:
        """Mark a clarification as expired."""
        request = self._pending_requests.get(clarification_id)
        if not request:
            return False

        request.status = "expired"
        self._request_history.append(request)

        return True

    def get_history(
        self,
        journey_id: Optional[str] = None,
        scan_id: Optional[str] = None
    ) -> List[ClarificationRequest]:
        """Get clarification history with optional filters."""
        history = self._request_history

        if journey_id:
            history = [r for r in history if r.journey_id == journey_id]

        if scan_id:
            history = [r for r in history if r.scan_id == scan_id]

        return history

    # Convenience methods for common scenarios

    def ask_for_credentials(
        self,
        action: str = "login",
        journey_id: Optional[str] = None
    ) -> ClarificationRequest:
        """Create a credentials clarification."""
        return self.create_clarification(
            ClarificationType.MISSING_CREDENTIALS,
            context={"action": action},
            journey_id=journey_id
        )

    def ask_for_mfa_code(
        self,
        journey_id: Optional[str] = None
    ) -> ClarificationRequest:
        """Create an MFA clarification."""
        return self.create_clarification(
            ClarificationType.MFA_REQUIRED,
            context={},
            journey_id=journey_id
        )

    def ask_to_solve_captcha(
        self,
        page: str,
        journey_id: Optional[str] = None
    ) -> ClarificationRequest:
        """Create a CAPTCHA clarification."""
        return self.create_clarification(
            ClarificationType.CAPTCHA_DETECTED,
            context={"page": page},
            journey_id=journey_id
        )

    def ask_about_element(
        self,
        element_type: str,
        elements: List[str],
        journey_id: Optional[str] = None
    ) -> ClarificationRequest:
        """Create an ambiguous element clarification."""
        return self.create_clarification(
            ClarificationType.AMBIGUOUS_ELEMENT,
            context={"element_type": element_type},
            custom_options=elements + ["Skip this step"],
            journey_id=journey_id
        )

    def ask_about_state(
        self,
        expected_state: str,
        actual_state: str,
        journey_id: Optional[str] = None
    ) -> ClarificationRequest:
        """Create an unexpected state clarification."""
        return self.create_clarification(
            ClarificationType.UNEXPECTED_STATE,
            context={
                "expected_state": expected_state,
                "actual_state": actual_state
            },
            journey_id=journey_id
        )

    def ask_about_paths(
        self,
        paths: List[str],
        journey_id: Optional[str] = None
    ) -> ClarificationRequest:
        """Create a multiple paths clarification."""
        return self.create_clarification(
            ClarificationType.MULTIPLE_PATHS,
            context={"paths": paths},
            custom_options=paths,
            journey_id=journey_id
        )

    def ask_for_confirmation(
        self,
        action: str,
        journey_id: Optional[str] = None
    ) -> ClarificationRequest:
        """Create a confirmation clarification."""
        return self.create_clarification(
            ClarificationType.CONFIRMATION_NEEDED,
            context={"action": action},
            journey_id=journey_id
        )

    def report_error(
        self,
        error_message: str,
        journey_id: Optional[str] = None,
        scan_id: Optional[str] = None
    ) -> ClarificationRequest:
        """Create an error clarification."""
        return self.create_clarification(
            ClarificationType.ERROR_ENCOUNTERED,
            context={"error_message": error_message},
            journey_id=journey_id,
            scan_id=scan_id
        )

    def ask_for_data(
        self,
        field_name: str,
        field_type: str = "text",
        journey_id: Optional[str] = None
    ) -> ClarificationRequest:
        """Create a data input clarification."""
        return self.create_clarification(
            ClarificationType.DATA_INPUT_NEEDED,
            context={
                "field_name": field_name,
                "field_type": field_type
            },
            journey_id=journey_id
        )
