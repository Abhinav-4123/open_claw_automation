"""
NEXUS QA Scan Checkpointing

Enables scan resume functionality by periodically saving state.
Supports recovery from failures, timeouts, and pauses.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Set
import json

from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ScanCheckpoint:
    """
    Serializable checkpoint state for scan resume.

    Contains all data needed to resume a scan from a specific point,
    minimizing duplicate work while ensuring complete coverage.
    """

    # Identity
    scan_id: str
    phase: str
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    # Progress
    progress: int = 0
    phase_progress: int = 0

    # Exploration State
    visited_urls: List[str] = field(default_factory=list)
    pending_urls: List[str] = field(default_factory=list)
    explored_elements: List[str] = field(default_factory=list)

    # Discovery Data
    discovered_apis: List[Dict] = field(default_factory=list)
    discovered_modules: List[Dict] = field(default_factory=list)
    discovered_journeys: List[Dict] = field(default_factory=list)

    # Test Plan (if created)
    test_plan: Optional[Dict] = None
    plan_notes: List[str] = field(default_factory=list)

    # Security Testing Progress
    completed_tests: List[str] = field(default_factory=list)
    pending_tests: List[Dict] = field(default_factory=list)

    # Findings (accumulated)
    findings: List[Dict] = field(default_factory=list)

    # Stats
    stats: Dict[str, int] = field(default_factory=dict)

    # Authentication State
    is_authenticated: bool = False
    auth_cookies: Optional[Dict] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert checkpoint to dictionary for storage."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanCheckpoint":
        """Create checkpoint from dictionary."""
        return cls(**data)

    def to_json(self) -> str:
        """Serialize checkpoint to JSON."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> "ScanCheckpoint":
        """Deserialize checkpoint from JSON."""
        return cls.from_dict(json.loads(json_str))


class CheckpointManager:
    """
    Manages checkpoint creation, saving, and restoration.

    Implements a strategy of periodic checkpoints with phase boundaries
    to minimize data loss while keeping checkpoint size manageable.
    """

    # Phases where checkpoints are most valuable
    CHECKPOINT_PHASES = [
        "planning_complete",
        "exploration_complete",
        "api_discovery_complete",
        "security_testing",  # Checkpoint during testing
        "reporting",
    ]

    # Checkpoint every N operations within a phase
    OPERATIONS_BETWEEN_CHECKPOINTS = 10

    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.current_checkpoint: Optional[ScanCheckpoint] = None
        self.operations_since_checkpoint = 0
        self.last_checkpoint_phase = None

    def should_checkpoint(self, phase: str, force: bool = False) -> bool:
        """
        Determine if a checkpoint should be created.

        Checkpoints are created:
        1. At phase boundaries (planning_complete, etc.)
        2. Every N operations within long phases
        3. When forced (before risky operations)
        """
        if force:
            return True

        # Always checkpoint at phase transitions
        if phase != self.last_checkpoint_phase and phase in self.CHECKPOINT_PHASES:
            return True

        # Checkpoint periodically during long phases
        if phase == "security_testing":
            self.operations_since_checkpoint += 1
            if self.operations_since_checkpoint >= self.OPERATIONS_BETWEEN_CHECKPOINTS:
                return True

        return False

    def create_checkpoint(
        self,
        phase: str,
        progress: int,
        session_state: Dict[str, Any]
    ) -> ScanCheckpoint:
        """
        Create a new checkpoint from current scan state.

        Args:
            phase: Current scan phase
            progress: Overall progress percentage
            session_state: State dictionary from LiveScanSession
        """
        checkpoint = ScanCheckpoint(
            scan_id=self.scan_id,
            phase=phase,
            progress=progress,
            phase_progress=session_state.get("phase_progress", 0),

            # Exploration state
            visited_urls=list(session_state.get("visited_urls", [])),
            pending_urls=session_state.get("pending_urls", []),
            explored_elements=list(session_state.get("explored_elements", [])),

            # Discovery data
            discovered_apis=[
                self._serialize_api(api)
                for api in session_state.get("apis", {}).values()
            ],
            discovered_modules=[
                self._serialize_module(mod)
                for mod in session_state.get("modules", {}).values()
            ],
            discovered_journeys=[
                self._serialize_journey(j)
                for j in session_state.get("journeys", {}).values()
            ],

            # Test plan
            test_plan=self._serialize_test_plan(session_state.get("test_plan")),
            plan_notes=session_state.get("plan_notes", []),

            # Security testing
            completed_tests=session_state.get("completed_tests", []),
            pending_tests=session_state.get("pending_tests", []),

            # Findings
            findings=session_state.get("findings", []),

            # Stats
            stats=session_state.get("stats", {}),

            # Auth
            is_authenticated=session_state.get("is_authenticated", False),
            auth_cookies=session_state.get("auth_cookies"),
        )

        self.current_checkpoint = checkpoint
        self.operations_since_checkpoint = 0
        self.last_checkpoint_phase = phase

        logger.info(
            f"Created checkpoint at phase '{phase}'",
            scan_id=self.scan_id,
            progress=progress,
            visited_urls=len(checkpoint.visited_urls),
            findings=len(checkpoint.findings)
        )

        return checkpoint

    def restore_state(
        self,
        checkpoint: ScanCheckpoint
    ) -> Dict[str, Any]:
        """
        Convert checkpoint back to session state for resuming.

        Returns a dictionary that can be used to restore
        LiveScanSession state.
        """
        return {
            "phase": checkpoint.phase,
            "progress": checkpoint.progress,
            "phase_progress": checkpoint.phase_progress,

            # Exploration
            "visited_urls": set(checkpoint.visited_urls),
            "pending_urls": checkpoint.pending_urls[:],
            "explored_elements": set(checkpoint.explored_elements),

            # Discovery (will need to be converted back to objects)
            "apis_data": checkpoint.discovered_apis,
            "modules_data": checkpoint.discovered_modules,
            "journeys_data": checkpoint.discovered_journeys,

            # Plan
            "test_plan_data": checkpoint.test_plan,
            "plan_notes": checkpoint.plan_notes[:],

            # Testing
            "completed_tests": checkpoint.completed_tests[:],
            "pending_tests": checkpoint.pending_tests[:],

            # Findings
            "findings": checkpoint.findings[:],

            # Stats
            "stats": checkpoint.stats.copy(),

            # Auth
            "is_authenticated": checkpoint.is_authenticated,
            "auth_cookies": checkpoint.auth_cookies,
        }

    def _serialize_api(self, api) -> Dict:
        """Serialize API object for checkpoint."""
        if hasattr(api, '__dict__'):
            return {
                "id": getattr(api, "id", ""),
                "method": getattr(api, "method", ""),
                "url": getattr(api, "url", ""),
                "path": getattr(api, "path", ""),
                "host": getattr(api, "host", ""),
                "params": getattr(api, "params", {}),
                "request_headers": getattr(api, "request_headers", {}),
                "response_status": getattr(api, "response_status", 0),
                "content_type": getattr(api, "content_type", ""),
                "auth_required": getattr(api, "auth_required", False),
                "test_strategy": getattr(api, "test_strategy", []),
            }
        return api if isinstance(api, dict) else {}

    def _serialize_module(self, module) -> Dict:
        """Serialize module object for checkpoint."""
        if hasattr(module, '__dict__'):
            return {
                "id": getattr(module, "id", ""),
                "name": getattr(module, "name", ""),
                "url": getattr(module, "url", ""),
                "description": getattr(module, "description", ""),
                "features": getattr(module, "features", []),
            }
        return module if isinstance(module, dict) else {}

    def _serialize_journey(self, journey) -> Dict:
        """Serialize journey object for checkpoint."""
        if hasattr(journey, '__dict__'):
            return {
                "id": getattr(journey, "id", ""),
                "name": getattr(journey, "name", ""),
                "description": getattr(journey, "description", ""),
                "start_url": getattr(journey, "start_url", ""),
                "steps": getattr(journey, "steps", []),
                "status": getattr(journey, "status", "discovered"),
            }
        return journey if isinstance(journey, dict) else {}

    def _serialize_test_plan(self, plan) -> Optional[Dict]:
        """Serialize test plan for checkpoint."""
        if plan is None:
            return None
        if hasattr(plan, '__dict__'):
            return {
                "id": getattr(plan, "id", ""),
                "app_description": getattr(plan, "app_description", ""),
                "identified_features": getattr(plan, "identified_features", []),
                "user_journeys": getattr(plan, "user_journeys", []),
                "api_endpoints": getattr(plan, "api_endpoints", []),
                "security_tests": getattr(plan, "security_tests", []),
                "notes": getattr(plan, "notes", []),
                "priority_areas": getattr(plan, "priority_areas", []),
            }
        return plan if isinstance(plan, dict) else None


def calculate_resume_point(checkpoint: ScanCheckpoint) -> Dict[str, Any]:
    """
    Determine optimal resume point from checkpoint.

    Returns instructions for resuming the scan efficiently.
    """
    phase = checkpoint.phase

    # If we completed planning, skip straight to where we left off
    if phase in ["planning_complete", "exploration", "exploration_complete"]:
        return {
            "skip_planning": True,
            "resume_phase": phase if "complete" not in phase else _next_phase(phase),
            "start_from_urls": checkpoint.pending_urls,
            "skip_visited": checkpoint.visited_urls,
        }

    # If we're in API discovery, continue from there
    if phase in ["api_discovery", "api_discovery_complete"]:
        return {
            "skip_planning": True,
            "skip_exploration": True,
            "resume_phase": phase if "complete" not in phase else "security_testing",
            "pending_apis": [
                api for api in checkpoint.discovered_apis
                if api.get("id") not in checkpoint.completed_tests
            ],
        }

    # If we're in security testing, continue from remaining tests
    if phase == "security_testing":
        return {
            "skip_planning": True,
            "skip_exploration": True,
            "skip_api_discovery": True,
            "resume_phase": "security_testing",
            "remaining_tests": checkpoint.pending_tests,
            "completed_test_ids": checkpoint.completed_tests,
        }

    # Default: restart from the current phase
    return {
        "resume_phase": phase,
        "checkpoint": checkpoint.to_dict(),
    }


def _next_phase(phase: str) -> str:
    """Get the next phase after a completed phase."""
    phase_order = [
        "planning",
        "planning_complete",
        "exploration",
        "exploration_complete",
        "api_discovery",
        "api_discovery_complete",
        "security_testing",
        "reporting",
        "completed",
    ]
    try:
        idx = phase_order.index(phase)
        if idx + 1 < len(phase_order):
            return phase_order[idx + 1]
    except ValueError:
        pass
    return phase
