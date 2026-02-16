"""
NEXUS QA Scan Orchestrator

Coordinates scan execution with checkpointing, progress tracking,
and integration with the database and job queue.
"""

import asyncio
from datetime import datetime
from typing import Any, Dict, List, Optional, Callable
from dataclasses import asdict

from app.core.config import settings
from app.core.logging import get_logger, set_request_context
from app.core.exceptions import ScanError, ScanTimeoutError

from .checkpoint import CheckpointManager, ScanCheckpoint, calculate_resume_point

logger = get_logger(__name__)


class ScanOrchestrator:
    """
    Orchestrates the execution of security scans.

    Responsibilities:
    - Manages LiveScanSession lifecycle
    - Implements checkpointing for resume capability
    - Tracks progress and emits events
    - Handles errors and timeouts gracefully
    - Integrates with database for persistence
    """

    # Phase definitions with progress ranges
    PHASES = {
        "initializing": (0, 5),
        "planning": (5, 15),
        "exploration": (15, 40),
        "api_discovery": (40, 55),
        "security_testing": (55, 90),
        "reporting": (90, 100),
    }

    def __init__(
        self,
        scan_id: str,
        url: str,
        scan_type: str = "deep",
        config: Optional[Dict] = None,
        checkpoint: Optional[Dict] = None,
        event_callback: Optional[Callable] = None,
    ):
        self.scan_id = scan_id
        self.url = url
        self.scan_type = scan_type
        self.config = config or {}
        self.event_callback = event_callback

        # Set logging context
        set_request_context(scan_id=scan_id)

        # Checkpoint management
        self.checkpoint_manager = CheckpointManager(scan_id)
        self.initial_checkpoint = (
            ScanCheckpoint.from_dict(checkpoint) if checkpoint else None
        )

        # State
        self.current_phase = "initializing"
        self.progress = 0
        self.session = None
        self.started_at = None
        self.completed_at = None

        # Results
        self.findings: List[Dict] = []
        self.overall_score = 100
        self.framework_scores: Dict[str, int] = {}

    async def run(self) -> Dict[str, Any]:
        """
        Execute the scan with checkpointing support.

        Returns scan results including findings and scores.
        """
        self.started_at = datetime.utcnow()
        logger.info(
            f"Starting scan orchestrator",
            scan_id=self.scan_id,
            url=self.url,
            scan_type=self.scan_type,
            resuming=self.initial_checkpoint is not None
        )

        try:
            # Import LiveScanSession here to avoid circular imports
            from app.live_scan import LiveScanSession

            # Create or restore session
            self.session = LiveScanSession(self.scan_id, self.url)

            # If resuming, restore state from checkpoint
            if self.initial_checkpoint:
                await self._restore_from_checkpoint()

            # Execute scan phases
            if self.scan_type == "quick":
                await self._run_quick_scan()
            elif self.scan_type == "deep":
                await self._run_deep_scan()
            elif self.scan_type == "autonomous":
                await self._run_autonomous_scan()
            else:
                await self._run_deep_scan()  # Default to deep

            # Compile results
            self.completed_at = datetime.utcnow()
            return self._compile_results()

        except asyncio.TimeoutError:
            logger.warning(f"Scan timed out", scan_id=self.scan_id)
            await self._save_checkpoint_on_error("timeout")
            raise ScanTimeoutError(
                scan_id=self.scan_id,
                timeout_seconds=settings.scan_timeout_seconds,
                phase=self.current_phase
            )

        except Exception as e:
            logger.error(f"Scan failed: {e}", scan_id=self.scan_id, exc_info=True)
            await self._save_checkpoint_on_error("error")
            raise ScanError(
                message=str(e),
                scan_id=self.scan_id,
                details={"phase": self.current_phase, "progress": self.progress}
            )

        finally:
            await self._cleanup()

    async def _run_quick_scan(self):
        """Execute a quick scan (limited scope)."""
        await self._update_phase("initializing")

        # Initialize browser and session
        await self._initialize_session()

        await self._update_phase("planning")
        # Quick scan: minimal planning
        await self.session._run_planning_phase()

        await self._update_phase("exploration")
        # Quick scan: limited exploration (max 10 pages)
        original_max = self.config.get("max_pages", settings.scan_max_pages)
        self.session.max_pages = min(10, original_max)
        await self.session._run_exploration_phase()

        await self._update_phase("security_testing")
        # Quick scan: basic tests only
        await self.session._run_security_testing_phase(quick_mode=True)

        await self._update_phase("reporting")
        await self._compile_findings()

    async def _run_deep_scan(self):
        """Execute a comprehensive deep scan."""
        # Check if we should skip phases based on checkpoint
        resume_point = None
        if self.initial_checkpoint:
            resume_point = calculate_resume_point(self.initial_checkpoint)
            logger.info(
                f"Resuming scan",
                resume_phase=resume_point.get("resume_phase"),
                skip_planning=resume_point.get("skip_planning", False)
            )

        # Phase 1: Initialize
        if not resume_point or not resume_point.get("skip_planning"):
            await self._update_phase("initializing")
            await self._initialize_session()

            # Phase 2: Planning
            await self._update_phase("planning")
            await self.session._run_planning_phase()
            await self._save_checkpoint("planning_complete")

        # Phase 3: Exploration
        if not resume_point or not resume_point.get("skip_exploration"):
            await self._update_phase("exploration")
            await self.session._run_exploration_phase()
            await self._save_checkpoint("exploration_complete")

        # Phase 4: API Discovery
        if not resume_point or not resume_point.get("skip_api_discovery"):
            await self._update_phase("api_discovery")
            await self.session._run_api_discovery_phase()
            await self._save_checkpoint("api_discovery_complete")

        # Phase 5: Security Testing
        await self._update_phase("security_testing")
        await self._run_security_testing_with_checkpoints(resume_point)

        # Phase 6: Reporting
        await self._update_phase("reporting")
        await self._compile_findings()

    async def _run_autonomous_scan(self):
        """Execute autonomous AI-driven scan."""
        # Autonomous scan uses the full AI capabilities
        await self._update_phase("initializing")
        await self._initialize_session()

        await self._update_phase("planning")
        # Enhanced planning with AI
        await self.session._run_planning_phase()
        await self._save_checkpoint("planning_complete")

        await self._update_phase("exploration")
        # AI-guided exploration
        await self.session._run_exploration_phase()
        await self._save_checkpoint("exploration_complete")

        await self._update_phase("api_discovery")
        await self.session._run_api_discovery_phase()
        await self._save_checkpoint("api_discovery_complete")

        await self._update_phase("security_testing")
        await self._run_security_testing_with_checkpoints(None)

        await self._update_phase("reporting")
        await self._compile_findings()

    async def _initialize_session(self):
        """Initialize the scan session and browser."""
        logger.info(f"Initializing scan session", scan_id=self.scan_id)

        # Let session handle browser initialization
        await self.session._initialize_browser()

        self.progress = self.PHASES["initializing"][1]

    async def _run_security_testing_with_checkpoints(
        self,
        resume_point: Optional[Dict]
    ):
        """
        Run security testing phase with periodic checkpoints.

        This is the longest phase, so we checkpoint more frequently here.
        """
        # Determine which tests to skip if resuming
        completed_test_ids = set()
        if resume_point and resume_point.get("completed_test_ids"):
            completed_test_ids = set(resume_point["completed_test_ids"])
            logger.info(
                f"Resuming security testing",
                completed_tests=len(completed_test_ids)
            )

        # Get all tests to run
        tests = self.session.security_tests[:]
        total_tests = len(tests)
        completed = 0

        for i, test in enumerate(tests):
            # Skip already completed tests
            test_id = getattr(test, "id", str(i))
            if test_id in completed_test_ids:
                completed += 1
                continue

            try:
                # Execute the test
                await self.session._execute_security_test(test)
                completed += 1

                # Update progress within phase
                phase_start, phase_end = self.PHASES["security_testing"]
                phase_range = phase_end - phase_start
                phase_progress = (completed / max(total_tests, 1)) * 100
                self.progress = phase_start + int((phase_progress / 100) * phase_range)

                # Checkpoint periodically
                if self.checkpoint_manager.should_checkpoint(
                    "security_testing",
                    force=(completed % 10 == 0)
                ):
                    await self._save_checkpoint("security_testing")

            except Exception as e:
                logger.warning(
                    f"Security test failed: {e}",
                    test_id=test_id,
                    exc_info=False
                )
                # Continue with next test

        logger.info(
            f"Security testing complete",
            total_tests=total_tests,
            completed=completed
        )

    async def _restore_from_checkpoint(self):
        """Restore session state from checkpoint."""
        if not self.initial_checkpoint:
            return

        logger.info(
            f"Restoring from checkpoint",
            phase=self.initial_checkpoint.phase,
            progress=self.initial_checkpoint.progress
        )

        state = self.checkpoint_manager.restore_state(self.initial_checkpoint)

        # Restore exploration state
        self.session.visited_urls = state["visited_urls"]
        self.session.pending_urls = state["pending_urls"]
        self.session.explored_elements = state["explored_elements"]

        # Restore findings
        self.session.findings = state["findings"]
        self.findings = state["findings"]

        # Restore stats
        self.session.stats = state["stats"]

        # Restore progress
        self.progress = state["progress"]
        self.current_phase = state["phase"]

        # Restore auth state
        if state.get("is_authenticated") and state.get("auth_cookies"):
            self.session.is_authenticated = True
            # Cookies would need to be restored to the browser context

    async def _save_checkpoint(self, phase: str):
        """Save a checkpoint at the current state."""
        if not self.checkpoint_manager.should_checkpoint(phase):
            return

        # Gather session state
        session_state = {
            "phase_progress": getattr(self.session, "phase_progress", 0),
            "visited_urls": getattr(self.session, "visited_urls", set()),
            "pending_urls": getattr(self.session, "pending_urls", []),
            "explored_elements": getattr(self.session, "explored_elements", set()),
            "apis": getattr(self.session, "apis", {}),
            "modules": getattr(self.session, "modules", {}),
            "journeys": getattr(self.session, "journeys", {}),
            "test_plan": getattr(self.session, "test_plan", None),
            "plan_notes": getattr(self.session, "plan_notes", []),
            "completed_tests": [
                getattr(t, "id", str(i))
                for i, t in enumerate(getattr(self.session, "security_tests", []))
                if getattr(t, "actual_result", None) is not None
            ],
            "pending_tests": [
                asdict(t) if hasattr(t, "__dict__") else t
                for t in getattr(self.session, "security_tests", [])
                if getattr(t, "actual_result", None) is None
            ],
            "findings": getattr(self.session, "findings", []),
            "stats": getattr(self.session, "stats", {}),
            "is_authenticated": getattr(self.session, "is_authenticated", False),
            "auth_cookies": None,  # Would need to extract from browser
        }

        checkpoint = self.checkpoint_manager.create_checkpoint(
            phase=phase,
            progress=self.progress,
            session_state=session_state
        )

        # Store checkpoint (this will be saved to DB by the caller)
        self.current_checkpoint = checkpoint.to_dict()

    async def _save_checkpoint_on_error(self, error_type: str):
        """Force save checkpoint when an error occurs."""
        try:
            await self._save_checkpoint(f"{self.current_phase}_error_{error_type}")
        except Exception as e:
            logger.error(f"Failed to save error checkpoint: {e}")

    async def _update_phase(self, phase: str):
        """Update current phase and progress."""
        self.current_phase = phase

        if phase in self.PHASES:
            self.progress = self.PHASES[phase][0]

        logger.info(
            f"Phase: {phase}",
            scan_id=self.scan_id,
            progress=self.progress
        )

        # Emit event if callback provided
        if self.event_callback:
            await self.event_callback({
                "type": "phase_changed",
                "phase": phase,
                "progress": self.progress,
                "timestamp": datetime.utcnow().isoformat()
            })

    async def _compile_findings(self):
        """Compile and score findings from the scan."""
        if not self.session:
            return

        # Get findings from session
        self.findings = getattr(self.session, "findings", [])
        vulnerabilities = getattr(self.session, "vulnerabilities", [])

        # Add vulnerabilities to findings
        for vuln in vulnerabilities:
            if vuln not in self.findings:
                self.findings.append(vuln)

        # Calculate overall score
        self.overall_score = self._calculate_score()

        # Calculate framework scores if applicable
        self.framework_scores = self._calculate_framework_scores()

        logger.info(
            f"Compiled findings",
            total_findings=len(self.findings),
            overall_score=self.overall_score
        )

    def _calculate_score(self) -> int:
        """Calculate overall security score based on findings."""
        if not self.findings:
            return 100

        # Deduct points based on severity
        deductions = {
            "critical": 25,
            "high": 15,
            "medium": 8,
            "low": 3,
            "info": 0,
        }

        total_deduction = 0
        for finding in self.findings:
            severity = finding.get("severity", "info").lower()
            total_deduction += deductions.get(severity, 0)

        # Score cannot go below 0
        return max(0, 100 - total_deduction)

    def _calculate_framework_scores(self) -> Dict[str, int]:
        """Calculate scores per security framework."""
        # Group findings by framework
        framework_findings: Dict[str, List] = {}

        for finding in self.findings:
            owasp = finding.get("owasp", "")
            if owasp:
                if owasp not in framework_findings:
                    framework_findings[owasp] = []
                framework_findings[owasp].append(finding)

        # Calculate score per framework
        scores = {}
        for framework, findings in framework_findings.items():
            scores[framework] = self._calculate_score_for_findings(findings)

        return scores

    def _calculate_score_for_findings(self, findings: List[Dict]) -> int:
        """Calculate score for a subset of findings."""
        if not findings:
            return 100

        deductions = {"critical": 30, "high": 20, "medium": 10, "low": 5, "info": 0}
        total_deduction = sum(
            deductions.get(f.get("severity", "info").lower(), 0)
            for f in findings
        )

        return max(0, 100 - total_deduction)

    def _compile_results(self) -> Dict[str, Any]:
        """Compile final scan results."""
        duration = None
        if self.started_at and self.completed_at:
            duration = (self.completed_at - self.started_at).total_seconds()

        return {
            "scan_id": self.scan_id,
            "url": self.url,
            "scan_type": self.scan_type,
            "status": "completed",
            "findings": self.findings,
            "findings_count": len(self.findings),
            "overall_score": self.overall_score,
            "framework_scores": self.framework_scores,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": duration,
            "stats": getattr(self.session, "stats", {}) if self.session else {},
        }

    async def _cleanup(self):
        """Clean up resources."""
        if self.session:
            try:
                await self.session._cleanup()
            except Exception as e:
                logger.warning(f"Cleanup error: {e}")

    def get_checkpoint(self) -> Optional[Dict]:
        """Get the current checkpoint data."""
        if hasattr(self, "current_checkpoint"):
            return self.current_checkpoint
        return None

    def get_status(self) -> Dict[str, Any]:
        """Get current orchestrator status."""
        return {
            "scan_id": self.scan_id,
            "phase": self.current_phase,
            "progress": self.progress,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "findings_count": len(self.findings),
        }
