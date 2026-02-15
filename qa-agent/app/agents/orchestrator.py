"""
NEXUS QA - Orchestrator Agent
Central coordinator for multi-agent system with bidirectional communication.
"""

import asyncio
import uuid
import logging
from datetime import datetime
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Type
from enum import Enum

from .base import (
    BaseAgent, AgentMessage, MessageType, AgentStatus,
    TaskContext, AgentResult, RecoverableError
)

logger = logging.getLogger(__name__)


class ScanPhase(str, Enum):
    """Phases of the autonomous scan."""
    INITIALIZING = "initializing"
    PRODUCT_ANALYSIS = "product_analysis"
    EXPLORATION = "exploration"
    PLANNING = "planning"
    SECURITY_TESTING = "security_testing"
    REPORT_GENERATION = "report_generation"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ScanSession:
    """Complete scan session state."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    url: str = ""
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    phase: ScanPhase = ScanPhase.INITIALIZING
    status: str = "running"

    # Aggregated results from agents
    product_profile: Dict[str, Any] = field(default_factory=dict)
    journeys: List[Dict] = field(default_factory=list)
    api_inventory: List[Dict] = field(default_factory=list)
    test_plan: Dict[str, Any] = field(default_factory=dict)
    security_findings: List[Dict] = field(default_factory=list)
    report_path: Optional[str] = None

    # Agent tracking
    agent_statuses: Dict[str, Dict] = field(default_factory=dict)
    phase_results: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    # Progress
    overall_progress: float = 0.0
    estimated_remaining_seconds: int = 0


class Orchestrator:
    """
    Central orchestrator for multi-agent autonomous scanning.

    Responsibilities:
    - Manage agent lifecycle
    - Route messages between agents
    - Handle failures and recovery
    - Aggregate results
    - Track overall progress
    """

    PHASE_WEIGHTS = {
        ScanPhase.PRODUCT_ANALYSIS: 10,
        ScanPhase.EXPLORATION: 30,
        ScanPhase.PLANNING: 10,
        ScanPhase.SECURITY_TESTING: 40,
        ScanPhase.REPORT_GENERATION: 10,
    }

    def __init__(self):
        self.sessions: Dict[str, ScanSession] = {}
        self.agents: Dict[str, BaseAgent] = {}
        self.message_queue: asyncio.Queue = asyncio.Queue()
        self._running = False
        self._message_handler_task: Optional[asyncio.Task] = None

    async def start(self):
        """Start the orchestrator message handling loop."""
        self._running = True
        self._message_handler_task = asyncio.create_task(self._message_loop())
        logger.info("Orchestrator started")

    async def stop(self):
        """Stop the orchestrator."""
        self._running = False
        if self._message_handler_task:
            self._message_handler_task.cancel()
            try:
                await self._message_handler_task
            except asyncio.CancelledError:
                pass
        logger.info("Orchestrator stopped")

    async def _message_loop(self):
        """Main message handling loop."""
        while self._running:
            try:
                msg = await asyncio.wait_for(
                    self.message_queue.get(),
                    timeout=1.0
                )
                await self._handle_message(msg)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.exception(f"Message handling error: {e}")

    async def _handle_message(self, msg: AgentMessage):
        """Route and handle incoming messages."""
        logger.debug(f"Orchestrator received: {msg.message_type} from {msg.from_agent}")

        # Update session with agent status
        for session in self.sessions.values():
            if msg.from_agent in session.agent_statuses:
                self._update_agent_status(session, msg)

        # Handle message types
        if msg.message_type == MessageType.PROGRESS:
            await self._handle_progress(msg)

        elif msg.message_type == MessageType.PHASE_COMPLETE:
            await self._handle_phase_complete(msg)

        elif msg.message_type == MessageType.REQUEST_DATA:
            await self._route_data_request(msg)

        elif msg.message_type == MessageType.DATA_RESPONSE:
            await self._route_data_response(msg)

        elif msg.message_type == MessageType.ERROR:
            await self._handle_error(msg)

        elif msg.message_type == MessageType.BLOCKED:
            await self._handle_blocked(msg)

    def _update_agent_status(self, session: ScanSession, msg: AgentMessage):
        """Update agent status in session."""
        if msg.from_agent not in session.agent_statuses:
            session.agent_statuses[msg.from_agent] = {}

        status = session.agent_statuses[msg.from_agent]
        status["last_message"] = msg.message_type.value
        status["last_update"] = datetime.now().isoformat()

        if msg.message_type == MessageType.PROGRESS:
            status["progress"] = msg.payload.get("progress", 0)
            status["message"] = msg.payload.get("message", "")

    async def _handle_progress(self, msg: AgentMessage):
        """Handle progress updates from agents."""
        # Update overall progress calculation
        for session in self.sessions.values():
            if msg.from_agent in session.agent_statuses:
                self._calculate_overall_progress(session)

    async def _handle_phase_complete(self, msg: AgentMessage):
        """Handle phase completion from an agent."""
        agent_type = msg.from_agent.split("_")[0]
        result = msg.payload

        # Store result in appropriate session
        for session in self.sessions.values():
            if msg.from_agent in session.agent_statuses:
                session.phase_results[agent_type] = result

                # Transition phase based on completed agent
                if agent_type == "pm":
                    session.product_profile = result.get("result", {})
                elif agent_type == "explorer":
                    session.journeys = result.get("result", {}).get("journeys", [])
                elif agent_type == "devtools":
                    session.api_inventory = result.get("result", {}).get("apis", [])
                elif agent_type == "planner":
                    session.test_plan = result.get("result", {})
                elif agent_type == "security":
                    session.security_findings.extend(
                        result.get("result", {}).get("findings", [])
                    )
                elif agent_type == "report":
                    session.report_path = result.get("result", {}).get("report_path")

    async def _route_data_request(self, msg: AgentMessage):
        """Route data request to target agent."""
        if msg.to_agent in self.agents:
            await self.agents[msg.to_agent].receive_message(msg)
        else:
            # Agent not available, send error response
            error_response = AgentMessage(
                to_agent=msg.from_agent,
                message_type=MessageType.DATA_RESPONSE,
                payload={"error": f"Agent {msg.to_agent} not available"},
                correlation_id=msg.id
            )
            if msg.from_agent in self.agents:
                await self.agents[msg.from_agent].receive_message(error_response)

    async def _route_data_response(self, msg: AgentMessage):
        """Route data response back to requesting agent."""
        if msg.to_agent in self.agents:
            await self.agents[msg.to_agent].receive_message(msg)

    async def _handle_error(self, msg: AgentMessage):
        """Handle errors from agents."""
        error = msg.payload.get("error", "Unknown error")
        recoverable = msg.payload.get("recoverable", True)

        for session in self.sessions.values():
            if msg.from_agent in session.agent_statuses:
                session.errors.append(f"{msg.from_agent}: {error}")

                if not recoverable:
                    session.agent_statuses[msg.from_agent]["status"] = "failed"

        logger.error(f"Agent error from {msg.from_agent}: {error}")

    async def _handle_blocked(self, msg: AgentMessage):
        """Handle blocked agents."""
        reason = msg.payload.get("reason", "Unknown")
        needs_human = msg.payload.get("needs_human", False)

        logger.warning(f"Agent {msg.from_agent} blocked: {reason}")

        if needs_human:
            # Create clarification request
            # This would integrate with the clarification system
            pass
        else:
            # Try automatic recovery
            await self._attempt_recovery(msg.from_agent, reason)

    async def _attempt_recovery(self, agent_name: str, reason: str):
        """Attempt to recover a blocked agent."""
        if agent_name in self.agents:
            agent = self.agents[agent_name]
            # Send retry message with hints
            await agent.receive_message(AgentMessage(
                from_agent="orchestrator",
                message_type=MessageType.RETRY,
                payload={"hint": "skip_and_continue", "reason": reason}
            ))

    def _calculate_overall_progress(self, session: ScanSession):
        """Calculate overall scan progress."""
        phase_progress = {
            ScanPhase.PRODUCT_ANALYSIS: 0.0,
            ScanPhase.EXPLORATION: 0.0,
            ScanPhase.PLANNING: 0.0,
            ScanPhase.SECURITY_TESTING: 0.0,
            ScanPhase.REPORT_GENERATION: 0.0,
        }

        # Map agents to phases
        agent_phase_map = {
            "pm": ScanPhase.PRODUCT_ANALYSIS,
            "explorer": ScanPhase.EXPLORATION,
            "devtools": ScanPhase.EXPLORATION,
            "planner": ScanPhase.PLANNING,
            "security": ScanPhase.SECURITY_TESTING,
            "api_tester": ScanPhase.SECURITY_TESTING,
            "ui_tester": ScanPhase.SECURITY_TESTING,
            "report": ScanPhase.REPORT_GENERATION,
        }

        for agent_name, status in session.agent_statuses.items():
            agent_type = agent_name.split("_")[0]
            if agent_type in agent_phase_map:
                phase = agent_phase_map[agent_type]
                progress = status.get("progress", 0)
                # Average if multiple agents in same phase
                phase_progress[phase] = max(phase_progress[phase], progress)

        # Calculate weighted overall progress
        total = 0.0
        for phase, weight in self.PHASE_WEIGHTS.items():
            total += (phase_progress[phase] / 100.0) * weight

        session.overall_progress = total

    async def receive_message(self, msg: AgentMessage):
        """Receive message from an agent."""
        await self.message_queue.put(msg)

    def register_agent(self, agent: BaseAgent):
        """Register an agent with the orchestrator."""
        self.agents[agent.name] = agent
        agent.set_orchestrator_callback(self.receive_message)
        logger.info(f"Registered agent: {agent.name}")

    def unregister_agent(self, agent_name: str):
        """Unregister an agent."""
        if agent_name in self.agents:
            del self.agents[agent_name]
            logger.info(f"Unregistered agent: {agent_name}")

    async def run_scan(
        self,
        url: str,
        agent_classes: List[Type[BaseAgent]],
        config: Dict[str, Any] = None
    ) -> ScanSession:
        """
        Run a complete autonomous scan.

        Args:
            url: Target URL to scan
            agent_classes: List of agent classes to use
            config: Additional configuration

        Returns:
            ScanSession with complete results
        """
        session = ScanSession(url=url)
        self.sessions[session.id] = session

        context = TaskContext(
            session_id=session.id,
            url=url,
            config=config or {},
            shared_data={},
            timeout_seconds=3600  # 1 hour max
        )

        try:
            # Start orchestrator message handling
            await self.start()

            # Phase 1: Product Analysis (PM Agent)
            session.phase = ScanPhase.PRODUCT_ANALYSIS
            await self._run_phase_1(session, context, agent_classes)

            # Phase 2: Exploration (Explorer + DevTools - parallel)
            session.phase = ScanPhase.EXPLORATION
            await self._run_phase_2(session, context, agent_classes)

            # Phase 3: Planning
            session.phase = ScanPhase.PLANNING
            await self._run_phase_3(session, context, agent_classes)

            # Phase 4: Security Testing (parallel)
            session.phase = ScanPhase.SECURITY_TESTING
            await self._run_phase_4(session, context, agent_classes)

            # Phase 5: Report Generation
            session.phase = ScanPhase.REPORT_GENERATION
            await self._run_phase_5(session, context, agent_classes)

            session.phase = ScanPhase.COMPLETED
            session.status = "completed"

        except Exception as e:
            session.phase = ScanPhase.FAILED
            session.status = "failed"
            session.errors.append(str(e))
            logger.exception(f"Scan failed: {e}")

        finally:
            session.completed_at = datetime.now()
            await self.stop()

        return session

    async def _run_phase_1(
        self,
        session: ScanSession,
        context: TaskContext,
        agent_classes: List[Type[BaseAgent]]
    ):
        """Phase 1: Product Analysis with PM Agent."""
        from .pm_agent import PMAgent

        pm_class = next(
            (c for c in agent_classes if c.agent_type == "pm"),
            PMAgent
        )

        agent = pm_class()
        self.register_agent(agent)
        session.agent_statuses[agent.name] = {"status": "starting"}

        result = await agent.run(context)

        if result.success:
            context.shared_data["product_profile"] = result.data
            session.product_profile = result.data

        self.unregister_agent(agent.name)

    async def _run_phase_2(
        self,
        session: ScanSession,
        context: TaskContext,
        agent_classes: List[Type[BaseAgent]]
    ):
        """Phase 2: Exploration with Explorer + DevTools (parallel)."""
        from .explorer_agent import ExplorerAgent
        from .devtools_agent import DevToolsAgent

        explorer_class = next(
            (c for c in agent_classes if c.agent_type == "explorer"),
            ExplorerAgent
        )
        devtools_class = next(
            (c for c in agent_classes if c.agent_type == "devtools"),
            DevToolsAgent
        )

        explorer = explorer_class()
        devtools = devtools_class()

        self.register_agent(explorer)
        self.register_agent(devtools)

        session.agent_statuses[explorer.name] = {"status": "starting"}
        session.agent_statuses[devtools.name] = {"status": "starting"}

        # Run in parallel
        results = await asyncio.gather(
            explorer.run(context),
            devtools.run(context),
            return_exceptions=True
        )

        # Process results
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                session.errors.append(str(result))
            elif result.success:
                if i == 0:  # Explorer
                    context.shared_data["journeys"] = result.data.get("journeys", [])
                    session.journeys = result.data.get("journeys", [])
                else:  # DevTools
                    context.shared_data["api_inventory"] = result.data.get("apis", [])
                    session.api_inventory = result.data.get("apis", [])

        self.unregister_agent(explorer.name)
        self.unregister_agent(devtools.name)

    async def _run_phase_3(
        self,
        session: ScanSession,
        context: TaskContext,
        agent_classes: List[Type[BaseAgent]]
    ):
        """Phase 3: Test Planning."""
        from .planner_agent import PlannerAgent

        planner_class = next(
            (c for c in agent_classes if c.agent_type == "planner"),
            PlannerAgent
        )

        agent = planner_class()
        self.register_agent(agent)
        session.agent_statuses[agent.name] = {"status": "starting"}

        result = await agent.run(context)

        if result.success:
            context.shared_data["test_plan"] = result.data
            session.test_plan = result.data

        self.unregister_agent(agent.name)

    async def _run_phase_4(
        self,
        session: ScanSession,
        context: TaskContext,
        agent_classes: List[Type[BaseAgent]]
    ):
        """Phase 4: Security Testing (parallel)."""
        from .security_agent import SecurityAgent

        security_class = next(
            (c for c in agent_classes if c.agent_type == "security"),
            SecurityAgent
        )

        agent = security_class()
        self.register_agent(agent)
        session.agent_statuses[agent.name] = {"status": "starting"}

        result = await agent.run(context)

        if result.success:
            session.security_findings = result.data.get("findings", [])
            context.shared_data["security_findings"] = session.security_findings

        self.unregister_agent(agent.name)

    async def _run_phase_5(
        self,
        session: ScanSession,
        context: TaskContext,
        agent_classes: List[Type[BaseAgent]]
    ):
        """Phase 5: Report Generation."""
        from .report_agent import ReportAgent

        report_class = next(
            (c for c in agent_classes if c.agent_type == "report"),
            ReportAgent
        )

        agent = report_class()
        self.register_agent(agent)
        session.agent_statuses[agent.name] = {"status": "starting"}

        result = await agent.run(context)

        if result.success:
            session.report_path = result.data.get("report_path")

        self.unregister_agent(agent.name)

    def get_session(self, session_id: str) -> Optional[ScanSession]:
        """Get a scan session by ID."""
        return self.sessions.get(session_id)

    def get_session_dict(self, session_id: str) -> Optional[Dict]:
        """Get session as dictionary for API response."""
        session = self.get_session(session_id)
        if not session:
            return None

        return {
            "id": session.id,
            "url": session.url,
            "started_at": session.started_at.isoformat(),
            "completed_at": session.completed_at.isoformat() if session.completed_at else None,
            "phase": session.phase.value,
            "status": session.status,
            "overall_progress": session.overall_progress,
            "product_profile": session.product_profile,
            "journeys_count": len(session.journeys),
            "apis_count": len(session.api_inventory),
            "findings_count": len(session.security_findings),
            "report_path": session.report_path,
            "errors": session.errors[-10:],
            "agent_statuses": session.agent_statuses
        }
