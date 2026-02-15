"""
NEXUS QA - Base Agent Class
Foundation for all autonomous agents with lifecycle management and communication.
"""

import asyncio
import uuid
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Callable

logger = logging.getLogger(__name__)


class MessageType(str, Enum):
    """Agent communication message types."""
    # Status updates
    HEARTBEAT = "heartbeat"
    PROGRESS = "progress"
    PHASE_COMPLETE = "phase_complete"

    # Coordination
    REQUEST_DATA = "request_data"
    DATA_RESPONSE = "data_response"
    HANDOFF = "handoff"
    START_TASK = "start_task"

    # Errors
    ERROR = "error"
    BLOCKED = "blocked"
    RETRY = "retry"
    AGENT_FAILED = "agent_failed"

    # Human in loop
    CLARIFICATION_NEEDED = "clarification_needed"
    CLARIFICATION_RESPONSE = "clarification_response"


class AgentStatus(str, Enum):
    """Agent lifecycle states."""
    IDLE = "idle"
    STARTING = "starting"
    RUNNING = "running"
    WAITING = "waiting"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class AgentMessage:
    """Message for inter-agent communication."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    from_agent: str = ""
    to_agent: str = ""
    message_type: MessageType = MessageType.HEARTBEAT
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    requires_response: bool = False
    timeout_seconds: int = 60
    correlation_id: Optional[str] = None  # For request/response matching


@dataclass
class AgentResult:
    """Result from agent execution."""
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    partial: bool = False
    duration_seconds: float = 0.0


@dataclass
class TaskContext:
    """Context passed to agents for execution."""
    session_id: str
    url: str
    config: Dict[str, Any] = field(default_factory=dict)
    shared_data: Dict[str, Any] = field(default_factory=dict)  # Data from other agents
    credentials: Dict[str, str] = field(default_factory=dict)
    timeout_seconds: int = 300


class BaseAgent(ABC):
    """
    Base class for all NEXUS QA agents.

    Each agent:
    - Has a unique name and type
    - Runs independently with own lifecycle
    - Communicates via message passing
    - Reports progress to orchestrator
    - Handles failures gracefully
    """

    agent_type: str = "base"

    def __init__(self, name: Optional[str] = None):
        self.name = name or f"{self.agent_type}_{uuid.uuid4().hex[:6]}"
        self.status = AgentStatus.IDLE
        self.progress = 0.0
        self.current_task: Optional[str] = None
        self.message_queue: asyncio.Queue = asyncio.Queue()
        self.response_futures: Dict[str, asyncio.Future] = {}
        self._orchestrator_callback: Optional[Callable] = None
        self._running = False
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        self.errors: List[str] = []

    def set_orchestrator_callback(self, callback: Callable):
        """Set callback for sending messages to orchestrator."""
        self._orchestrator_callback = callback

    async def send_message(self, msg: AgentMessage):
        """Send message to orchestrator for routing."""
        msg.from_agent = self.name
        if self._orchestrator_callback:
            await self._orchestrator_callback(msg)

    async def receive_message(self, msg: AgentMessage):
        """Receive message from orchestrator."""
        await self.message_queue.put(msg)

        # If this is a response to a pending request, resolve the future
        if msg.correlation_id and msg.correlation_id in self.response_futures:
            self.response_futures[msg.correlation_id].set_result(msg)

    async def request_data(
        self,
        from_agent: str,
        data_type: str,
        params: Dict = None,
        timeout: int = 30
    ) -> Optional[Dict]:
        """Request data from another agent via orchestrator."""
        msg = AgentMessage(
            to_agent=from_agent,
            message_type=MessageType.REQUEST_DATA,
            payload={"data_type": data_type, "params": params or {}},
            requires_response=True,
            timeout_seconds=timeout
        )

        # Create future for response
        future = asyncio.get_event_loop().create_future()
        self.response_futures[msg.id] = future

        await self.send_message(msg)

        try:
            response = await asyncio.wait_for(future, timeout=timeout)
            return response.payload.get("data")
        except asyncio.TimeoutError:
            logger.warning(f"{self.name}: Timeout waiting for {data_type} from {from_agent}")
            return None
        finally:
            self.response_futures.pop(msg.id, None)

    async def report_progress(self, progress: float, message: str = ""):
        """Report progress to orchestrator."""
        self.progress = min(100.0, max(0.0, progress))
        await self.send_message(AgentMessage(
            to_agent="orchestrator",
            message_type=MessageType.PROGRESS,
            payload={"progress": self.progress, "message": message}
        ))

    async def report_blocked(self, reason: str, needs_human: bool = False):
        """Report that agent is blocked."""
        self.status = AgentStatus.BLOCKED
        await self.send_message(AgentMessage(
            to_agent="orchestrator",
            message_type=MessageType.BLOCKED,
            payload={"reason": reason, "needs_human": needs_human}
        ))

    async def report_error(self, error: str, recoverable: bool = True):
        """Report error to orchestrator."""
        self.errors.append(error)
        await self.send_message(AgentMessage(
            to_agent="orchestrator",
            message_type=MessageType.ERROR,
            payload={"error": error, "recoverable": recoverable}
        ))

    async def complete(self, result: AgentResult):
        """Mark agent as complete with result."""
        self.status = AgentStatus.COMPLETED
        self.end_time = datetime.now()
        self.progress = 100.0
        await self.send_message(AgentMessage(
            to_agent="orchestrator",
            message_type=MessageType.PHASE_COMPLETE,
            payload={
                "result": result.data,
                "success": result.success,
                "error": result.error,
                "partial": result.partial,
                "duration": result.duration_seconds
            }
        ))

    async def run(self, context: TaskContext) -> AgentResult:
        """Execute the agent's main task with error handling."""
        self._running = True
        self.status = AgentStatus.RUNNING
        self.start_time = datetime.now()
        self.errors = []

        try:
            await self.report_progress(0, f"Starting {self.agent_type}")
            result = await self.execute(context)
            await self.complete(result)
            return result

        except asyncio.CancelledError:
            logger.info(f"{self.name}: Cancelled")
            self.status = AgentStatus.FAILED
            return AgentResult(success=False, error="Cancelled")

        except Exception as e:
            error_msg = f"{self.agent_type} error: {str(e)}"
            logger.exception(f"{self.name}: {error_msg}")
            self.status = AgentStatus.FAILED
            await self.report_error(error_msg, recoverable=False)
            return AgentResult(success=False, error=error_msg)

        finally:
            self._running = False
            self.end_time = datetime.now()

    @abstractmethod
    async def execute(self, context: TaskContext) -> AgentResult:
        """
        Main execution logic - implemented by subclasses.

        Args:
            context: TaskContext with URL, config, and shared data

        Returns:
            AgentResult with success status and data
        """
        pass

    def get_status_dict(self) -> Dict[str, Any]:
        """Get agent status as dictionary."""
        return {
            "name": self.name,
            "type": self.agent_type,
            "status": self.status.value,
            "progress": self.progress,
            "current_task": self.current_task,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "errors": self.errors[-5:] if self.errors else []  # Last 5 errors
        }


class RecoverableError(Exception):
    """Error that can be recovered from with retry or alternative approach."""
    def __init__(self, message: str, recovery_hint: str = ""):
        super().__init__(message)
        self.recovery_hint = recovery_hint


class FatalError(Exception):
    """Error that cannot be recovered from - agent should stop."""
    pass


class BlockedError(Exception):
    """Agent is blocked and needs external intervention."""
    def __init__(self, message: str, needs_human: bool = False):
        super().__init__(message)
        self.needs_human = needs_human
