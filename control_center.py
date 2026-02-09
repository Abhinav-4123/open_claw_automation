"""
Control Center - The command hub for the AI Company
Handles user inputs, file uploads, and directs agents
"""
import os
import json
import asyncio
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

from dotenv import load_dotenv
load_dotenv()


class TaskPriority(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class TaskStatus(Enum):
    PENDING = "pending"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    REVIEW = "review"
    COMPLETED = "completed"
    FAILED = "failed"


class TaskCategory(Enum):
    BUG_FIX = "bug_fix"
    FEATURE = "feature"
    MARKETING = "marketing"
    BRANDING = "branding"
    SALES = "sales"
    SUPPORT = "support"
    RESEARCH = "research"
    CONTENT = "content"
    OPERATIONS = "operations"
    OTHER = "other"


@dataclass
class UserInput:
    """A user input/command to the system"""
    id: str
    text: str
    category: TaskCategory
    priority: TaskPriority
    attachments: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    processed: bool = False
    assigned_to: Optional[str] = None
    result: Optional[Dict] = None


@dataclass
class CompanyTask:
    """A task in the company system"""
    id: str
    title: str
    description: str
    category: TaskCategory
    priority: TaskPriority
    status: TaskStatus
    created_at: datetime
    assigned_agent: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict] = None
    user_input_id: Optional[str] = None
    parent_task_id: Optional[str] = None
    subtasks: List[str] = field(default_factory=list)


class ControlCenter:
    """
    The Control Center - Central command for the AI Company.

    This is where:
    - User inputs are received and processed
    - Tasks are created and assigned to agents
    - Progress is tracked
    - Results are reported
    """

    def __init__(self):
        self.user_inputs: Dict[str, UserInput] = {}
        self.tasks: Dict[str, CompanyTask] = {}
        self.action_queue: List[Dict] = []
        self.notifications: List[Dict] = []

        # Track company metrics
        self.metrics = {
            "total_tasks": 0,
            "completed_tasks": 0,
            "active_tasks": 0,
            "revenue": 0,
            "customers": 0,
            "mrr": 0
        }

        # Agent assignments
        self.agent_workload: Dict[str, List[str]] = {}

    def receive_user_input(
            self,
            text: str,
            category: str = "other",
            priority: str = "medium",
            attachments: List[str] = None
    ) -> UserInput:
        """Receive and process user input"""

        input_id = f"input_{uuid.uuid4().hex[:8]}"

        user_input = UserInput(
            id=input_id,
            text=text,
            category=TaskCategory(category) if category in [e.value for e in TaskCategory] else TaskCategory.OTHER,
            priority=TaskPriority(priority) if priority in [e.value for e in TaskPriority] else TaskPriority.MEDIUM,
            attachments=attachments or []
        )

        self.user_inputs[input_id] = user_input

        # Auto-create task from input
        task = self._create_task_from_input(user_input)

        return user_input

    def _create_task_from_input(self, user_input: UserInput) -> CompanyTask:
        """Create a task from user input"""

        task_id = f"task_{uuid.uuid4().hex[:8]}"

        # Determine title from input
        title = user_input.text[:50] + "..." if len(user_input.text) > 50 else user_input.text

        task = CompanyTask(
            id=task_id,
            title=title,
            description=user_input.text,
            category=user_input.category,
            priority=user_input.priority,
            status=TaskStatus.PENDING,
            created_at=datetime.now(),
            user_input_id=user_input.id
        )

        self.tasks[task_id] = task
        self.metrics["total_tasks"] += 1
        self.metrics["active_tasks"] += 1

        # Add to action queue for processing
        self.action_queue.append({
            "type": "new_task",
            "task_id": task_id,
            "priority": user_input.priority.value,
            "timestamp": datetime.now().isoformat()
        })

        return task

    def assign_task(self, task_id: str, agent_id: str) -> bool:
        """Assign a task to an agent"""
        if task_id not in self.tasks:
            return False

        task = self.tasks[task_id]
        task.assigned_agent = agent_id
        task.status = TaskStatus.ASSIGNED

        # Track agent workload
        if agent_id not in self.agent_workload:
            self.agent_workload[agent_id] = []
        self.agent_workload[agent_id].append(task_id)

        return True

    def update_task_status(self, task_id: str, status: str, result: Dict = None) -> bool:
        """Update task status"""
        if task_id not in self.tasks:
            return False

        task = self.tasks[task_id]
        task.status = TaskStatus(status)

        if status == "in_progress" and not task.started_at:
            task.started_at = datetime.now()

        if status == "completed":
            task.completed_at = datetime.now()
            task.result = result
            self.metrics["completed_tasks"] += 1
            self.metrics["active_tasks"] -= 1

            # Notify user
            self.notifications.append({
                "type": "task_completed",
                "task_id": task_id,
                "title": task.title,
                "timestamp": datetime.now().isoformat()
            })

        if status == "failed":
            self.metrics["active_tasks"] -= 1
            self.notifications.append({
                "type": "task_failed",
                "task_id": task_id,
                "title": task.title,
                "timestamp": datetime.now().isoformat()
            })

        return True

    def get_pending_tasks(self) -> List[CompanyTask]:
        """Get all pending tasks sorted by priority"""
        pending = [t for t in self.tasks.values() if t.status == TaskStatus.PENDING]
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        return sorted(pending, key=lambda x: priority_order.get(x.priority.value, 4))

    def get_active_tasks(self) -> List[CompanyTask]:
        """Get all in-progress tasks"""
        active_statuses = [TaskStatus.ASSIGNED, TaskStatus.IN_PROGRESS, TaskStatus.REVIEW]
        return [t for t in self.tasks.values() if t.status in active_statuses]

    def get_completed_tasks(self, limit: int = 20) -> List[CompanyTask]:
        """Get recently completed tasks"""
        completed = [t for t in self.tasks.values() if t.status == TaskStatus.COMPLETED]
        return sorted(completed, key=lambda x: x.completed_at or datetime.min, reverse=True)[:limit]

    def get_tasks_by_category(self, category: str) -> List[CompanyTask]:
        """Get tasks by category"""
        return [t for t in self.tasks.values() if t.category.value == category]

    def get_notifications(self, unread_only: bool = True, limit: int = 10) -> List[Dict]:
        """Get notifications"""
        return self.notifications[-limit:]

    def clear_notifications(self):
        """Clear all notifications"""
        self.notifications = []

    def get_dashboard_data(self) -> Dict:
        """Get all data needed for dashboard"""
        pending = self.get_pending_tasks()
        active = self.get_active_tasks()
        completed = self.get_completed_tasks(10)

        return {
            "metrics": self.metrics,
            "pending_tasks": [
                {
                    "id": t.id,
                    "title": t.title,
                    "category": t.category.value,
                    "priority": t.priority.value,
                    "created_at": t.created_at.isoformat()
                }
                for t in pending[:10]
            ],
            "active_tasks": [
                {
                    "id": t.id,
                    "title": t.title,
                    "category": t.category.value,
                    "assigned_to": t.assigned_agent,
                    "status": t.status.value,
                    "started_at": t.started_at.isoformat() if t.started_at else None
                }
                for t in active
            ],
            "recent_completed": [
                {
                    "id": t.id,
                    "title": t.title,
                    "category": t.category.value,
                    "completed_at": t.completed_at.isoformat() if t.completed_at else None
                }
                for t in completed
            ],
            "notifications": self.get_notifications(),
            "agent_workload": {
                agent: len(tasks)
                for agent, tasks in self.agent_workload.items()
            },
            "timestamp": datetime.now().isoformat()
        }

    def update_revenue(self, amount: float, customer_id: str = None):
        """Update revenue metrics"""
        self.metrics["revenue"] += amount
        if customer_id:
            self.metrics["customers"] += 1

    def set_mrr(self, mrr: float):
        """Set current MRR"""
        self.metrics["mrr"] = mrr


# Global control center instance
control_center = ControlCenter()
