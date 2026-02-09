"""
Shared Memory - PostgreSQL database for agent communication
All agents read/write here to coordinate
"""
import os
import json
from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy import create_engine, Column, String, Text, DateTime, Integer, JSON, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./openclaw.db")

# Use SQLite for local dev, PostgreSQL for production
if "sqlite" in DATABASE_URL:
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
else:
    engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class AgentRecord(Base):
    """Track all spawned agents"""
    __tablename__ = "agents"

    id = Column(String, primary_key=True)
    role = Column(String, index=True)
    status = Column(String, default="running")  # running, completed, failed
    instructions = Column(Text)
    spawned_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    result = Column(JSON, nullable=True)
    parent_id = Column(String, nullable=True)  # Which agent spawned this one


class Task(Base):
    """Tasks assigned to agents"""
    __tablename__ = "tasks"

    id = Column(String, primary_key=True)
    agent_id = Column(String, index=True)
    task_type = Column(String)  # outreach, feedback, improvement
    target = Column(String)  # e.g., Twitter handle, company name
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    result = Column(JSON, nullable=True)


class Outreach(Base):
    """Track all outreach attempts"""
    __tablename__ = "outreach"

    id = Column(String, primary_key=True)
    platform = Column(String)  # twitter, linkedin, reddit, email
    target_handle = Column(String)
    target_name = Column(String, nullable=True)
    message_sent = Column(Text)
    sent_at = Column(DateTime, default=datetime.utcnow)
    response_received = Column(Boolean, default=False)
    response_text = Column(Text, nullable=True)
    response_at = Column(DateTime, nullable=True)
    sentiment = Column(String, nullable=True)  # positive, negative, neutral
    converted = Column(Boolean, default=False)


class Feedback(Base):
    """Collect and store feedback"""
    __tablename__ = "feedback"

    id = Column(String, primary_key=True)
    source = Column(String)  # twitter, email, demo_call
    user_handle = Column(String)
    raw_feedback = Column(Text)
    sentiment = Column(String)
    key_points = Column(JSON)  # extracted insights
    actionable = Column(Boolean, default=False)
    action_taken = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ProductIteration(Base):
    """Track product improvements"""
    __tablename__ = "iterations"

    id = Column(String, primary_key=True)
    version = Column(String)
    changes = Column(JSON)  # list of changes made
    triggered_by = Column(JSON)  # feedback IDs that triggered this
    created_at = Column(DateTime, default=datetime.utcnow)
    deployed = Column(Boolean, default=False)


class Mission(Base):
    """The overall mission/goal"""
    __tablename__ = "mission"

    id = Column(String, primary_key=True)
    goal = Column(Text)  # e.g., "$1M MRR"
    current_mrr = Column(Integer, default=0)
    customers = Column(Integer, default=0)
    strategy = Column(JSON)  # current strategy
    last_updated = Column(DateTime, default=datetime.utcnow)


# Create tables
Base.metadata.create_all(bind=engine)


class Memory:
    """Shared memory interface for all agents"""

    def __init__(self):
        self.db = SessionLocal()

    def close(self):
        self.db.close()

    # Agent Management
    def register_agent(self, agent_id: str, role: str, instructions: str, parent_id: str = None):
        agent = AgentRecord(
            id=agent_id,
            role=role,
            instructions=instructions,
            parent_id=parent_id
        )
        self.db.add(agent)
        self.db.commit()
        return agent

    def update_agent_status(self, agent_id: str, status: str, result: dict = None):
        agent = self.db.query(AgentRecord).filter(AgentRecord.id == agent_id).first()
        if agent:
            agent.status = status
            agent.result = result
            if status in ["completed", "failed"]:
                agent.completed_at = datetime.utcnow()
            self.db.commit()

    def get_active_agents(self) -> List[AgentRecord]:
        return self.db.query(AgentRecord).filter(AgentRecord.status == "running").all()

    # Outreach Tracking
    def log_outreach(self, platform: str, target_handle: str, message: str, target_name: str = None) -> str:
        import uuid
        outreach_id = str(uuid.uuid4())[:8]
        outreach = Outreach(
            id=outreach_id,
            platform=platform,
            target_handle=target_handle,
            target_name=target_name,
            message_sent=message
        )
        self.db.add(outreach)
        self.db.commit()
        return outreach_id

    def log_response(self, outreach_id: str, response: str, sentiment: str):
        outreach = self.db.query(Outreach).filter(Outreach.id == outreach_id).first()
        if outreach:
            outreach.response_received = True
            outreach.response_text = response
            outreach.response_at = datetime.utcnow()
            outreach.sentiment = sentiment
            self.db.commit()

    def get_outreach_stats(self) -> Dict:
        total = self.db.query(Outreach).count()
        responded = self.db.query(Outreach).filter(Outreach.response_received == True).count()
        converted = self.db.query(Outreach).filter(Outreach.converted == True).count()
        return {
            "total_sent": total,
            "responses": responded,
            "response_rate": responded / total if total > 0 else 0,
            "conversions": converted,
            "conversion_rate": converted / total if total > 0 else 0
        }

    # Feedback Management
    def store_feedback(self, source: str, user_handle: str, raw_feedback: str,
                       sentiment: str, key_points: List[str], actionable: bool = False) -> str:
        import uuid
        feedback_id = str(uuid.uuid4())[:8]
        feedback = Feedback(
            id=feedback_id,
            source=source,
            user_handle=user_handle,
            raw_feedback=raw_feedback,
            sentiment=sentiment,
            key_points=key_points,
            actionable=actionable
        )
        self.db.add(feedback)
        self.db.commit()
        return feedback_id

    def get_actionable_feedback(self) -> List[Feedback]:
        return self.db.query(Feedback).filter(
            Feedback.actionable == True,
            Feedback.action_taken == None
        ).all()

    def mark_feedback_actioned(self, feedback_id: str, action: str):
        feedback = self.db.query(Feedback).filter(Feedback.id == feedback_id).first()
        if feedback:
            feedback.action_taken = action
            self.db.commit()

    # Mission Management
    def get_mission(self) -> Optional[Mission]:
        return self.db.query(Mission).first()

    def update_mission(self, mrr: int = None, customers: int = None, strategy: dict = None):
        mission = self.get_mission()
        if mission:
            if mrr is not None:
                mission.current_mrr = mrr
            if customers is not None:
                mission.customers = customers
            if strategy is not None:
                mission.strategy = strategy
            mission.last_updated = datetime.utcnow()
            self.db.commit()

    def initialize_mission(self, goal: str, strategy: dict):
        mission = Mission(
            id="main",
            goal=goal,
            strategy=strategy
        )
        self.db.add(mission)
        self.db.commit()


def get_memory() -> Memory:
    return Memory()
