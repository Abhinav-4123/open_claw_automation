"""
OpenClaw - The First Autonomous AI Company
Main API Server

This serves as the interface to the autonomous system.
The system runs independently - this is just for monitoring and manual overrides.
"""
import os
import asyncio
from datetime import datetime
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from dotenv import load_dotenv
load_dotenv()

# Initialize core components
from core import engine, brain
from agents import OrchestratorAgent, MarketingAgent, FeedbackAgent, ImproverAgent, spawner
from memory.database import get_memory

# Global state
engine_task: Optional[asyncio.Task] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown"""
    global engine_task

    print("=" * 60)
    print("  OPENCLAW - THE FIRST AUTONOMOUS AI COMPANY")
    print("=" * 60)
    print(f"  Starting at {datetime.now().isoformat()}")
    print("=" * 60)

    # Initialize database
    memory = get_memory()
    if not memory.get_mission():
        memory.initialize_mission(
            goal="$1M MRR",
            strategy={"phase": "launch", "channels": ["twitter", "linkedin"]}
        )

    # Start autonomous engine in background
    from core.engine import run_forever
    engine_task = asyncio.create_task(run_forever())

    print("  Autonomous engine started")
    print("=" * 60)

    yield

    # Shutdown
    print("Shutting down autonomous engine...")
    engine.stop()
    if engine_task:
        engine_task.cancel()


app = FastAPI(
    title="OpenClaw - Autonomous AI Company",
    description="The first fully autonomous AI-powered business",
    version="1.0.0",
    lifespan=lifespan
)


# ============================================
# STATUS ENDPOINTS (For you to check)
# ============================================

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Visual dashboard"""
    status = engine.get_status()
    brain_status = status.get("brain", {})
    metrics = brain_status.get("metrics", {})

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>OpenClaw - Autonomous Dashboard</title>
        <meta http-equiv="refresh" content="30">
        <style>
            body {{ font-family: -apple-system, sans-serif; background: #0a0a0a; color: #fff; padding: 20px; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            h1 {{ color: #00ff88; }}
            .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }}
            .card {{ background: #111; border: 1px solid #222; border-radius: 8px; padding: 20px; }}
            .card h3 {{ color: #888; font-size: 14px; margin: 0 0 10px 0; }}
            .card .value {{ font-size: 32px; font-weight: bold; }}
            .green {{ color: #00ff88; }}
            .red {{ color: #ff4444; }}
            .yellow {{ color: #ffcc00; }}
            .decisions {{ background: #111; border: 1px solid #222; border-radius: 8px; padding: 20px; margin-top: 20px; }}
            .decision {{ padding: 10px; border-bottom: 1px solid #222; }}
            .decision:last-child {{ border-bottom: none; }}
            .health {{ padding: 10px 20px; border-radius: 20px; display: inline-block; }}
            .health.healthy {{ background: #00ff8820; color: #00ff88; }}
            .health.degraded {{ background: #ffcc0020; color: #ffcc00; }}
            .health.critical {{ background: #ff444420; color: #ff4444; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🤖 OpenClaw - Autonomous Dashboard</h1>
            <p>Status: <span class="health {status.get('health', {}).get('status', 'healthy')}">{status.get('health', {}).get('status', 'Unknown').upper()}</span></p>
            <p>Health Score: {status.get('health', {}).get('score', 0)}/100 | Uptime: {status.get('engine', {}).get('uptime', '0')} | Cycles: {status.get('engine', {}).get('cycles', 0)}</p>

            <div class="grid">
                <div class="card">
                    <h3>OUTREACH SENT</h3>
                    <div class="value">{metrics.get('total_outreach', 0)}</div>
                </div>
                <div class="card">
                    <h3>RESPONSES</h3>
                    <div class="value green">{metrics.get('responses', 0)}</div>
                </div>
                <div class="card">
                    <h3>RESPONSE RATE</h3>
                    <div class="value yellow">{metrics.get('response_rate', '0%')}</div>
                </div>
                <div class="card">
                    <h3>CONVERSIONS</h3>
                    <div class="value green">{metrics.get('conversions', 0)}</div>
                </div>
            </div>

            <div class="grid">
                <div class="card">
                    <h3>CURRENT MRR</h3>
                    <div class="value green">{metrics.get('mrr', '$0')}</div>
                </div>
                <div class="card">
                    <h3>CUSTOMERS</h3>
                    <div class="value">{metrics.get('customers', 0)}</div>
                </div>
                <div class="card">
                    <h3>ACTIVE AGENTS</h3>
                    <div class="value">{brain_status.get('agents', {}).get('active', 0)}</div>
                </div>
                <div class="card">
                    <h3>GOAL</h3>
                    <div class="value">$1M MRR</div>
                </div>
            </div>

            <div class="decisions">
                <h2>Recent Autonomous Decisions</h2>
                {''.join([f'''
                <div class="decision">
                    <strong>{d.get('action', 'Unknown')}</strong>
                    <span class="{'green' if d.get('success') else 'red'}">{'✓' if d.get('success') else '✗'}</span>
                    <br><small>{d.get('reasoning', '')[:100]}...</small>
                    <br><small style="color: #666">{d.get('time', '')}</small>
                </div>
                ''' for d in brain_status.get('recent_decisions', [])])}
            </div>

            <p style="color: #666; margin-top: 20px;">Auto-refreshes every 30 seconds. Last updated: {datetime.now().isoformat()}</p>
        </div>
    </body>
    </html>
    """
    return html


@app.get("/status")
async def get_status():
    """Get full system status (JSON)"""
    return engine.get_status()


@app.get("/metrics")
async def get_metrics():
    """Get business metrics"""
    memory = get_memory()
    stats = memory.get_outreach_stats()
    mission = memory.get_mission()

    return {
        "outreach": stats,
        "mission": {
            "goal": mission.goal if mission else "$1M MRR",
            "current_mrr": mission.current_mrr if mission else 0,
            "customers": mission.customers if mission else 0
        },
        "timestamp": datetime.now().isoformat()
    }


@app.get("/agents")
async def list_agents():
    """List all agents"""
    return {
        "agents": [
            {
                "id": a.id,
                "role": a.role,
                "status": a.status,
                "tasks_completed": a.tasks_completed,
                "success_rate": a.success_rate
            }
            for a in brain.agents.values()
        ],
        "summary": {
            "total": len(brain.agents),
            "active": len([a for a in brain.agents.values() if a.status == "running"]),
            "failed": len([a for a in brain.agents.values() if a.status == "failed"])
        }
    }


@app.get("/decisions")
async def get_decisions():
    """Get recent decisions"""
    return {
        "decisions": [
            {
                "id": d.id,
                "type": d.type.value,
                "reasoning": d.reasoning,
                "success": d.success,
                "outcome": d.outcome,
                "timestamp": d.timestamp.isoformat()
            }
            for d in brain.decisions[-20:]
        ],
        "total": len(brain.decisions)
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    from core.health import HealthMonitor
    monitor = HealthMonitor()
    report = monitor.check()

    return {
        "score": report.score,
        "status": report.status,
        "issues": report.issues,
        "timestamp": report.timestamp.isoformat()
    }


# ============================================
# MANUAL OVERRIDE ENDPOINTS (Use sparingly)
# ============================================

class ManualAction(BaseModel):
    action: str
    parameters: dict = {}


@app.post("/manual/action")
async def manual_action(action: ManualAction, background_tasks: BackgroundTasks):
    """Manually trigger an action (emergency override)"""
    from core.brain import Decision, DecisionType

    decision = Decision(
        id=f"manual_{datetime.now().strftime('%H%M%S')}",
        timestamp=datetime.now(),
        type=DecisionType[action.action.upper()],
        reasoning="Manual override by owner",
        data=action.parameters
    )

    background_tasks.add_task(brain.execute_decision, decision)

    return {
        "status": "queued",
        "decision_id": decision.id,
        "action": action.action
    }


@app.post("/manual/spawn")
async def manual_spawn(agent_type: str = "marketing", platform: str = "twitter"):
    """Manually spawn an agent"""
    if agent_type == "marketing":
        agent = await spawner.spawn(
            role=f"Marketing-{platform}",
            agent_class=MarketingAgent,
            platform=platform
        )
    elif agent_type == "feedback":
        agent = await spawner.spawn(
            role="Feedback",
            agent_class=FeedbackAgent
        )
    elif agent_type == "improver":
        agent = await spawner.spawn(
            role="Improver",
            agent_class=ImproverAgent
        )
    else:
        raise HTTPException(400, "Invalid agent type")

    return {"agent_id": agent.agent_id, "role": agent.role}


@app.post("/manual/stop")
async def manual_stop():
    """Emergency stop (pauses autonomous operation)"""
    engine.stop()
    return {"status": "stopped", "message": "Autonomous engine stopped. Restart the server to resume."}


# ============================================
# FEEDBACK ENDPOINT (For product improvement)
# ============================================

@app.get("/feedback")
async def get_feedback():
    """Get collected feedback"""
    memory = get_memory()
    actionable = memory.get_actionable_feedback()

    return {
        "actionable": [
            {
                "id": f.id,
                "source": f.source,
                "user": f.user_handle,
                "feedback": f.raw_feedback,
                "sentiment": f.sentiment,
                "key_points": f.key_points
            }
            for f in actionable[:20]
        ],
        "total_actionable": len(actionable)
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
