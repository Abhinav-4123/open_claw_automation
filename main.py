"""
OpenClaw - Autonomous Marketing Swarm
Main API Server with Live Dashboard
"""
import os
import asyncio
from datetime import datetime
from typing import Optional, List, Dict
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

# Track user action items
USER_ACTION_ITEMS: List[Dict] = []


def add_user_action(action_type: str, title: str, description: str, priority: str = "medium"):
    """Add an item that needs user attention"""
    USER_ACTION_ITEMS.append({
        "id": f"action_{datetime.now().strftime('%H%M%S')}",
        "type": action_type,
        "title": title,
        "description": description,
        "priority": priority,
        "created_at": datetime.now().isoformat(),
        "completed": False
    })


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown"""
    global engine_task

    print("=" * 60)
    print("  OPENCLAW - AUTONOMOUS MARKETING SWARM")
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

    # Check for missing configurations and add user action items
    if not os.getenv("TWITTER_API_KEY"):
        add_user_action("authentication", "Twitter API Keys Required",
                       "Add TWITTER_API_KEY, TWITTER_API_SECRET to .env for Twitter outreach", "high")

    if not os.getenv("SMTP_USER"):
        add_user_action("authentication", "Email SMTP Required",
                       "Add SMTP_USER and SMTP_PASS to .env for email notifications", "medium")

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
    title="OpenClaw - Autonomous Marketing Swarm",
    description="AI-powered autonomous marketing system",
    version="1.0.0",
    lifespan=lifespan
)


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Live Dashboard - Shows ongoing tasks, planned tasks, and user actions needed"""
    status = engine.get_status()
    brain_status = status.get("brain", {})
    metrics = brain_status.get("metrics", {})
    health = status.get("health", {})
    engine_status = status.get("engine", {})

    # Get active agents for ongoing tasks
    active_agents = [a for a in brain.agents.values() if a.status == "running"]

    # Pending user actions
    pending_actions = [a for a in USER_ACTION_ITEMS if not a.get("completed")]

    # Recent decisions
    recent_decisions = brain_status.get("recent_decisions", [])[-5:]

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>OpenClaw Dashboard</title>
        <meta http-equiv="refresh" content="15">
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 100%);
                color: #fff;
                min-height: 100vh;
                padding: 20px;
            }}
            .container {{ max-width: 1400px; margin: 0 auto; }}

            .header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 30px;
                padding-bottom: 20px;
                border-bottom: 1px solid #333;
            }}
            .header h1 {{
                font-size: 28px;
                background: linear-gradient(90deg, #00ff88, #00ccff);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }}
            .status-badge {{
                padding: 8px 16px;
                border-radius: 20px;
                font-size: 14px;
                font-weight: 600;
            }}
            .status-healthy {{ background: rgba(0, 255, 136, 0.2); color: #00ff88; }}
            .status-degraded {{ background: rgba(255, 204, 0, 0.2); color: #ffcc00; }}
            .status-critical {{ background: rgba(255, 68, 68, 0.2); color: #ff4444; }}

            .metrics-grid {{
                display: grid;
                grid-template-columns: repeat(5, 1fr);
                gap: 15px;
                margin-bottom: 30px;
            }}
            .metric-card {{
                background: rgba(255,255,255,0.05);
                border: 1px solid rgba(255,255,255,0.1);
                border-radius: 12px;
                padding: 20px;
                text-align: center;
            }}
            .metric-card h4 {{ color: #888; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }}
            .metric-card .value {{ font-size: 36px; font-weight: 700; margin-top: 8px; }}
            .green {{ color: #00ff88; }}
            .yellow {{ color: #ffcc00; }}
            .blue {{ color: #00ccff; }}
            .red {{ color: #ff4444; }}

            .main-grid {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; }}

            .section {{
                background: rgba(255,255,255,0.03);
                border: 1px solid rgba(255,255,255,0.08);
                border-radius: 16px;
                padding: 20px;
            }}
            .section h2 {{
                font-size: 16px;
                color: #aaa;
                margin-bottom: 15px;
                display: flex;
                align-items: center;
                gap: 8px;
            }}
            .section h2 .icon {{ font-size: 20px; }}

            .task-item {{
                background: rgba(255,255,255,0.05);
                border-radius: 8px;
                padding: 12px;
                margin-bottom: 10px;
            }}
            .task-item.running {{ border-left: 3px solid #00ff88; }}
            .task-item.pending {{ border-left: 3px solid #ffcc00; }}
            .task-item.action {{ border-left: 3px solid #ff4444; }}
            .task-item h5 {{ font-size: 14px; margin-bottom: 4px; }}
            .task-item p {{ font-size: 12px; color: #888; }}
            .task-item .badge {{
                display: inline-block;
                padding: 2px 8px;
                border-radius: 4px;
                font-size: 10px;
                text-transform: uppercase;
            }}
            .badge-high {{ background: rgba(255, 68, 68, 0.2); color: #ff4444; }}
            .badge-medium {{ background: rgba(255, 204, 0, 0.2); color: #ffcc00; }}
            .badge-low {{ background: rgba(0, 204, 255, 0.2); color: #00ccff; }}

            .decision-item {{
                padding: 10px;
                border-bottom: 1px solid rgba(255,255,255,0.05);
            }}
            .decision-item:last-child {{ border-bottom: none; }}
            .decision-item .action {{
                font-weight: 600;
                color: #00ccff;
            }}
            .decision-item .time {{
                font-size: 11px;
                color: #666;
            }}
            .decision-item .reasoning {{
                font-size: 12px;
                color: #888;
                margin-top: 4px;
            }}

            .footer {{
                margin-top: 30px;
                text-align: center;
                color: #666;
                font-size: 12px;
            }}

            .empty-state {{
                text-align: center;
                padding: 30px;
                color: #666;
            }}
            .empty-state .icon {{ font-size: 40px; margin-bottom: 10px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div>
                    <h1>OpenClaw Dashboard</h1>
                    <p style="color: #666; margin-top: 5px;">Autonomous Marketing Swarm</p>
                </div>
                <div style="text-align: right;">
                    <span class="status-badge status-{health.get('status', 'healthy')}">
                        {health.get('status', 'RUNNING').upper()}
                    </span>
                    <p style="color: #666; font-size: 12px; margin-top: 5px;">
                        Health: {health.get('score', 100)}/100 | Cycles: {engine_status.get('cycles', 0)}
                    </p>
                </div>
            </div>

            <div class="metrics-grid">
                <div class="metric-card">
                    <h4>Outreach Sent</h4>
                    <div class="value blue">{metrics.get('total_outreach', 0)}</div>
                </div>
                <div class="metric-card">
                    <h4>Responses</h4>
                    <div class="value green">{metrics.get('responses', 0)}</div>
                </div>
                <div class="metric-card">
                    <h4>Response Rate</h4>
                    <div class="value yellow">{metrics.get('response_rate', '0%')}</div>
                </div>
                <div class="metric-card">
                    <h4>Current MRR</h4>
                    <div class="value green">{metrics.get('mrr', '$0')}</div>
                </div>
                <div class="metric-card">
                    <h4>Active Agents</h4>
                    <div class="value">{brain_status.get('agents', {}).get('active', 0) if isinstance(brain_status.get('agents'), dict) else 0}</div>
                </div>
            </div>

            <div class="main-grid">
                <!-- User Actions Required -->
                <div class="section">
                    <h2><span class="icon">⚠️</span> Your Action Required</h2>
                    {''.join([f'''
                    <div class="task-item action">
                        <span class="badge badge-{a.get('priority', 'medium')}">{a.get('priority', 'medium')}</span>
                        <h5>{a.get('title', 'Unknown')}</h5>
                        <p>{a.get('description', '')}</p>
                    </div>
                    ''' for a in pending_actions]) if pending_actions else '''
                    <div class="empty-state">
                        <div class="icon">✅</div>
                        <p>No actions needed from you</p>
                    </div>
                    '''}
                </div>

                <!-- Ongoing Tasks -->
                <div class="section">
                    <h2><span class="icon">🔄</span> Currently Running</h2>
                    {''.join([f'''
                    <div class="task-item running">
                        <h5>{a.role}</h5>
                        <p>ID: {a.id} | Tasks: {a.tasks_completed}</p>
                    </div>
                    ''' for a in active_agents]) if active_agents else '''
                    <div class="empty-state">
                        <div class="icon">💤</div>
                        <p>No agents currently running</p>
                        <p style="font-size: 11px; margin-top: 5px;">Agents spawn automatically when needed</p>
                    </div>
                    '''}
                </div>

                <!-- Planned / Next Up -->
                <div class="section">
                    <h2><span class="icon">📋</span> Next Planned</h2>
                    <div class="task-item pending">
                        <h5>Twitter Outreach</h5>
                        <p>Target: 25 potential customers</p>
                    </div>
                    <div class="task-item pending">
                        <h5>LinkedIn Outreach</h5>
                        <p>Target: 25 potential customers</p>
                    </div>
                    <div class="task-item pending">
                        <h5>Feedback Collection</h5>
                        <p>Analyze responses hourly</p>
                    </div>
                    <div class="task-item pending">
                        <h5>Strategy Optimization</h5>
                        <p>Adjust based on response rates</p>
                    </div>
                </div>
            </div>

            <!-- Recent Activity -->
            <div class="section" style="margin-top: 20px;">
                <h2><span class="icon">📜</span> Recent Decisions</h2>
                {''.join([f'''
                <div class="decision-item">
                    <span class="action">{d.get('action', 'Unknown')}</span>
                    <span class="{'green' if d.get('success') else 'red'}"> {'✓' if d.get('success') else '✗'}</span>
                    <span class="time">{d.get('time', '')}</span>
                    <p class="reasoning">{d.get('reasoning', 'No details')[:150]}</p>
                </div>
                ''' for d in recent_decisions]) if recent_decisions else '''
                <div class="empty-state">
                    <div class="icon">🤖</div>
                    <p>Autonomous decisions will appear here</p>
                </div>
                '''}
            </div>

            <div class="footer">
                <p>Auto-refreshes every 15 seconds | Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p style="margin-top: 5px;">Goal: $1M MRR | Strategy: Outreach</p>
            </div>
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


@app.get("/actions")
async def get_user_actions():
    """Get pending user action items"""
    return {
        "pending": [a for a in USER_ACTION_ITEMS if not a.get("completed")],
        "completed": [a for a in USER_ACTION_ITEMS if a.get("completed")]
    }


@app.post("/actions/{action_id}/complete")
async def complete_action(action_id: str):
    """Mark a user action as complete"""
    for action in USER_ACTION_ITEMS:
        if action["id"] == action_id:
            action["completed"] = True
            return {"status": "completed", "action_id": action_id}
    raise HTTPException(404, "Action not found")


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


# Manual override endpoints
class ManualAction(BaseModel):
    action: str
    parameters: dict = {}


@app.post("/manual/action")
async def manual_action(action: ManualAction, background_tasks: BackgroundTasks):
    """Manually trigger an action"""
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


@app.post("/manual/stop")
async def manual_stop():
    """Emergency stop"""
    engine.stop()
    return {"status": "stopped", "message": "Autonomous engine stopped. Restart the server to resume."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
