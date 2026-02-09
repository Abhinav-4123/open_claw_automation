"""
OpenClaw - AI Company Control Center
"""
import os
import json
import asyncio
from datetime import datetime
from typing import Optional, List, Dict
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, File, UploadFile, Form
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from dotenv import load_dotenv
load_dotenv()

from control_center import control_center
from agents.chef import chef
from agents.coder import coder

engine_running = True
cycle_count = 0
startup_time = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global startup_time
    startup_time = datetime.now()

    print("=" * 60)
    print("  OPENCLAW - AI COMPANY CONTROL CENTER")
    print("=" * 60)

    await chef.create_agent("marketing")
    await chef.create_agent("coder")
    await chef.create_agent("branding")
    await chef.create_agent("sales")

    asyncio.create_task(run_engine())

    yield
    print("Shutting down...")


async def run_engine():
    global cycle_count, engine_running

    while engine_running:
        cycle_count += 1
        pending = control_center.get_pending_tasks()

        for task in pending[:3]:
            agent_type = {
                "bug_fix": "coder", "feature": "coder",
                "marketing": "marketing", "branding": "branding",
                "sales": "sales"
            }.get(task.category.value, "marketing")

            agents = [a for a in chef.agent_registry.values()
                      if a["type"] == agent_type and a["status"] == "active"]

            if agents:
                control_center.assign_task(task.id, agents[0]["id"])
                control_center.update_task_status(task.id, "in_progress")

        await asyncio.sleep(30)


app = FastAPI(title="OpenClaw", version="2.0.0", lifespan=lifespan)


def render_tasks(tasks, task_class):
    if not tasks:
        return '<div style="text-align:center;padding:30px;color:#666;">No tasks</div>'

    html = ""
    for t in tasks:
        title = t.get('title', 'Unknown')
        cat = t.get('category', 'other')
        pri = t.get('priority', 'medium')
        html += f'''<div style="background:#1a1a2e;border-radius:8px;padding:15px;margin-bottom:10px;border-left:3px solid #00ccff;">
            <h5 style="font-size:14px;margin-bottom:4px;">{title}</h5>
            <p style="font-size:12px;color:#666;">{cat} | {pri}</p>
        </div>'''
    return html


def render_agents(agents):
    if not agents:
        return '<div style="text-align:center;padding:30px;color:#666;">No agents</div>'

    html = ""
    for a in agents:
        agent_type = a.get('type', 'unknown')
        status = a.get('status', 'unknown')
        tasks = a.get('tasks_completed', 0)
        color = '#00ff88' if status == 'active' else '#ff4444'
        html += f'''<div style="background:#1a1a2e;border-radius:8px;padding:12px;margin-bottom:10px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <h5 style="font-size:13px;">{agent_type.title()}</h5>
                <div style="width:8px;height:8px;border-radius:50%;background:{color};"></div>
            </div>
            <p style="font-size:11px;color:#666;">Tasks: {tasks}</p>
        </div>'''
    return html


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    global cycle_count, startup_time

    data = control_center.get_dashboard_data()
    agents = chef.get_all_agents()
    uptime = str(datetime.now() - startup_time).split('.')[0] if startup_time else "0:00:00"

    metrics = data.get('metrics', {})
    active_html = render_tasks(data.get('active_tasks', []), 'active')
    pending_html = render_tasks(data.get('pending_tasks', []), 'pending')
    completed_html = render_tasks(data.get('recent_completed', []), 'completed')
    agents_html = render_agents(agents)

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>OpenClaw Control Center</title>
    <meta http-equiv="refresh" content="15">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: system-ui, sans-serif; background: #0a0a0f; color: #e0e0e0; min-height: 100vh; }}
        .header {{ background: #1a1a2e; padding: 20px 30px; border-bottom: 1px solid #333; display: flex; justify-content: space-between; align-items: center; }}
        .header h1 {{ font-size: 24px; color: #00ff88; }}
        .header-stats {{ display: flex; gap: 30px; font-size: 14px; color: #888; }}
        .header-stats span {{ color: #00ff88; font-weight: 600; }}
        .main {{ display: grid; grid-template-columns: 300px 1fr 300px; min-height: calc(100vh - 80px); }}
        .panel {{ padding: 20px; }}
        .left {{ background: #111; border-right: 1px solid #222; }}
        .right {{ background: #111; border-left: 1px solid #222; }}
        h2 {{ font-size: 16px; color: #00ccff; margin-bottom: 15px; }}
        .form {{ background: #1a1a2e; border-radius: 12px; padding: 15px; }}
        .form label {{ display: block; font-size: 12px; color: #888; margin-bottom: 5px; }}
        .form textarea, .form select, .form input {{ width: 100%; background: #0a0a0f; border: 1px solid #333; border-radius: 8px; padding: 10px; color: #fff; font-size: 14px; margin-bottom: 10px; }}
        .form textarea {{ min-height: 100px; resize: vertical; }}
        .form button {{ width: 100%; background: linear-gradient(90deg, #00ff88, #00ccff); border: none; border-radius: 8px; padding: 12px; color: #000; font-weight: 600; cursor: pointer; }}
        .metrics {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-bottom: 25px; }}
        .metric {{ background: #1a1a2e; border: 1px solid #222; border-radius: 12px; padding: 20px; text-align: center; }}
        .metric h4 {{ font-size: 11px; color: #666; text-transform: uppercase; }}
        .metric .val {{ font-size: 32px; font-weight: 700; margin-top: 5px; }}
        .green {{ color: #00ff88; }}
        .blue {{ color: #00ccff; }}
        .yellow {{ color: #ffcc00; }}
        .section {{ background: #111; border: 1px solid #222; border-radius: 12px; padding: 20px; margin-bottom: 20px; }}
        .section h3 {{ font-size: 14px; color: #888; margin-bottom: 15px; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>OpenClaw Control Center</h1>
            <p style="color:#666;font-size:12px;margin-top:4px;">AI Company Command Hub</p>
        </div>
        <div class="header-stats">
            <div>Status: <span>RUNNING</span></div>
            <div>Uptime: <span>{uptime}</span></div>
            <div>Cycle: <span>{cycle_count}</span></div>
            <div>Agents: <span>{len(agents)}</span></div>
        </div>
    </div>

    <div class="main">
        <div class="panel left">
            <h2>Command Center</h2>
            <form class="form" action="/api/submit-task" method="POST" enctype="multipart/form-data">
                <label>What do you need?</label>
                <textarea name="description" placeholder="Describe your task..."></textarea>

                <label>Category</label>
                <select name="category">
                    <option value="bug_fix">Bug Fix</option>
                    <option value="feature">New Feature</option>
                    <option value="marketing">Marketing</option>
                    <option value="branding">Branding</option>
                    <option value="sales">Sales</option>
                    <option value="other">Other</option>
                </select>

                <label>Priority</label>
                <select name="priority">
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                    <option value="low">Low</option>
                </select>

                <label>Attachments</label>
                <input type="file" name="attachments" multiple>

                <button type="submit">Submit Task</button>
            </form>
        </div>

        <div class="panel">
            <div class="metrics">
                <div class="metric">
                    <h4>Total Tasks</h4>
                    <div class="val blue">{metrics.get('total_tasks', 0)}</div>
                </div>
                <div class="metric">
                    <h4>Active</h4>
                    <div class="val yellow">{metrics.get('active_tasks', 0)}</div>
                </div>
                <div class="metric">
                    <h4>Completed</h4>
                    <div class="val green">{metrics.get('completed_tasks', 0)}</div>
                </div>
                <div class="metric">
                    <h4>Revenue</h4>
                    <div class="val green">${metrics.get('revenue', 0):,.0f}</div>
                </div>
                <div class="metric">
                    <h4>MRR</h4>
                    <div class="val green">${metrics.get('mrr', 0):,.0f}</div>
                </div>
            </div>

            <div class="section">
                <h3>Active Tasks</h3>
                {active_html}
            </div>

            <div class="section">
                <h3>Pending Tasks</h3>
                {pending_html}
            </div>

            <div class="section">
                <h3>Recently Completed</h3>
                {completed_html}
            </div>
        </div>

        <div class="panel right">
            <h2>AI Workforce</h2>
            {agents_html}
        </div>
    </div>
</body>
</html>"""


class TaskSubmission(BaseModel):
    description: str
    category: str = "other"
    priority: str = "medium"


@app.post("/api/submit-task")
async def submit_task(
        description: str = Form(...),
        category: str = Form("other"),
        priority: str = Form("medium"),
        attachments: List[UploadFile] = File(None)
):
    attachment_contents = []
    if attachments:
        for file in attachments:
            if file.filename:
                content = await file.read()
                try:
                    attachment_contents.append(f"File: {file.filename}\n{content.decode('utf-8')}")
                except:
                    attachment_contents.append(f"File: {file.filename} (binary)")

    control_center.receive_user_input(
        text=description,
        category=category,
        priority=priority,
        attachments=attachment_contents
    )

    return HTMLResponse(content='<script>window.location.href="/";</script>')


@app.post("/api/create-agent")
async def create_agent(agent_type: str):
    agent = await chef.create_agent(agent_type)
    return {"status": "created", "agent": agent}


@app.get("/api/status")
async def get_status():
    return {
        "uptime": str(datetime.now() - startup_time) if startup_time else "0",
        "cycles": cycle_count,
        "agents": len(chef.get_all_agents()),
        "tasks": control_center.get_dashboard_data()
    }


@app.get("/health")
async def health():
    return {"status": "healthy", "cycles": cycle_count}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
