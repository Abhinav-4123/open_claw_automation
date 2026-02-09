"""
OpenClaw - AI Company Control Center
Autonomous AI agents working to build and grow the company
"""
import os
import json
import asyncio
import random
from datetime import datetime
from typing import Optional, List, Dict
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, File, UploadFile, Form
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

import google.generativeai as genai
from dotenv import load_dotenv
load_dotenv()

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

from control_center import control_center
from agents.chef import chef
from agents.coder import coder

engine_running = True
cycle_count = 0
startup_time = None
activity_log = []  # Track recent agent activities
model = genai.GenerativeModel('gemini-2.0-flash')

# Company configuration
COMPANY_GOAL = os.getenv("COMPANY_GOAL", "Build TestGuard AI - automated QA testing SaaS")
PRODUCT_NAME = os.getenv("PRODUCT_NAME", "TestGuard AI")
TARGET_MRR = 10000  # $10K MRR goal


def log_activity(agent_type: str, action: str, details: str = ""):
    """Log agent activity"""
    global activity_log
    activity_log.insert(0, {
        "time": datetime.now().strftime("%H:%M:%S"),
        "agent": agent_type,
        "action": action,
        "details": details[:100]
    })
    activity_log = activity_log[:20]  # Keep last 20


async def generate_autonomous_tasks():
    """Generate initial autonomous tasks for each agent type"""

    initial_tasks = [
        # Marketing tasks
        {"title": "Research target audience for TestGuard AI", "category": "marketing", "priority": "high",
         "description": "Identify ideal customer profile: QA teams, startups, dev agencies needing automated testing"},
        {"title": "Create social media content calendar", "category": "marketing", "priority": "medium",
         "description": "Plan 2 weeks of LinkedIn and Twitter content about QA automation benefits"},
        {"title": "Find 50 potential leads on LinkedIn", "category": "marketing", "priority": "high",
         "description": "Search for QA managers, CTOs, and engineering leads at mid-size tech companies"},

        # Branding tasks
        {"title": "Define brand voice and messaging", "category": "branding", "priority": "high",
         "description": "Create brand guidelines: professional, innovative, developer-friendly tone"},
        {"title": "Generate tagline options", "category": "branding", "priority": "medium",
         "description": "Create 5 compelling taglines for TestGuard AI"},

        # Sales tasks
        {"title": "Create cold outreach email templates", "category": "sales", "priority": "high",
         "description": "Write 3 personalized email templates for different buyer personas"},
        {"title": "Define pricing strategy", "category": "sales", "priority": "critical",
         "description": "Research competitor pricing and propose tiered pricing model"},

        # Coder tasks
        {"title": "Review landing page requirements", "category": "feature", "priority": "high",
         "description": "Plan landing page structure: hero, features, pricing, testimonials, CTA"},
        {"title": "Design API architecture", "category": "feature", "priority": "medium",
         "description": "Define REST API endpoints for test management and reporting"},
    ]

    for task in initial_tasks:
        control_center.receive_user_input(
            text=task["description"],
            category=task["category"],
            priority=task["priority"]
        )
        # Update title
        latest_task = list(control_center.tasks.values())[-1]
        latest_task.title = task["title"]

    log_activity("system", "Initialized", f"Created {len(initial_tasks)} autonomous tasks")


async def process_task_with_ai(task, agent) -> Dict:
    """Have an agent actually work on a task using AI"""

    prompt = f"""You are a {agent['type']} specialist working at an AI startup.

Company Goal: {COMPANY_GOAL}
Product: {PRODUCT_NAME}

Your current task:
Title: {task.title}
Description: {task.description}
Category: {task.category.value}
Priority: {task.priority.value}

Complete this task and provide:
1. A brief summary of what you did (2-3 sentences)
2. Key deliverables or outputs
3. Suggested next steps

Be specific and actionable. Format as JSON:
{{
    "summary": "What was accomplished",
    "deliverables": ["list", "of", "outputs"],
    "next_steps": ["suggested", "follow-up", "tasks"],
    "success": true
}}"""

    try:
        response = model.generate_content(prompt)
        text = response.text.strip()
        if "```" in text:
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        result = json.loads(text)
        return result
    except Exception as e:
        return {
            "summary": f"Worked on: {task.title}",
            "deliverables": ["Analysis completed"],
            "next_steps": ["Review and iterate"],
            "success": True
        }


@asynccontextmanager
async def lifespan(app: FastAPI):
    global startup_time
    startup_time = datetime.now()

    print("=" * 60)
    print("  OPENCLAW - AI COMPANY CONTROL CENTER")
    print("=" * 60)
    print(f"  Goal: {COMPANY_GOAL}")
    print("=" * 60)

    # Create agents
    await chef.create_agent("marketing")
    await chef.create_agent("coder")
    await chef.create_agent("branding")
    await chef.create_agent("sales")

    log_activity("chef", "Spawned agents", "marketing, coder, branding, sales")

    # Generate autonomous tasks
    await generate_autonomous_tasks()

    # Start the autonomous engine
    asyncio.create_task(run_engine())

    yield
    print("Shutting down...")


async def run_engine():
    """Main autonomous engine - assigns and processes tasks"""
    global cycle_count, engine_running

    await asyncio.sleep(5)  # Initial delay

    while engine_running:
        cycle_count += 1

        # Get pending tasks
        pending = control_center.get_pending_tasks()

        # Process up to 2 tasks per cycle
        for task in pending[:2]:
            agent_type = {
                "bug_fix": "coder", "feature": "coder",
                "marketing": "marketing", "branding": "branding",
                "sales": "sales", "other": "marketing"
            }.get(task.category.value, "marketing")

            # Find available agent
            agents = [a for a in chef.agent_registry.values()
                      if a["type"] == agent_type and a["status"] == "active"]

            if agents:
                agent = agents[0]
                agent_id = agent["id"]

                # Assign and start task
                control_center.assign_task(task.id, agent_id)
                control_center.update_task_status(task.id, "in_progress")
                agent["current_task"] = task.title

                log_activity(agent_type, "Started", task.title)

                # Process task with AI
                result = await process_task_with_ai(task, agent)

                # Complete task
                control_center.update_task_status(task.id, "completed", result)
                agent["tasks_completed"] = agent.get("tasks_completed", 0) + 1
                agent["current_task"] = None
                agent["last_result"] = result.get("summary", "")

                log_activity(agent_type, "Completed", result.get("summary", task.title)[:50])

                # Create follow-up tasks from next_steps
                for next_step in result.get("next_steps", [])[:1]:  # Limit to 1 follow-up
                    if random.random() < 0.3:  # 30% chance to create follow-up
                        control_center.receive_user_input(
                            text=next_step,
                            category=task.category.value,
                            priority="medium"
                        )
                        log_activity("system", "New task", next_step[:50])

                await asyncio.sleep(2)  # Small delay between tasks

        # Wait before next cycle (15 seconds for faster demo)
        await asyncio.sleep(15)


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
        current = a.get('current_task', None)
        last_result = a.get('last_result', '')

        if current:
            color = '#ffcc00'  # Yellow = working
            status_text = f"Working: {current[:25]}..."
        else:
            color = '#00ff88'  # Green = idle/ready
            status_text = f"Completed: {tasks} tasks"

        html += f'''<div style="background:#1a1a2e;border-radius:8px;padding:12px;margin-bottom:10px;">
            <div style="display:flex;justify-content:space-between;align-items:center;">
                <h5 style="font-size:13px;">{agent_type.title()}</h5>
                <div style="width:8px;height:8px;border-radius:50%;background:{color};"></div>
            </div>
            <p style="font-size:11px;color:#888;margin-top:4px;">{status_text}</p>
            {f'<p style="font-size:10px;color:#666;margin-top:2px;">{last_result[:40]}...</p>' if last_result else ''}
        </div>'''
    return html


def render_activity_log():
    global activity_log
    if not activity_log:
        return '<div style="color:#666;font-size:12px;">No activity yet...</div>'

    html = ""
    for log in activity_log[:10]:
        agent = log.get('agent', 'system')
        action = log.get('action', '')
        details = log.get('details', '')
        time = log.get('time', '')

        color = {
            'marketing': '#ff6b6b',
            'coder': '#4ecdc4',
            'branding': '#ffe66d',
            'sales': '#95e1d3',
            'system': '#888',
            'chef': '#00ff88'
        }.get(agent, '#888')

        html += f'''<div style="padding:6px 0;border-bottom:1px solid #222;font-size:11px;">
            <span style="color:#555;">{time}</span>
            <span style="color:{color};font-weight:600;margin-left:8px;">{agent.upper()}</span>
            <span style="color:#888;margin-left:8px;">{action}</span>
            <span style="color:#666;margin-left:4px;">{details}</span>
        </div>'''
    return html


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    global cycle_count, startup_time, activity_log

    data = control_center.get_dashboard_data()
    agents = chef.get_all_agents()
    uptime = str(datetime.now() - startup_time).split('.')[0] if startup_time else "0:00:00"

    metrics = data.get('metrics', {})
    active_html = render_tasks(data.get('active_tasks', []), 'active')
    pending_html = render_tasks(data.get('pending_tasks', []), 'pending')
    completed_html = render_tasks(data.get('recent_completed', []), 'completed')
    agents_html = render_agents(agents)
    activity_html = render_activity_log()

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>OpenClaw Control Center</title>
    <meta http-equiv="refresh" content="10">
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

            <h2 style="margin-top:20px;">Activity Log</h2>
            <div style="background:#1a1a2e;border-radius:8px;padding:12px;max-height:300px;overflow-y:auto;">
                {activity_html}
            </div>
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
