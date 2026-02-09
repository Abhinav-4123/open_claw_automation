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
from agents.queen import queen
from agents.overseer import overseer
from agents.sovereign import sovereign
from agents.oracle import oracle
from agents.bookie import bookie
from agent_personalities import AGENT_PERSONALITIES, get_agent_display, get_agent_card_html

engine_running = True

# User action items tracking
user_action_items = []
cycle_count = 0
startup_time = None
activity_log = []  # Track recent agent activities
daily_goals = []  # Queen's daily goals
model = genai.GenerativeModel('gemini-2.0-flash')

# Company configuration
COMPANY_GOAL = os.getenv("COMPANY_GOAL", "Build VibeSecurity - AI-powered security analysis platform")
PRODUCT_NAME = os.getenv("PRODUCT_NAME", "VibeSecurity")
TARGET_MRR = 10000  # $10K MRR goal

# Security Frameworks
SECURITY_FRAMEWORKS = {
    "VAPT": ["Network scanning", "Web app testing", "API security", "Auth testing"],
    "ISO 27001": ["Access control", "Cryptography", "Operations security", "Compliance"],
    "OWASP Top 10": ["Injection", "Broken Auth", "XSS", "SSRF", "Security Misconfiguration"],
    "PCI DSS": ["Secure network", "Protect data", "Vulnerability mgmt", "Access control"],
    "SOC 2": ["Security", "Availability", "Processing Integrity", "Confidentiality"]
}


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
    global startup_time, daily_goals
    startup_time = datetime.now()

    print("=" * 60)
    print("  VIBESECURITY - AI COMPANY CONTROL CENTER")
    print("=" * 60)
    print(f"  Goal: {COMPANY_GOAL}")
    print("=" * 60)

    # Queen creates managed agents (with error handling)
    try:
        await queen.create_managed_agent("product_manager", "Product Strategy & Roadmap")
        await queen.create_managed_agent("programme_manager", "Execution & Delivery")
        log_activity("queen", "Created PMs", "product_manager, programme_manager")
    except Exception as e:
        log_activity("queen", "Error", f"Could not create PMs: {str(e)[:50]}")

    # Chef creates worker agents (predefined blueprints - no API call needed)
    try:
        await chef.create_agent("marketing")
        await chef.create_agent("coder")
        await chef.create_agent("branding")
        await chef.create_agent("sales")
        log_activity("chef", "Spawned agents", "marketing, coder, branding, sales")
    except Exception as e:
        log_activity("chef", "Error", f"Could not spawn agents: {str(e)[:50]}")

    # Queen generates daily goals (minimum 4)
    try:
        daily_goals = await queen.generate_daily_goals(COMPANY_GOAL)
        log_activity("queen", "Daily goals", f"Generated {len(daily_goals)} goals for today")
    except Exception as e:
        log_activity("queen", "Error", f"Could not generate goals: {str(e)[:50]}")

    # Generate autonomous tasks
    await generate_autonomous_tasks()

    # Start the autonomous engine
    asyncio.create_task(run_engine())

    # Start Overseer monitoring (every 2 hours)
    asyncio.create_task(overseer.start_monitoring())
    log_activity("overseer", "Started", "Monitoring every 2 hours")

    yield
    print("Shutting down...")
    await overseer.stop_monitoring()


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


def render_overseer_status():
    """Render Overseer Agent status panel"""
    status = overseer.get_status()
    health = status.get("latest_health_score")
    health_color = "#00ff88" if health and health >= 70 else "#ffcc00" if health and health >= 50 else "#ff4444"

    last_check = status.get("last_check", "Never")
    if last_check != "Never":
        last_check = last_check.split("T")[1].split(".")[0] if "T" in last_check else last_check

    return f'''
    <div style="background:linear-gradient(135deg,#1a1a00,#333300);border:1px solid #666600;border-radius:8px;padding:12px;margin-bottom:15px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
            <h4 style="font-size:12px;color:#ffcc00;">OVERSEER</h4>
            <span style="background:{'#00ff88' if status.get('running') else '#ff4444'};color:#000;padding:2px 6px;border-radius:8px;font-size:9px;font-weight:600;">{'ACTIVE' if status.get('running') else 'STOPPED'}</span>
        </div>
        <div style="font-size:11px;color:#888;">
            <div>Health: <span style="color:{health_color};font-weight:600;">{f"{health:.0f}" if health else "N/A"}%</span></div>
            <div>Checks: {status.get('total_checks', 0)} | Blockers: {status.get('active_blockers', 0)}</div>
            <div>Last: {last_check} | Next: 2h</div>
        </div>
    </div>
    '''


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
            'chef': '#00ff88',
            'queen': '#ff00ff',
            'overseer': '#ffcc00'
        }.get(agent, '#888')

        html += f'''<div style="padding:6px 0;border-bottom:1px solid #222;font-size:11px;">
            <span style="color:#555;">{time}</span>
            <span style="color:{color};font-weight:600;margin-left:8px;">{agent.upper()}</span>
            <span style="color:#888;margin-left:8px;">{action}</span>
            <span style="color:#666;margin-left:4px;">{details}</span>
        </div>'''
    return html


def render_queen_status():
    """Render Queen Agent status panel"""
    status = queen.get_status()
    goals = queen.daily_goals

    goals_html = ""
    for g in goals[:4]:
        status_color = '#00ff88' if g.status == 'completed' else '#ffcc00' if g.status == 'in_progress' else '#888'
        goals_html += f'''<div style="background:#1a1a2e;padding:10px;border-radius:6px;margin-bottom:8px;border-left:3px solid {status_color};">
            <div style="font-size:12px;font-weight:600;">{g.title}</div>
            <div style="font-size:10px;color:#666;margin-top:2px;">→ {g.assigned_to}</div>
        </div>'''

    if not goals_html:
        goals_html = '<div style="color:#666;font-size:11px;">Generating goals...</div>'

    frameworks_html = ""
    for key, fw in queen.security_frameworks.items():
        pri_color = '#ff4444' if fw.priority == 'critical' else '#ffcc00' if fw.priority == 'high' else '#00ccff'
        frameworks_html += f'''<span style="display:inline-block;background:#1a1a2e;padding:4px 8px;border-radius:4px;font-size:10px;margin:2px;border:1px solid {pri_color};">{key.upper()}</span>'''

    return f'''
    <div style="background:linear-gradient(135deg,#1a0033,#330066);border:1px solid #6600cc;border-radius:12px;padding:15px;margin-bottom:15px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
            <h3 style="font-size:14px;color:#ff00ff;">👑 QUEEN AGENT</h3>
            <span style="background:#00ff88;color:#000;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600;">ACTIVE</span>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:11px;margin-bottom:10px;">
            <div>Managed Agents: <span style="color:#00ccff;">{status['managed_agents']}</span></div>
            <div>Goals Today: <span style="color:#ffcc00;">{status['daily_goals']}</span></div>
            <div>Completed: <span style="color:#00ff88;">{status['goals_completed']}</span></div>
            <div>Target: <span style="color:#ff6b6b;">4/day</span></div>
        </div>
        <div style="margin-bottom:10px;">
            <div style="font-size:11px;color:#888;margin-bottom:5px;">Security Frameworks:</div>
            {frameworks_html}
        </div>
    </div>
    <h3 style="font-size:13px;color:#ff00ff;margin-bottom:10px;">Daily Goals</h3>
    {goals_html}
    '''


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
    <meta http-equiv="refresh" content="30">
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
            {render_queen_status()}
            {render_overseer_status()}

            <h2 style="margin-top:10px;">AI Workforce</h2>
            {agents_html}

            <h2 style="margin-top:20px;">Activity Log</h2>
            <div style="background:#1a1a2e;border-radius:8px;padding:12px;max-height:200px;overflow-y:auto;">
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


@app.get("/api/queen/status")
async def queen_status():
    """Get Queen Agent status"""
    return queen.get_status()


@app.get("/api/queen/goals")
async def queen_goals():
    """Get today's daily goals"""
    return {
        "goals": [
            {
                "id": g.id,
                "title": g.title,
                "description": g.description,
                "assigned_to": g.assigned_to,
                "status": g.status
            }
            for g in queen.daily_goals
        ],
        "target": queen.metrics["daily_goal"],
        "completed": len([g for g in queen.daily_goals if g.status == "completed"])
    }


@app.post("/api/queen/generate-goals")
async def regenerate_goals():
    """Regenerate daily goals"""
    try:
        goals = await queen.generate_daily_goals(COMPANY_GOAL)
        log_activity("queen", "Regenerated", f"{len(goals)} new daily goals")
        return {"success": True, "goals_count": len(goals)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.get("/api/security/frameworks")
async def security_frameworks():
    """Get available security frameworks"""
    return {
        name: {
            "name": fw.name,
            "description": fw.description,
            "controls": fw.controls,
            "priority": fw.priority
        }
        for name, fw in queen.security_frameworks.items()
    }


@app.post("/api/security/analyze")
async def analyze_security(target: str = Form(...)):
    """Analyze security requirements for a target"""
    try:
        analysis = await queen.analyze_security_requirements(target)
        log_activity("queen", "Security Analysis", f"Analyzed: {target[:30]}")
        return analysis
    except Exception as e:
        return {"error": str(e)}


# ============== OVERSEER ENDPOINTS ==============

@app.get("/api/overseer/status")
async def overseer_status():
    """Get Overseer Agent status"""
    return overseer.get_status()


@app.get("/api/overseer/health-history")
async def overseer_health_history(limit: int = 10):
    """Get system health score history"""
    return {
        "history": overseer.get_health_history(limit),
        "current_health": overseer.status_history[-1].health_score if overseer.status_history else None
    }


@app.post("/api/overseer/run-check")
async def run_overseer_check():
    """Manually trigger an Overseer check cycle"""
    try:
        status = await overseer.run_check_cycle()
        log_activity("overseer", "Manual Check", f"Health: {status.health_score:.1f}")
        return {
            "success": True,
            "health_score": status.health_score,
            "blockers_found": len(status.blockers),
            "recommendations": status.recommendations
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.get("/api/overseer/blockers")
async def get_blockers():
    """Get current system blockers"""
    return {
        "active_blockers": [
            {
                "id": b.id,
                "type": b.type.value,
                "description": b.description,
                "severity": b.severity,
                "detected_at": b.detected_at.isoformat(),
                "resolved": b.resolved
            }
            for b in overseer.blockers.values()
            if not b.resolved
        ],
        "total_blockers": len(overseer.blockers)
    }


@app.get("/api/overseer/actions")
async def get_overseer_actions(limit: int = 20):
    """Get recent Overseer actions"""
    actions = sorted(
        overseer.actions.values(),
        key=lambda a: a.created_at,
        reverse=True
    )[:limit]

    return {
        "actions": [
            {
                "id": a.id,
                "type": a.type.value,
                "description": a.description,
                "target": a.target,
                "status": a.status,
                "created_at": a.created_at.isoformat(),
                "completed_at": a.completed_at.isoformat() if a.completed_at else None
            }
            for a in actions
        ]
    }


# ============== SOVEREIGN/BUSINESS ENDPOINTS ==============

@app.get("/api/sovereign/status")
async def sovereign_status():
    """Get Sovereign Agent status"""
    return sovereign.get_status()


@app.get("/api/sovereign/ventures")
async def get_ventures():
    """Get all ventures"""
    return sovereign.get_ventures()


@app.post("/api/sovereign/generate-strategies")
async def generate_strategies(count: int = 20):
    """Generate new business strategies"""
    try:
        strategies = await sovereign.generate_strategies(count)
        log_activity("sovereign", "Strategies", f"Generated {len(strategies)} strategies")
        return {"success": True, "count": len(strategies)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/sovereign/launch-venture")
async def launch_venture():
    """Launch a new venture from strategy pool"""
    try:
        if not sovereign.strategy_pool:
            await sovereign.generate_strategies(10)

        if sovereign.strategy_pool:
            strategy = sovereign.strategy_pool[0]
            venture = await sovereign.launch_venture(strategy)
            sovereign.strategy_pool.remove(strategy)
            log_activity("sovereign", "Launch", f"Launched: {venture.name}")
            return {"success": True, "venture": venture.name}
        return {"success": False, "error": "No strategies available"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/sovereign/chat")
async def chat_with_sovereign(message: str = Form(...)):
    """Chat with the Sovereign"""
    try:
        response = await sovereign.process_user_message(message)
        log_activity("sovereign", "Chat", message[:30])
        return {"response": response}
    except Exception as e:
        return {"response": f"Error: {str(e)}"}


@app.post("/api/sovereign/discuss")
async def discuss_strategy(idea: str = Form(...)):
    """Deep strategic discussion about an idea"""
    try:
        analysis = await sovereign.discuss_strategy(idea)
        log_activity("sovereign", "Strategy Discussion", idea[:30])
        return analysis
    except Exception as e:
        return {"error": str(e)}


@app.get("/api/sovereign/messages")
async def get_sovereign_messages(limit: int = 20):
    """Get recent Sovereign messages"""
    return {"messages": sovereign.messages[-limit:]}


# ============== ORACLE ENDPOINTS ==============

@app.get("/api/oracle/status")
async def oracle_status():
    """Get Oracle Agent status"""
    return oracle.get_status()


@app.get("/api/oracle/opportunities")
async def get_opportunities(count: int = 10):
    """Get top opportunities"""
    return {"opportunities": oracle.get_top_opportunities(count)}


@app.post("/api/oracle/analyze-trends")
async def analyze_trends():
    """Analyze market trends"""
    try:
        trends = await oracle.analyze_market_trends()
        log_activity("oracle", "Trends", f"Analyzed {len(trends.hot_markets)} markets")
        return {
            "hot_markets": trends.hot_markets,
            "technologies": trends.emerging_technologies,
            "opportunities": trends.opportunities
        }
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/oracle/generate")
async def generate_opportunities(count: int = 20):
    """Generate new opportunities"""
    try:
        opportunities = await oracle.generate_opportunities(count)
        return {"success": True, "count": len(opportunities)}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============== BOOKIE ENDPOINTS ==============

@app.get("/api/bookie/status")
async def bookie_status():
    """Get Bookie Agent status"""
    return bookie.get_status()


@app.get("/api/bookie/portfolio")
async def get_portfolio():
    """Get portfolio summary"""
    return bookie.get_portfolio_summary()


@app.get("/api/bookie/bets")
async def get_bets():
    """Get all bets"""
    return {"bets": bookie.get_all_bets()}


@app.post("/api/bookie/place-bet")
async def place_bet(stake: float = Form(500)):
    """Place a new bet on a strategy"""
    try:
        # Get strategy from Oracle
        if not oracle.opportunities:
            await oracle.generate_opportunities(10)

        top_opps = oracle.get_top_opportunities(1)
        if top_opps:
            strategy = top_opps[0]
            bet = await bookie.place_bet(strategy, stake)
            if bet:
                log_activity("bookie", "Bet", f"Placed ${stake:,.0f} on {bet.name}")
                return {"success": True, "bet_id": bet.id, "name": bet.name}
        return {"success": False, "error": "No opportunities or insufficient capital"}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/bookie/optimize")
async def optimize_portfolio():
    """Auto-optimize the portfolio"""
    try:
        results = await bookie.auto_manage()
        return {"success": True, "actions": results["actions"]}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ============== CENTRALIZED COMMAND CENTER ==============

def add_user_action(action: str, priority: str = "medium", category: str = "general"):
    """Add an action item for the user"""
    global user_action_items
    user_action_items.append({
        "id": f"action_{datetime.now().strftime('%H%M%S')}",
        "action": action,
        "priority": priority,
        "category": category,
        "created_at": datetime.now().isoformat(),
        "completed": False
    })
    user_action_items = user_action_items[-20:]  # Keep last 20


@app.get("/command", response_class=HTMLResponse)
async def command_center():
    """Centralized Command Center - The main dashboard"""
    global activity_log, user_action_items

    # Gather all data
    sov_status = sovereign.get_status()
    bookie_status = bookie.get_portfolio_summary()
    oracle_status = oracle.get_status()
    overseer_status = overseer.get_status()
    queen_status = queen.get_status()
    dashboard_data = control_center.get_dashboard_data()
    all_agents = chef.get_all_agents()

    # Calculate progress
    total_revenue = sov_status["total_revenue"]
    target = sov_status["target"]
    progress_pct = (total_revenue / target) * 100 if target > 0 else 0

    # Build agent cards
    agents_html = ""
    core_agents = [
        ("sovereign", "active", "Orchestrating business strategy", 0),
        ("oracle", "active", "Analyzing market trends", oracle_status.get("trend_analyses", 0)),
        ("bookie", "active", f"Managing {bookie_status['active_bets']} bets", bookie_status.get("active_bets", 0)),
        ("queen", "active", f"Tracking {queen_status['daily_goals']} daily goals", queen_status.get("goals_completed", 0)),
        ("overseer", "active", f"System health: {overseer_status.get('latest_health_score', 'N/A')}%", overseer_status.get("total_checks", 0)),
        ("chef", "active", f"Managing {len(all_agents)} worker agents", len(all_agents)),
    ]

    for agent_type, status, task, done in core_agents:
        agents_html += get_agent_card_html(agent_type, status, task, done)

    # Worker agents
    worker_html = ""
    for agent in all_agents[:6]:
        agent_type = agent.get("type", "unknown")
        current = agent.get("current_task", "Idle")
        done = agent.get("tasks_completed", 0)
        worker_html += get_agent_card_html(agent_type, "active" if current else "idle", current, done)

    # Tasks
    pending_tasks = dashboard_data.get("pending_tasks", [])[:5]
    active_tasks = dashboard_data.get("active_tasks", [])[:5]
    completed_tasks = dashboard_data.get("recent_completed", [])[:5]

    def render_task_list(tasks, status_type):
        if not tasks:
            return '<div style="color:#666;padding:10px;text-align:center;">No tasks</div>'
        html = ""
        colors = {"pending": "#888", "active": "#ffcc00", "completed": "#00ff88"}
        for t in tasks:
            html += f'''<div style="background:#1a1a2e;padding:10px;border-radius:6px;margin-bottom:6px;border-left:3px solid {colors.get(status_type, '#888')};">
                <div style="font-size:12px;font-weight:500;">{t.get("title", "Task")[:40]}</div>
                <div style="font-size:10px;color:#666;margin-top:3px;">{t.get("category", "general")} | {t.get("priority", "medium")}</div>
            </div>'''
        return html

    pending_html = render_task_list(pending_tasks, "pending")
    active_html = render_task_list(active_tasks, "active")
    completed_html = render_task_list(completed_tasks, "completed")

    # User action items
    pending_actions = [a for a in user_action_items if not a.get("completed")]
    action_html = ""
    if pending_actions:
        for a in pending_actions[:5]:
            pri_color = {"high": "#ff4444", "medium": "#ffcc00", "low": "#00ccff"}.get(a["priority"], "#888")
            action_html += f'''<div style="background:#2a1a1a;padding:12px;border-radius:8px;margin-bottom:8px;border-left:3px solid {pri_color};">
                <div style="display:flex;justify-content:space-between;align-items:center;">
                    <span style="font-size:13px;">{a["action"]}</span>
                    <span style="font-size:10px;color:{pri_color};">{a["priority"].upper()}</span>
                </div>
                <div style="font-size:10px;color:#666;margin-top:4px;">{a["category"]}</div>
            </div>'''
    else:
        action_html = '<div style="color:#00ff88;padding:20px;text-align:center;">All caught up! No pending actions.</div>'

    # Ventures summary
    ventures = sovereign.get_ventures()[:4]
    ventures_html = ""
    for v in ventures:
        s_color = {"profitable": "#00ff88", "scaling": "#00ccff", "building": "#ffcc00"}.get(v["status"], "#888")
        ventures_html += f'''<div style="background:#1a2a1a;padding:10px;border-radius:6px;margin-bottom:6px;border-left:3px solid {s_color};">
            <div style="font-size:12px;font-weight:500;">{v["name"][:30]}</div>
            <div style="font-size:10px;color:#888;">${v["revenue"]:,.0f} rev | {v["status"]}</div>
        </div>'''

    if not ventures_html:
        ventures_html = '<div style="color:#666;padding:10px;text-align:center;">No ventures yet</div>'

    # Activity log
    recent_activity = activity_log[:8]
    activity_html = ""
    for log in recent_activity:
        agent = log.get("agent", "system")
        p = get_agent_display(agent)
        activity_html += f'''<div style="padding:6px 0;border-bottom:1px solid #222;font-size:11px;">
            <span style="color:#555;">{log.get("time", "")}</span>
            <span style="color:{p["color"]};margin-left:8px;">{p["emoji"]} {p["name"]}</span>
            <span style="color:#888;margin-left:8px;">{log.get("action", "")}</span>
        </div>'''

    # Chat messages
    chat_html = ""
    for m in sovereign.messages[-6:]:
        sender = m.get("sender", "system")
        color = "#ff6600" if sender == "sovereign" else "#00ccff" if sender == "user" else "#888"
        name = "Marcus" if sender == "sovereign" else "You" if sender == "user" else sender
        chat_html += f'''<div style="margin-bottom:8px;padding:8px;background:#1a1a2e;border-radius:6px;">
            <strong style="color:{color};">{name}:</strong>
            <span style="color:#ccc;font-size:12px;"> {m.get("content", "")[:100]}</span>
        </div>'''

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Command Center - OpenClaw</title>
    <meta http-equiv="refresh" content="30">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: system-ui, sans-serif; background: #0a0a0f; color: #e0e0e0; min-height: 100vh; }}
        .header {{ background: linear-gradient(135deg, #0a0a0f, #1a1a2e); padding: 15px 25px; border-bottom: 1px solid #333; display: flex; justify-content: space-between; align-items: center; }}
        .header h1 {{ font-size: 22px; }}
        .header h1 span {{ background: linear-gradient(90deg, #ff6600, #ffcc00); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .nav {{ display: flex; gap: 15px; }}
        .nav a {{ color: #888; text-decoration: none; font-size: 13px; padding: 6px 12px; border-radius: 6px; transition: all 0.3s; }}
        .nav a:hover {{ background: #1a1a2e; color: #fff; }}
        .nav a.active {{ background: #ff6600; color: #000; }}
        .main {{ display: grid; grid-template-columns: 280px 1fr 320px; min-height: calc(100vh - 60px); }}
        .panel {{ padding: 15px; overflow-y: auto; }}
        .left {{ background: #0d0d12; border-right: 1px solid #222; }}
        .right {{ background: #0d0d12; border-left: 1px solid #222; }}
        h2 {{ font-size: 13px; color: #888; text-transform: uppercase; margin-bottom: 12px; letter-spacing: 1px; }}
        h3 {{ font-size: 12px; color: #666; margin: 15px 0 10px 0; }}
        .metric-row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 15px; }}
        .metric {{ background: #1a1a2e; padding: 12px; border-radius: 8px; text-align: center; }}
        .metric h4 {{ font-size: 10px; color: #666; text-transform: uppercase; }}
        .metric .val {{ font-size: 22px; font-weight: 700; margin-top: 4px; }}
        .progress-bar {{ background: #222; border-radius: 8px; height: 8px; margin: 8px 0; overflow: hidden; }}
        .progress-fill {{ background: linear-gradient(90deg, #ff6600, #ffcc00); height: 100%; }}
        .big-stat {{ text-align: center; padding: 20px; background: linear-gradient(135deg, #1a1a2e, #0a0a0f); border-radius: 12px; margin-bottom: 15px; border: 1px solid #333; }}
        .big-stat .val {{ font-size: 36px; font-weight: 700; background: linear-gradient(90deg, #00ff88, #00ccff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .section {{ background: #111; border: 1px solid #222; border-radius: 10px; padding: 15px; margin-bottom: 15px; }}
        .btn {{ display: inline-block; padding: 8px 16px; background: linear-gradient(90deg, #ff6600, #ffcc00); color: #000; border-radius: 6px; text-decoration: none; font-weight: 600; font-size: 12px; border: none; cursor: pointer; margin: 3px; }}
        .btn:hover {{ opacity: 0.9; }}
        .btn-secondary {{ background: #333; color: #fff; }}
        .chat-box {{ background: #0a0a0f; border: 1px solid #333; border-radius: 8px; padding: 10px; max-height: 200px; overflow-y: auto; margin-bottom: 10px; }}
        .chat-input {{ display: flex; gap: 8px; }}
        .chat-input input {{ flex: 1; padding: 8px 12px; background: #1a1a2e; border: 1px solid #333; border-radius: 6px; color: #fff; font-size: 12px; }}
        .user-actions {{ background: linear-gradient(135deg, #2a1a1a, #1a1a2e); border: 1px solid #ff4444; border-radius: 10px; padding: 15px; margin-bottom: 15px; }}
        .tabs {{ display: flex; gap: 5px; margin-bottom: 10px; }}
        .tab {{ padding: 6px 12px; background: #1a1a2e; border-radius: 6px; font-size: 11px; cursor: pointer; }}
        .tab.active {{ background: #ff6600; color: #000; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 <span>COMMAND CENTER</span></h1>
        <div class="nav">
            <a href="/command" class="active">Command</a>
            <a href="/profit">Profit</a>
            <a href="/">Tasks</a>
            <a href="/docs">API</a>
        </div>
        <div style="font-size:12px;color:#888;">
            Cycle #{cycle_count} | Health: {overseer_status.get('latest_health_score', 'N/A')}%
        </div>
    </div>

    <div class="main">
        <!-- LEFT: AGENT TEAM -->
        <div class="panel left">
            <h2>🤖 Agent Team</h2>
            {agents_html}

            <h3>Worker Agents</h3>
            {worker_html if worker_html else '<div style="color:#666;font-size:11px;">No workers spawned yet</div>'}
        </div>

        <!-- CENTER: MAIN CONTENT -->
        <div class="panel">
            <!-- Progress to $1M -->
            <div class="big-stat">
                <div style="font-size:12px;color:#888;">PROGRESS TO $1M</div>
                <div class="val">${total_revenue:,.0f}</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width:{min(progress_pct, 100):.1f}%;"></div>
                </div>
                <div style="font-size:12px;color:#888;">{progress_pct:.2f}% Complete</div>
            </div>

            <div class="metric-row">
                <div class="metric">
                    <h4>MRR</h4>
                    <div class="val" style="color:#00ff88;">${sov_status['mrr']:,.0f}</div>
                </div>
                <div class="metric">
                    <h4>Ventures</h4>
                    <div class="val" style="color:#00ccff;">{sov_status['ventures_count']}</div>
                </div>
                <div class="metric">
                    <h4>Active Bets</h4>
                    <div class="val" style="color:#ffcc00;">{bookie_status['active_bets']}</div>
                </div>
                <div class="metric">
                    <h4>Win Rate</h4>
                    <div class="val">{bookie_status['win_rate']*100:.0f}%</div>
                </div>
            </div>

            <!-- YOUR ACTION ITEMS -->
            <div class="user-actions">
                <h2 style="color:#ff4444;">⚡ YOUR ACTION ITEMS</h2>
                {action_html}
            </div>

            <!-- Task Boards -->
            <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;">
                <div class="section">
                    <h2>📋 Pending</h2>
                    {pending_html}
                </div>
                <div class="section">
                    <h2>🔄 In Progress</h2>
                    {active_html}
                </div>
                <div class="section">
                    <h2>✅ Completed</h2>
                    {completed_html}
                </div>
            </div>

            <!-- Quick Actions -->
            <div class="section">
                <h2>⚡ Quick Actions</h2>
                <form action="/api/sovereign/generate-strategies" method="POST" style="display:inline;">
                    <button type="submit" class="btn">Generate Strategies</button>
                </form>
                <form action="/api/sovereign/launch-venture" method="POST" style="display:inline;">
                    <button type="submit" class="btn">Launch Venture</button>
                </form>
                <form action="/api/oracle/analyze-trends" method="POST" style="display:inline;">
                    <button type="submit" class="btn btn-secondary">Analyze Trends</button>
                </form>
                <form action="/api/bookie/place-bet" method="POST" style="display:inline;">
                    <input type="hidden" name="stake" value="500">
                    <button type="submit" class="btn btn-secondary">Place $500 Bet</button>
                </form>
                <form action="/api/overseer/run-check" method="POST" style="display:inline;">
                    <button type="submit" class="btn btn-secondary">Run Health Check</button>
                </form>
            </div>
        </div>

        <!-- RIGHT: VENTURES & CHAT -->
        <div class="panel right">
            <!-- Chat with Marcus -->
            <div class="section">
                <h2>💬 Chat with Marcus (The Mastermind)</h2>
                <div class="chat-box">
                    {chat_html if chat_html else '<div style="color:#666;text-align:center;padding:20px;">Start a conversation...</div>'}
                </div>
                <form action="/api/sovereign/chat" method="POST" class="chat-input">
                    <input type="text" name="message" placeholder="Ask Marcus anything..." required>
                    <button type="submit" class="btn">Send</button>
                </form>
            </div>

            <!-- Active Ventures -->
            <div class="section">
                <h2>🚀 Active Ventures</h2>
                {ventures_html}
            </div>

            <!-- Oracle Insights -->
            <div class="section">
                <h2>🔮 Luna's Insights</h2>
                <div style="font-size:11px;color:#888;">
                    <div>Opportunities Found: <span style="color:#9933ff;">{oracle_status.get('opportunities_count', 0)}</span></div>
                    <div>Hot Markets: <span style="color:#9933ff;">{', '.join(oracle_status.get('top_markets', ['Analyzing...']))[:50]}</span></div>
                </div>
            </div>

            <!-- Activity Feed -->
            <div class="section">
                <h2>📊 Activity Feed</h2>
                <div style="max-height:150px;overflow-y:auto;">
                    {activity_html if activity_html else '<div style="color:#666;font-size:11px;">No activity yet</div>'}
                </div>
            </div>
        </div>
    </div>
</body>
</html>"""


# ============== PROFIT DASHBOARD ==============

@app.get("/profit", response_class=HTMLResponse)
async def profit_dashboard():
    """Business profit tracking dashboard"""
    sov_status = sovereign.get_status()
    bookie_status = bookie.get_portfolio_summary()
    oracle_status = oracle.get_status()

    ventures = sovereign.get_ventures()[:5]
    bets = bookie.get_all_bets()[:5]

    ventures_html = ""
    for v in ventures:
        status_color = {"profitable": "#00ff88", "scaling": "#00ccff", "building": "#ffcc00", "killed": "#ff4444"}.get(v["status"], "#888")
        ventures_html += f'''<div style="background:#1a1a2e;padding:12px;border-radius:8px;margin-bottom:8px;border-left:3px solid {status_color};">
            <div style="display:flex;justify-content:space-between;">
                <strong>{v["name"][:30]}</strong>
                <span style="color:{status_color};">{v["status"].upper()}</span>
            </div>
            <div style="font-size:12px;color:#888;margin-top:4px;">
                Revenue: ${v["revenue"]:,.0f} | ROI: {v["roi"]:.0f}%
            </div>
        </div>'''

    bets_html = ""
    for b in bets:
        status_color = {"winning": "#00ff88", "active": "#00ccff", "losing": "#ff4444"}.get(b["status"], "#888")
        bets_html += f'''<div style="background:#1a1a2e;padding:12px;border-radius:8px;margin-bottom:8px;border-left:3px solid {status_color};">
            <div style="display:flex;justify-content:space-between;">
                <strong>{b["name"][:25]}</strong>
                <span style="color:{status_color};">{b["status"].upper()}</span>
            </div>
            <div style="font-size:12px;color:#888;margin-top:4px;">
                Stake: ${b["stake"]:,.0f} | Value: ${b["current_value"]:,.0f} | ROI: {b["roi"]:.0f}%
            </div>
        </div>'''

    progress_pct = sov_status["progress_percent"]
    progress_color = "#00ff88" if progress_pct >= 50 else "#ffcc00" if progress_pct >= 20 else "#888"

    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Profit Dashboard - OpenClaw</title>
    <meta http-equiv="refresh" content="30">
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: system-ui, sans-serif; background: #0a0a0f; color: #e0e0e0; min-height: 100vh; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e, #0a0a0f); padding: 20px 30px; border-bottom: 1px solid #333; }}
        .header h1 {{ font-size: 28px; }}
        .header h1 span {{ background: linear-gradient(90deg, #00ff88, #00ccff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .main {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; padding: 20px; }}
        .panel {{ background: #111; border: 1px solid #222; border-radius: 12px; padding: 20px; }}
        .panel h2 {{ font-size: 16px; color: #00ccff; margin-bottom: 15px; }}
        .big-number {{ font-size: 48px; font-weight: 700; background: linear-gradient(90deg, #00ff88, #00ccff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .stats-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }}
        .stat {{ background: #1a1a2e; padding: 15px; border-radius: 8px; text-align: center; }}
        .stat h4 {{ font-size: 11px; color: #666; text-transform: uppercase; }}
        .stat .val {{ font-size: 24px; font-weight: 600; margin-top: 5px; }}
        .progress-bar {{ background: #222; border-radius: 10px; height: 20px; margin: 15px 0; overflow: hidden; }}
        .progress-fill {{ background: linear-gradient(90deg, #00ff88, #00ccff); height: 100%; transition: width 0.5s; }}
        .btn {{ display: inline-block; padding: 10px 20px; background: linear-gradient(90deg, #00ff88, #00ccff); color: #000; border-radius: 8px; text-decoration: none; font-weight: 600; margin: 5px; cursor: pointer; border: none; }}
        .btn:hover {{ opacity: 0.9; }}
        .chat-box {{ background: #0a0a0f; border: 1px solid #333; border-radius: 8px; padding: 10px; height: 200px; overflow-y: auto; margin-bottom: 10px; }}
        .chat-input {{ display: flex; gap: 10px; }}
        .chat-input input {{ flex: 1; padding: 10px; background: #1a1a2e; border: 1px solid #333; border-radius: 8px; color: #fff; }}
    </style>
</head>
<body>
    <div class="header">
        <h1><span>$1M</span> MISSION CONTROL</h1>
        <p style="color:#888;margin-top:5px;">Autonomous Business Network | {len(sovereign.ventures)} Ventures | {bookie_status["active_bets"]} Active Bets</p>
    </div>

    <div class="main">
        <div class="panel">
            <h2>SOVEREIGN STATUS</h2>
            <div class="big-number">${sov_status["total_revenue"]:,.0f}</div>
            <p style="color:#888;margin:10px 0;">of ${sov_status["target"]:,.0f} target</p>
            <div class="progress-bar">
                <div class="progress-fill" style="width:{min(progress_pct, 100):.1f}%;"></div>
            </div>
            <p style="color:{progress_color};font-weight:600;">{progress_pct:.1f}% Complete</p>

            <div class="stats-grid" style="margin-top:20px;">
                <div class="stat">
                    <h4>MRR</h4>
                    <div class="val" style="color:#00ff88;">${sov_status["mrr"]:,.0f}</div>
                </div>
                <div class="stat">
                    <h4>ROI</h4>
                    <div class="val" style="color:#00ccff;">{sov_status["roi"]:.0f}%</div>
                </div>
                <div class="stat">
                    <h4>Invested</h4>
                    <div class="val">${sov_status["total_invested"]:,.0f}</div>
                </div>
                <div class="stat">
                    <h4>Strategies</h4>
                    <div class="val">{sov_status["strategy_pool_size"]}</div>
                </div>
            </div>

            <div style="margin-top:20px;">
                <form action="/api/sovereign/launch-venture" method="POST" style="display:inline;">
                    <button type="submit" class="btn">Launch Venture</button>
                </form>
                <form action="/api/sovereign/generate-strategies" method="POST" style="display:inline;">
                    <button type="submit" class="btn">Generate Strategies</button>
                </form>
            </div>
        </div>

        <div class="panel">
            <h2>ACTIVE VENTURES</h2>
            {ventures_html or '<p style="color:#666;">No ventures yet. Generate strategies and launch!</p>'}

            <h2 style="margin-top:20px;">BETS PORTFOLIO</h2>
            {bets_html or '<p style="color:#666;">No active bets.</p>'}

            <div style="margin-top:15px;">
                <form action="/api/bookie/place-bet" method="POST" style="display:inline;">
                    <input type="hidden" name="stake" value="500">
                    <button type="submit" class="btn">Place $500 Bet</button>
                </form>
                <form action="/api/bookie/optimize" method="POST" style="display:inline;">
                    <button type="submit" class="btn">Optimize Portfolio</button>
                </form>
            </div>
        </div>

        <div class="panel">
            <h2>CHAT WITH SOVEREIGN</h2>
            <div class="chat-box" id="chatBox">
                {''.join([f'<div style="margin-bottom:10px;"><strong style="color:{("#00ff88" if m["sender"]=="sovereign" else "#ffcc00" if m["sender"]=="user" else "#888")}">{m["sender"].upper()}:</strong> {m["content"]}</div>' for m in sovereign.messages[-10:]])}
            </div>
            <form action="/api/sovereign/chat" method="POST" class="chat-input">
                <input type="text" name="message" placeholder="Ask Sovereign anything..." required>
                <button type="submit" class="btn">Send</button>
            </form>

            <h2 style="margin-top:20px;">ORACLE INSIGHTS</h2>
            <div style="background:#1a1a2e;padding:12px;border-radius:8px;">
                <p style="font-size:12px;color:#888;">Hot Markets:</p>
                <p style="color:#00ccff;">{', '.join(oracle_status.get("top_markets", ["Analyzing..."]))}</p>
                <p style="font-size:12px;color:#888;margin-top:10px;">Opportunities: {oracle_status.get("opportunities_count", 0)}</p>
            </div>
            <form action="/api/oracle/analyze-trends" method="POST" style="margin-top:10px;">
                <button type="submit" class="btn">Analyze Trends</button>
            </form>

            <h2 style="margin-top:20px;">PORTFOLIO STATS</h2>
            <div class="stats-grid">
                <div class="stat">
                    <h4>Bankroll</h4>
                    <div class="val" style="color:#00ff88;">${bookie_status["total_bankroll"]:,.0f}</div>
                </div>
                <div class="stat">
                    <h4>Win Rate</h4>
                    <div class="val">{bookie_status["win_rate"]*100:.0f}%</div>
                </div>
                <div class="stat">
                    <h4>Net Profit</h4>
                    <div class="val" style="color:{'#00ff88' if bookie_status['net_profit']>=0 else '#ff4444'};">${bookie_status["net_profit"]:,.0f}</div>
                </div>
                <div class="stat">
                    <h4>Available</h4>
                    <div class="val">${bookie_status["available_capital"]:,.0f}</div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>"""


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
