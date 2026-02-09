"""
OpenClaw - AI Company Control Center
Autonomous AI agents working to build and grow the company
"""
import os
import json
import asyncio
import random
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, List, Dict
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, File, UploadFile, Form, Request, Response, Depends, Cookie
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware

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

# ============================================
# AUTHENTICATION CONFIGURATION
# ============================================
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_hex(32))
SESSION_EXPIRE_HOURS = 24

# Master account
MASTER_ACCOUNTS = {
    "abhinav100.sharma@gmail.com": {
        "password_hash": hashlib.sha256("openclaw2024!".encode()).hexdigest(),
        "role": "admin",
        "name": "Abhinav"
    }
}

# Active sessions (in production, use Redis or database)
active_sessions: Dict[str, dict] = {}

def verify_password(email: str, password: str) -> bool:
    """Verify user credentials"""
    if email not in MASTER_ACCOUNTS:
        return False
    stored_hash = MASTER_ACCOUNTS[email]["password_hash"]
    input_hash = hashlib.sha256(password.encode()).hexdigest()
    return stored_hash == input_hash

def create_session(email: str) -> str:
    """Create a new session token"""
    token = secrets.token_urlsafe(32)
    active_sessions[token] = {
        "email": email,
        "created": datetime.now(),
        "expires": datetime.now() + timedelta(hours=SESSION_EXPIRE_HOURS),
        "role": MASTER_ACCOUNTS[email]["role"],
        "name": MASTER_ACCOUNTS[email]["name"]
    }
    return token

def get_session(token: str) -> Optional[dict]:
    """Get session data if valid"""
    if not token or token not in active_sessions:
        return None
    session = active_sessions[token]
    if datetime.now() > session["expires"]:
        del active_sessions[token]
        return None
    return session

async def require_auth(request: Request) -> dict:
    """Dependency to require authentication"""
    token = request.cookies.get("session_token")
    session = get_session(token)
    if not session:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return session

# ============================================

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

# Add session middleware
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)


# ============================================
# LOGIN PAGE
# ============================================
@app.get("/login", response_class=HTMLResponse)
async def login_page(error: str = None):
    """Login page"""
    error_msg = f'<div style="color:#ff4444;margin-bottom:15px;">{error}</div>' if error else ""
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login - OpenClaw</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: system-ui, sans-serif;
                background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }}
            .login-box {{
                background: #111;
                border: 1px solid #333;
                border-radius: 16px;
                padding: 40px;
                width: 400px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.5);
            }}
            .logo {{
                text-align: center;
                margin-bottom: 30px;
            }}
            .logo h1 {{
                font-size: 32px;
                background: linear-gradient(90deg, #ff6600, #ffcc00);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }}
            .logo p {{
                color: #666;
                font-size: 14px;
                margin-top: 5px;
            }}
            .form-group {{
                margin-bottom: 20px;
            }}
            label {{
                display: block;
                color: #888;
                font-size: 12px;
                margin-bottom: 8px;
                text-transform: uppercase;
            }}
            input {{
                width: 100%;
                padding: 14px;
                background: #0a0a0f;
                border: 1px solid #333;
                border-radius: 8px;
                color: #fff;
                font-size: 16px;
            }}
            input:focus {{
                outline: none;
                border-color: #ff6600;
            }}
            button {{
                width: 100%;
                padding: 14px;
                background: linear-gradient(90deg, #ff6600, #ffcc00);
                border: none;
                border-radius: 8px;
                color: #000;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                margin-top: 10px;
            }}
            button:hover {{
                opacity: 0.9;
            }}
        </style>
    </head>
    <body>
        <div class="login-box">
            <div class="logo">
                <h1>OpenClaw</h1>
                <p>AI Company Command Center</p>
            </div>
            {error_msg}
            <form method="POST" action="/login">
                <div class="form-group">
                    <label>Email</label>
                    <input type="email" name="email" required placeholder="your@email.com">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" required placeholder="••••••••">
                </div>
                <button type="submit">Sign In</button>
            </form>
        </div>
    </body>
    </html>
    '''

@app.post("/login")
async def do_login(request: Request, email: str = Form(...), password: str = Form(...)):
    """Process login"""
    if verify_password(email, password):
        token = create_session(email)
        response = RedirectResponse(url="/command", status_code=303)
        response.set_cookie(
            key="session_token",
            value=token,
            httponly=True,
            max_age=SESSION_EXPIRE_HOURS * 3600,
            samesite="lax"
        )
        return response
    return RedirectResponse(url="/login?error=Invalid+credentials", status_code=303)

@app.get("/logout")
async def logout(request: Request):
    """Logout and clear session"""
    token = request.cookies.get("session_token")
    if token and token in active_sessions:
        del active_sessions[token]
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("session_token")
    return response


# ============================================
# AUTHENTICATION CHECK HELPER
# ============================================
def check_auth(request: Request) -> Optional[dict]:
    """Check if user is authenticated, return session or None"""
    token = request.cookies.get("session_token")
    return get_session(token)


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
async def dashboard(request: Request):
    # Check authentication
    session = check_auth(request)
    if not session:
        return RedirectResponse(url="/login", status_code=303)

    # Get user info
    user_name = session.get("name", "User")

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
            <div style="border-left:1px solid #444;padding-left:20px;display:flex;align-items:center;gap:10px;">
                <span style="color:#ff6600;">{user_name}</span>
                <a href="/logout" style="color:#888;font-size:11px;text-decoration:none;">Logout</a>
            </div>
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


class ChatMessage(BaseModel):
    message: str

@app.post("/api/sovereign/chat")
async def chat_with_sovereign(request: Request):
    """Chat with the Sovereign - accepts both JSON and Form data"""
    try:
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            data = await request.json()
            message = data.get("message", "")
        else:
            form = await request.form()
            message = form.get("message", "")

        if not message:
            return {"response": "Please send a message"}

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
async def command_center(request: Request):
    """Centralized Command Center - Modern Notion-like Dashboard"""
    session = check_auth(request)
    if not session:
        return RedirectResponse(url="/login", status_code=303)

    global activity_log, user_action_items

    user_name = session.get("name", "User")
    sov_status = sovereign.get_status()
    bookie_status = bookie.get_portfolio_summary()
    oracle_status = oracle.get_status()
    overseer_status = overseer.get_status()
    queen_status = queen.get_status()
    dashboard_data = control_center.get_dashboard_data()
    all_agents = chef.get_all_agents()

    total_revenue = sov_status["total_revenue"]
    target = sov_status["target"]
    progress_pct = (total_revenue / target) * 100 if target > 0 else 0
    health_score = overseer_status.get('latest_health_score', 80)

    # Build ventures data
    ventures = sovereign.get_ventures()[:6]
    ventures_json = json.dumps([{"name": v["name"], "status": v["status"], "revenue": v["revenue"], "roi": v.get("roi", 0)} for v in ventures])

    # Build chat history
    chat_messages = sovereign.messages[-10:]
    chat_json = json.dumps([{"sender": m.get("sender", "system"), "content": m.get("content", "")} for m in chat_messages])

    # Activity log
    activity_json = json.dumps(activity_log[:15])

    # Tasks
    pending_tasks = dashboard_data.get("pending_tasks", [])[:8]
    active_tasks = dashboard_data.get("active_tasks", [])[:8]
    completed_tasks = dashboard_data.get("recent_completed", [])[:8]

    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenClaw - Command Center</title>
    <style>
        :root {{
            --bg-primary: #191919;
            --bg-secondary: #252525;
            --bg-tertiary: #2f2f2f;
            --bg-hover: #373737;
            --text-primary: #ebebeb;
            --text-secondary: #9b9b9b;
            --text-muted: #6b6b6b;
            --accent: #eb5757;
            --accent-green: #4dab9a;
            --accent-blue: #529cca;
            --accent-yellow: #d9a648;
            --accent-purple: #9a6dd7;
            --border: #373737;
            --shadow: rgba(0,0,0,0.3);
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.5;
        }}

        /* Sidebar */
        .sidebar {{
            position: fixed;
            left: 0;
            top: 0;
            width: 240px;
            height: 100vh;
            background: var(--bg-secondary);
            border-right: 1px solid var(--border);
            padding: 16px 8px;
            display: flex;
            flex-direction: column;
        }}
        .sidebar-header {{
            padding: 8px 12px;
            margin-bottom: 8px;
        }}
        .sidebar-header h1 {{
            font-size: 14px;
            font-weight: 600;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .sidebar-header .logo {{
            width: 24px;
            height: 24px;
            background: linear-gradient(135deg, var(--accent), var(--accent-yellow));
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
        }}
        .nav-section {{
            margin-bottom: 16px;
        }}
        .nav-section-title {{
            font-size: 11px;
            font-weight: 600;
            color: var(--text-muted);
            padding: 8px 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .nav-item {{
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 8px 12px;
            border-radius: 6px;
            cursor: pointer;
            color: var(--text-secondary);
            text-decoration: none;
            font-size: 14px;
            transition: all 0.15s;
        }}
        .nav-item:hover {{ background: var(--bg-hover); color: var(--text-primary); }}
        .nav-item.active {{ background: var(--bg-tertiary); color: var(--text-primary); }}
        .nav-item .icon {{ font-size: 16px; width: 20px; text-align: center; }}
        .nav-item .badge {{
            margin-left: auto;
            background: var(--accent);
            color: white;
            font-size: 11px;
            padding: 2px 6px;
            border-radius: 10px;
        }}
        .sidebar-footer {{
            margin-top: auto;
            padding: 12px;
            border-top: 1px solid var(--border);
        }}
        .user-info {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .user-avatar {{
            width: 32px;
            height: 32px;
            background: var(--accent-purple);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 14px;
        }}
        .user-details {{ flex: 1; }}
        .user-name {{ font-size: 13px; font-weight: 500; }}
        .user-role {{ font-size: 11px; color: var(--text-muted); }}

        /* Main Content */
        .main {{
            margin-left: 240px;
            min-height: 100vh;
        }}
        .topbar {{
            position: sticky;
            top: 0;
            background: var(--bg-primary);
            border-bottom: 1px solid var(--border);
            padding: 12px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            z-index: 100;
        }}
        .topbar-left {{
            display: flex;
            align-items: center;
            gap: 16px;
        }}
        .topbar h2 {{
            font-size: 20px;
            font-weight: 600;
        }}
        .health-badge {{
            display: flex;
            align-items: center;
            gap: 6px;
            padding: 4px 12px;
            background: var(--bg-tertiary);
            border-radius: 20px;
            font-size: 12px;
        }}
        .health-dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--accent-green);
        }}

        .content {{
            padding: 24px;
            max-width: 1400px;
        }}

        /* Stats Row */
        .stats-row {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
        }}
        .stat-card .label {{
            font-size: 12px;
            color: var(--text-muted);
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .stat-card .value {{
            font-size: 28px;
            font-weight: 700;
        }}
        .stat-card .change {{
            font-size: 12px;
            margin-top: 4px;
        }}
        .stat-card .change.positive {{ color: var(--accent-green); }}
        .stat-card .change.negative {{ color: var(--accent); }}

        /* Progress Card */
        .progress-card {{
            background: linear-gradient(135deg, var(--bg-secondary), var(--bg-tertiary));
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
        }}
        .progress-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }}
        .progress-title {{
            font-size: 14px;
            color: var(--text-secondary);
        }}
        .progress-amount {{
            font-size: 36px;
            font-weight: 700;
            background: linear-gradient(90deg, var(--accent-green), var(--accent-blue));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .progress-bar {{
            height: 8px;
            background: var(--bg-primary);
            border-radius: 4px;
            overflow: hidden;
            margin-bottom: 8px;
        }}
        .progress-fill {{
            height: 100%;
            background: linear-gradient(90deg, var(--accent-green), var(--accent-blue));
            border-radius: 4px;
            transition: width 0.5s ease;
        }}
        .progress-text {{
            font-size: 12px;
            color: var(--text-muted);
        }}

        /* Grid Layout */
        .grid-2 {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 24px;
            margin-bottom: 24px;
        }}
        .grid-3 {{
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 16px;
            margin-bottom: 24px;
        }}

        /* Card */
        .card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
        }}
        .card-header {{
            padding: 16px 20px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .card-title {{
            font-size: 14px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .card-body {{
            padding: 16px 20px;
        }}

        /* Chat */
        .chat-container {{
            display: flex;
            flex-direction: column;
            height: 400px;
        }}
        .chat-messages {{
            flex: 1;
            overflow-y: auto;
            padding: 16px;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }}
        .chat-message {{
            max-width: 85%;
            padding: 12px 16px;
            border-radius: 12px;
            font-size: 14px;
            line-height: 1.5;
        }}
        .chat-message.user {{
            align-self: flex-end;
            background: var(--accent-blue);
            color: white;
            border-bottom-right-radius: 4px;
        }}
        .chat-message.ai {{
            align-self: flex-start;
            background: var(--bg-tertiary);
            border-bottom-left-radius: 4px;
        }}
        .chat-message .sender {{
            font-size: 11px;
            font-weight: 600;
            margin-bottom: 4px;
            opacity: 0.8;
        }}
        .chat-input-container {{
            padding: 16px;
            border-top: 1px solid var(--border);
            display: flex;
            gap: 12px;
        }}
        .chat-input {{
            flex: 1;
            padding: 12px 16px;
            background: var(--bg-primary);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 14px;
            outline: none;
        }}
        .chat-input:focus {{ border-color: var(--accent-blue); }}
        .chat-input::placeholder {{ color: var(--text-muted); }}

        /* Button */
        .btn {{
            padding: 10px 20px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            border: none;
            transition: all 0.15s;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }}
        .btn-primary {{
            background: var(--accent-blue);
            color: white;
        }}
        .btn-primary:hover {{ opacity: 0.9; }}
        .btn-secondary {{
            background: var(--bg-tertiary);
            color: var(--text-primary);
        }}
        .btn-secondary:hover {{ background: var(--bg-hover); }}
        .btn-accent {{
            background: linear-gradient(135deg, var(--accent), var(--accent-yellow));
            color: white;
        }}
        .btn:disabled {{
            opacity: 0.5;
            cursor: not-allowed;
        }}

        /* Quick Actions */
        .quick-actions {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }}
        .action-btn {{
            padding: 8px 16px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text-primary);
            font-size: 13px;
            cursor: pointer;
            transition: all 0.15s;
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .action-btn:hover {{
            background: var(--bg-hover);
            border-color: var(--accent-blue);
        }}
        .action-btn:disabled {{
            opacity: 0.5;
            cursor: not-allowed;
        }}
        .action-btn .spinner {{
            width: 14px;
            height: 14px;
            border: 2px solid var(--text-muted);
            border-top-color: var(--accent-blue);
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            display: none;
        }}
        .action-btn.loading .spinner {{ display: block; }}
        .action-btn.loading .icon {{ display: none; }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}

        /* Task List */
        .task-list {{
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}
        .task-item {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px;
            background: var(--bg-primary);
            border-radius: 8px;
            cursor: pointer;
            transition: background 0.15s;
        }}
        .task-item:hover {{ background: var(--bg-tertiary); }}
        .task-status {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            flex-shrink: 0;
        }}
        .task-status.pending {{ background: var(--text-muted); }}
        .task-status.active {{ background: var(--accent-yellow); }}
        .task-status.completed {{ background: var(--accent-green); }}
        .task-content {{
            flex: 1;
            min-width: 0;
        }}
        .task-title {{
            font-size: 13px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        .task-meta {{
            font-size: 11px;
            color: var(--text-muted);
        }}
        .task-priority {{
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 10px;
            text-transform: uppercase;
            font-weight: 600;
        }}
        .task-priority.high {{ background: rgba(235,87,87,0.2); color: var(--accent); }}
        .task-priority.medium {{ background: rgba(217,166,72,0.2); color: var(--accent-yellow); }}
        .task-priority.low {{ background: rgba(77,171,154,0.2); color: var(--accent-green); }}

        /* Venture List */
        .venture-item {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px;
            background: var(--bg-primary);
            border-radius: 8px;
            margin-bottom: 8px;
        }}
        .venture-icon {{
            width: 36px;
            height: 36px;
            background: var(--bg-tertiary);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 18px;
        }}
        .venture-info {{ flex: 1; }}
        .venture-name {{ font-size: 13px; font-weight: 500; }}
        .venture-stats {{ font-size: 11px; color: var(--text-muted); }}
        .venture-status {{
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 500;
        }}
        .venture-status.building {{ background: rgba(217,166,72,0.2); color: var(--accent-yellow); }}
        .venture-status.profitable {{ background: rgba(77,171,154,0.2); color: var(--accent-green); }}
        .venture-status.scaling {{ background: rgba(82,156,202,0.2); color: var(--accent-blue); }}

        /* Activity */
        .activity-item {{
            display: flex;
            gap: 12px;
            padding: 10px 0;
            border-bottom: 1px solid var(--border);
        }}
        .activity-item:last-child {{ border-bottom: none; }}
        .activity-dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-top: 6px;
            flex-shrink: 0;
        }}
        .activity-content {{
            flex: 1;
        }}
        .activity-text {{
            font-size: 13px;
        }}
        .activity-time {{
            font-size: 11px;
            color: var(--text-muted);
        }}

        /* Toast */
        .toast {{
            position: fixed;
            bottom: 24px;
            right: 24px;
            padding: 16px 24px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 12px;
            box-shadow: 0 8px 24px var(--shadow);
            display: flex;
            align-items: center;
            gap: 12px;
            transform: translateY(100px);
            opacity: 0;
            transition: all 0.3s ease;
            z-index: 1000;
        }}
        .toast.show {{
            transform: translateY(0);
            opacity: 1;
        }}
        .toast.success {{ border-left: 4px solid var(--accent-green); }}
        .toast.error {{ border-left: 4px solid var(--accent); }}
        .toast.info {{ border-left: 4px solid var(--accent-blue); }}

        /* Empty State */
        .empty-state {{
            text-align: center;
            padding: 32px;
            color: var(--text-muted);
        }}
        .empty-state .icon {{
            font-size: 32px;
            margin-bottom: 12px;
        }}
    </style>
</head>
<body>
    <!-- Sidebar -->
    <aside class="sidebar">
        <div class="sidebar-header">
            <h1>
                <div class="logo">O</div>
                OpenClaw
            </h1>
        </div>

        <nav class="nav-section">
            <div class="nav-section-title">Dashboards</div>
            <a href="/command" class="nav-item active">
                <span class="icon">📊</span> Command Center
            </a>
            <a href="/profit" class="nav-item">
                <span class="icon">💰</span> Profit Tracker
            </a>
            <a href="/" class="nav-item">
                <span class="icon">📋</span> Task Manager
            </a>
        </nav>

        <nav class="nav-section">
            <div class="nav-section-title">AI Agents</div>
            <a href="#agents" class="nav-item" onclick="scrollToSection('agents')">
                <span class="icon">🎯</span> Marcus (Sovereign)
            </a>
            <a href="#chat" class="nav-item" onclick="scrollToSection('chat')">
                <span class="icon">🔮</span> Luna (Oracle)
            </a>
            <a href="#ventures" class="nav-item" onclick="scrollToSection('ventures')">
                <span class="icon">💵</span> Tony (Bookie)
                <span class="badge">{bookie_status['active_bets']}</span>
            </a>
        </nav>

        <nav class="nav-section">
            <div class="nav-section-title">Tools</div>
            <a href="/docs" class="nav-item">
                <span class="icon">📚</span> API Docs
            </a>
        </nav>

        <div class="sidebar-footer">
            <div class="user-info">
                <div class="user-avatar">{user_name[0].upper()}</div>
                <div class="user-details">
                    <div class="user-name">{user_name}</div>
                    <div class="user-role">Admin</div>
                </div>
                <a href="/logout" style="color:var(--text-muted);font-size:18px;" title="Logout">⏻</a>
            </div>
        </div>
    </aside>

    <!-- Main Content -->
    <main class="main">
        <div class="topbar">
            <div class="topbar-left">
                <h2>Command Center</h2>
                <div class="health-badge">
                    <div class="health-dot" style="background:{'var(--accent-green)' if health_score >= 70 else 'var(--accent-yellow)' if health_score >= 50 else 'var(--accent)'}"></div>
                    Health: {health_score:.0f}%
                </div>
            </div>
            <div class="quick-actions">
                <button class="action-btn" onclick="executeAction('generate-strategies')">
                    <span class="icon">✨</span>
                    <span class="spinner"></span>
                    Generate Ideas
                </button>
                <button class="action-btn" onclick="executeAction('launch-venture')">
                    <span class="icon">🚀</span>
                    <span class="spinner"></span>
                    Launch Venture
                </button>
                <button class="action-btn" onclick="executeAction('analyze-trends')">
                    <span class="icon">📈</span>
                    <span class="spinner"></span>
                    Analyze Market
                </button>
                <button class="action-btn" onclick="executeAction('run-check')">
                    <span class="icon">🔍</span>
                    <span class="spinner"></span>
                    Health Check
                </button>
            </div>
        </div>

        <div class="content">
            <!-- Progress Card -->
            <div class="progress-card">
                <div class="progress-header">
                    <div>
                        <div class="progress-title">Mission Progress</div>
                        <div class="progress-amount">${total_revenue:,.0f}</div>
                    </div>
                    <div style="text-align:right;">
                        <div class="progress-title">Target</div>
                        <div style="font-size:24px;font-weight:600;color:var(--text-secondary);">$1,000,000</div>
                    </div>
                </div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width:{min(progress_pct, 100):.1f}%;"></div>
                </div>
                <div class="progress-text">{progress_pct:.2f}% complete - ${target - total_revenue:,.0f} to go</div>
            </div>

            <!-- Stats Row -->
            <div class="stats-row">
                <div class="stat-card">
                    <div class="label">Monthly Revenue</div>
                    <div class="value" style="color:var(--accent-green);">${sov_status['mrr']:,.0f}</div>
                    <div class="change positive">MRR</div>
                </div>
                <div class="stat-card">
                    <div class="label">Active Ventures</div>
                    <div class="value" style="color:var(--accent-blue);">{sov_status['ventures_count']}</div>
                    <div class="change">{sov_status.get('ventures_profitable', 0)} profitable</div>
                </div>
                <div class="stat-card">
                    <div class="label">Bankroll</div>
                    <div class="value" style="color:var(--accent-yellow);">${bookie_status['total_bankroll']:,.0f}</div>
                    <div class="change">{bookie_status['active_bets']} active bets</div>
                </div>
                <div class="stat-card">
                    <div class="label">Win Rate</div>
                    <div class="value">{bookie_status['win_rate']*100:.0f}%</div>
                    <div class="change {'positive' if bookie_status['net_profit'] >= 0 else 'negative'}">${bookie_status['net_profit']:,.0f} net</div>
                </div>
            </div>

            <!-- Main Grid -->
            <div class="grid-2">
                <!-- Chat with Marcus -->
                <div class="card" id="chat">
                    <div class="card-header">
                        <div class="card-title">
                            <span>🎯</span> Chat with Marcus
                        </div>
                        <span style="font-size:12px;color:var(--text-muted);">The Mastermind</span>
                    </div>
                    <div class="chat-container">
                        <div class="chat-messages" id="chatMessages">
                            <!-- Messages will be loaded here -->
                        </div>
                        <div class="chat-input-container">
                            <input type="text" class="chat-input" id="chatInput" placeholder="Ask Marcus anything about strategy..." onkeypress="if(event.key==='Enter')sendMessage()">
                            <button class="btn btn-primary" onclick="sendMessage()">Send</button>
                        </div>
                    </div>
                </div>

                <!-- Ventures -->
                <div class="card" id="ventures">
                    <div class="card-header">
                        <div class="card-title">
                            <span>🚀</span> Active Ventures
                        </div>
                        <button class="btn btn-secondary" onclick="executeAction('launch-venture')" style="font-size:12px;padding:6px 12px;">+ New</button>
                    </div>
                    <div class="card-body" id="venturesList">
                        <!-- Ventures will be loaded here -->
                    </div>
                </div>
            </div>

            <!-- Tasks Grid -->
            <div class="grid-3" id="agents">
                <div class="card">
                    <div class="card-header">
                        <div class="card-title"><span>📋</span> Pending</div>
                        <span style="font-size:12px;color:var(--text-muted);">{len(pending_tasks)}</span>
                    </div>
                    <div class="card-body">
                        <div class="task-list" id="pendingTasks"></div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-header">
                        <div class="card-title"><span>🔄</span> In Progress</div>
                        <span style="font-size:12px;color:var(--text-muted);">{len(active_tasks)}</span>
                    </div>
                    <div class="card-body">
                        <div class="task-list" id="activeTasks"></div>
                    </div>
                </div>
                <div class="card">
                    <div class="card-header">
                        <div class="card-title"><span>✅</span> Completed</div>
                        <span style="font-size:12px;color:var(--text-muted);">{len(completed_tasks)}</span>
                    </div>
                    <div class="card-body">
                        <div class="task-list" id="completedTasks"></div>
                    </div>
                </div>
            </div>

            <!-- Activity Feed -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title"><span>📊</span> Activity Feed</div>
                    <span style="font-size:12px;color:var(--text-muted);">Live updates</span>
                </div>
                <div class="card-body" style="max-height:300px;overflow-y:auto;" id="activityFeed">
                    <!-- Activity will be loaded here -->
                </div>
            </div>
        </div>
    </main>

    <!-- Toast -->
    <div class="toast" id="toast"></div>

    <script>
        // Data from server
        const chatHistory = {chat_json};
        const ventures = {ventures_json};
        const activities = {activity_json};
        const pendingTasks = {json.dumps([dict(t) for t in pending_tasks])};
        const activeTasks = {json.dumps([dict(t) for t in active_tasks])};
        const completedTasks = {json.dumps([dict(t) for t in completed_tasks])};

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {{
            renderChat();
            renderVentures();
            renderTasks();
            renderActivity();
        }});

        // Render chat messages
        function renderChat() {{
            const container = document.getElementById('chatMessages');
            if (chatHistory.length === 0) {{
                container.innerHTML = '<div class="empty-state"><div class="icon">💬</div><p>Start a conversation with Marcus</p></div>';
                return;
            }}
            container.innerHTML = chatHistory.map(m => `
                <div class="chat-message ${{m.sender === 'user' ? 'user' : 'ai'}}">
                    <div class="sender">${{m.sender === 'sovereign' ? 'Marcus' : m.sender === 'user' ? 'You' : m.sender}}</div>
                    ${{m.content}}
                </div>
            `).join('');
            container.scrollTop = container.scrollHeight;
        }}

        // Send chat message
        async function sendMessage() {{
            const input = document.getElementById('chatInput');
            const message = input.value.trim();
            if (!message) return;

            // Add user message to UI
            const container = document.getElementById('chatMessages');
            container.innerHTML += `<div class="chat-message user"><div class="sender">You</div>${{message}}</div>`;
            container.scrollTop = container.scrollHeight;
            input.value = '';
            input.disabled = true;

            try {{
                const response = await fetch('/api/sovereign/chat', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{message: message}})
                }});
                const data = await response.json();

                if (data.response) {{
                    container.innerHTML += `<div class="chat-message ai"><div class="sender">Marcus</div>${{data.response}}</div>`;
                    container.scrollTop = container.scrollHeight;
                }}
            }} catch (err) {{
                showToast('Failed to send message', 'error');
            }}
            input.disabled = false;
            input.focus();
        }}

        // Execute quick action
        async function executeAction(action) {{
            const btn = event.target.closest('.action-btn');
            btn.classList.add('loading');
            btn.disabled = true;

            const endpoints = {{
                'generate-strategies': '/api/sovereign/generate-strategies',
                'launch-venture': '/api/sovereign/launch-venture',
                'analyze-trends': '/api/oracle/analyze-trends',
                'run-check': '/api/overseer/run-check'
            }};

            try {{
                const response = await fetch(endpoints[action], {{method: 'POST'}});
                const data = await response.json();

                if (data.success !== false) {{
                    showToast(getSuccessMessage(action, data), 'success');
                    setTimeout(() => location.reload(), 1500);
                }} else {{
                    showToast(data.error || 'Action failed', 'error');
                }}
            }} catch (err) {{
                showToast('Request failed', 'error');
            }}

            btn.classList.remove('loading');
            btn.disabled = false;
        }}

        function getSuccessMessage(action, data) {{
            const messages = {{
                'generate-strategies': `Generated ${{data.count || 0}} new strategies`,
                'launch-venture': `Launched: ${{data.venture || 'New venture'}}`,
                'analyze-trends': 'Market analysis complete',
                'run-check': `Health check: ${{data.health_score || 'OK'}}%`
            }};
            return messages[action] || 'Action completed';
        }}

        // Render ventures
        function renderVentures() {{
            const container = document.getElementById('venturesList');
            if (ventures.length === 0) {{
                container.innerHTML = '<div class="empty-state"><div class="icon">🚀</div><p>No ventures yet. Launch one!</p></div>';
                return;
            }}
            container.innerHTML = ventures.map(v => `
                <div class="venture-item">
                    <div class="venture-icon">${{v.status === 'profitable' ? '💰' : v.status === 'scaling' ? '📈' : '🔨'}}</div>
                    <div class="venture-info">
                        <div class="venture-name">${{v.name}}</div>
                        <div class="venture-stats">$${{v.revenue.toLocaleString()}} revenue · ${{v.roi.toFixed(0)}}% ROI</div>
                    </div>
                    <span class="venture-status ${{v.status}}">${{v.status}}</span>
                </div>
            `).join('');
        }}

        // Render tasks
        function renderTasks() {{
            renderTaskList('pendingTasks', pendingTasks, 'pending');
            renderTaskList('activeTasks', activeTasks, 'active');
            renderTaskList('completedTasks', completedTasks, 'completed');
        }}

        function renderTaskList(containerId, tasks, status) {{
            const container = document.getElementById(containerId);
            if (tasks.length === 0) {{
                container.innerHTML = '<div class="empty-state" style="padding:16px;"><p>No tasks</p></div>';
                return;
            }}
            container.innerHTML = tasks.map(t => `
                <div class="task-item">
                    <div class="task-status ${{status}}"></div>
                    <div class="task-content">
                        <div class="task-title">${{t.title || 'Task'}}</div>
                        <div class="task-meta">${{t.category || 'general'}}</div>
                    </div>
                    <span class="task-priority ${{t.priority || 'medium'}}">${{t.priority || 'med'}}</span>
                </div>
            `).join('');
        }}

        // Render activity
        function renderActivity() {{
            const container = document.getElementById('activityFeed');
            if (activities.length === 0) {{
                container.innerHTML = '<div class="empty-state"><div class="icon">📊</div><p>No activity yet</p></div>';
                return;
            }}
            const colors = {{
                'sovereign': 'var(--accent)',
                'oracle': 'var(--accent-purple)',
                'bookie': 'var(--accent-green)',
                'queen': 'var(--accent-yellow)',
                'overseer': 'var(--accent-blue)',
                'coder': 'var(--accent-blue)',
                'marketing': 'var(--accent)'
            }};
            container.innerHTML = activities.slice(0, 10).map(a => `
                <div class="activity-item">
                    <div class="activity-dot" style="background:${{colors[a.agent] || 'var(--text-muted)'}}"></div>
                    <div class="activity-content">
                        <div class="activity-text"><strong>${{a.agent}}</strong> ${{a.action}}</div>
                        <div class="activity-time">${{a.time}} · ${{a.details || ''}}</div>
                    </div>
                </div>
            `).join('');
        }}

        // Toast notification
        function showToast(message, type = 'info') {{
            const toast = document.getElementById('toast');
            toast.textContent = message;
            toast.className = 'toast ' + type + ' show';
            setTimeout(() => toast.classList.remove('show'), 3000);
        }}

        // Scroll to section
        function scrollToSection(id) {{
            document.getElementById(id)?.scrollIntoView({{behavior: 'smooth'}});
        }}
    </script>
</body>
</html>'''


# ============== PROFIT DASHBOARD ==============

@app.get("/profit", response_class=HTMLResponse)
async def profit_dashboard(request: Request):
    """Business profit tracking dashboard"""
    # Check authentication
    session = check_auth(request)
    if not session:
        return RedirectResponse(url="/login", status_code=303)

    # Get user info
    user_name = session.get("name", "User")

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
    <div class="header" style="display:flex;justify-content:space-between;align-items:center;">
        <div>
            <h1><span>$1M</span> MISSION CONTROL</h1>
            <p style="color:#888;margin-top:5px;">Autonomous Business Network | {len(sovereign.ventures)} Ventures | {bookie_status["active_bets"]} Active Bets</p>
        </div>
        <div style="display:flex;align-items:center;gap:15px;">
            <a href="/command" style="color:#888;text-decoration:none;font-size:13px;">Command</a>
            <a href="/" style="color:#888;text-decoration:none;font-size:13px;">Tasks</a>
            <span style="color:#ff6600;font-size:13px;">{user_name}</span>
            <a href="/logout" style="color:#888;font-size:12px;text-decoration:none;">Logout</a>
        </div>
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


# ============================================
# ALTERNATIVE ROUTES (aliases)
# ============================================

@app.get("/task-center", response_class=HTMLResponse)
async def task_center_redirect(request: Request):
    """Redirect to main dashboard (task center)"""
    session = check_auth(request)
    if not session:
        return RedirectResponse(url="/login", status_code=303)
    return RedirectResponse(url="/", status_code=303)

@app.get("/vibesecurity/profit", response_class=HTMLResponse)
async def vibesecurity_profit(request: Request):
    """VibeSecurity profit dashboard alias"""
    return await profit_dashboard(request)

@app.get("/vibesecurity/command", response_class=HTMLResponse)
async def vibesecurity_command(request: Request):
    """VibeSecurity command center alias"""
    return await command_center(request)

@app.get("/vibesecurity/tasks", response_class=HTMLResponse)
async def vibesecurity_tasks(request: Request):
    """VibeSecurity task center alias"""
    return await dashboard(request)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_alias(request: Request):
    """Dashboard alias"""
    session = check_auth(request)
    if not session:
        return RedirectResponse(url="/login", status_code=303)
    return RedirectResponse(url="/command", status_code=303)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
