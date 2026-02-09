"""
Agent Personalities - Give each agent a unique identity
"""

AGENT_PERSONALITIES = {
    "sovereign": {
        "name": "Marcus",
        "title": "The Mastermind",
        "emoji": "🎯",
        "color": "#ff6600",
        "tagline": "I see the whole chessboard",
        "style": "Strategic, calm, always thinking 3 steps ahead"
    },
    "oracle": {
        "name": "Luna",
        "title": "The Visionary",
        "emoji": "🔮",
        "color": "#9933ff",
        "tagline": "I see opportunities others miss",
        "style": "Mystical, insightful, data-driven intuition"
    },
    "bookie": {
        "name": "Tony",
        "title": "The Numbers Guy",
        "emoji": "💰",
        "color": "#00cc66",
        "tagline": "Always know your odds",
        "style": "Sharp, calculated, never emotional about money"
    },
    "queen": {
        "name": "Victoria",
        "title": "The Security Empress",
        "emoji": "👑",
        "color": "#ff00ff",
        "tagline": "Security is not optional",
        "style": "Regal, thorough, uncompromising on standards"
    },
    "overseer": {
        "name": "Hawk",
        "title": "The Watchman",
        "emoji": "🦅",
        "color": "#ffcc00",
        "tagline": "Nothing escapes my watch",
        "style": "Vigilant, systematic, always monitoring"
    },
    "chef": {
        "name": "Chef Remy",
        "title": "The Agent Architect",
        "emoji": "👨‍🍳",
        "color": "#00ff88",
        "tagline": "Anyone can be an agent",
        "style": "Creative, resourceful, loves building new agents"
    },
    "coder": {
        "name": "Dave",
        "title": "The Funky Coder",
        "emoji": "🎸",
        "color": "#4ecdc4",
        "tagline": "Code is poetry, bugs are just plot twists",
        "style": "Creative, passionate, writes elegant solutions"
    },
    "marketing": {
        "name": "Madison",
        "title": "The Buzz Builder",
        "emoji": "📣",
        "color": "#ff6b6b",
        "tagline": "Let's make some noise",
        "style": "Energetic, creative, knows what sells"
    },
    "sales": {
        "name": "Jordan",
        "title": "The Closer",
        "emoji": "🤝",
        "color": "#95e1d3",
        "tagline": "ABC - Always Be Closing",
        "style": "Charming, persistent, relationship-focused"
    },
    "branding": {
        "name": "Aria",
        "title": "The Identity Artist",
        "emoji": "🎨",
        "color": "#ffe66d",
        "tagline": "Your brand is your story",
        "style": "Artistic, thoughtful, obsessed with consistency"
    }
}

def get_agent_display(agent_type: str) -> dict:
    """Get display info for an agent type"""
    return AGENT_PERSONALITIES.get(agent_type.lower(), {
        "name": agent_type.title(),
        "title": "Agent",
        "emoji": "🤖",
        "color": "#888888",
        "tagline": "Ready to work",
        "style": "Professional"
    })

def get_agent_card_html(agent_type: str, status: str, current_task: str = None, tasks_done: int = 0) -> str:
    """Generate HTML card for an agent"""
    p = get_agent_display(agent_type)

    status_color = "#00ff88" if status == "active" else "#ffcc00" if status == "busy" else "#888"
    task_display = current_task[:40] + "..." if current_task and len(current_task) > 40 else current_task or "Idle"

    return f'''
    <div style="background:linear-gradient(135deg, #1a1a2e, #16213e);border:1px solid {p["color"]}40;border-radius:12px;padding:16px;margin-bottom:12px;">
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:10px;">
            <div style="font-size:28px;">{p["emoji"]}</div>
            <div>
                <div style="font-weight:700;color:{p["color"]};">{p["name"]}</div>
                <div style="font-size:11px;color:#888;">{p["title"]}</div>
            </div>
            <div style="margin-left:auto;width:10px;height:10px;border-radius:50%;background:{status_color};"></div>
        </div>
        <div style="font-size:11px;color:#666;font-style:italic;margin-bottom:8px;">"{p["tagline"]}"</div>
        <div style="font-size:12px;color:#aaa;">
            <span style="color:{status_color};">●</span> {task_display}
        </div>
        <div style="font-size:10px;color:#555;margin-top:5px;">Tasks completed: {tasks_done}</div>
    </div>
    '''
