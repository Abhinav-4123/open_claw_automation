# OpenClaw - Autonomous Agent Swarm

## What This Does

OpenClaw is a self-improving marketing and product development system:

1. **Queen (Orchestrator)** - Controls the swarm, sets strategy
2. **Marketing Agents** - Do outreach on Twitter/LinkedIn/Reddit
3. **Feedback Agents** - Collect and analyze responses
4. **Improvement Agents** - Propose product changes based on feedback

The system runs autonomously, improving itself based on what works.

---

## Quick Start

### Option 1: Run Locally (Development)

```bash
cd openclaw

# Install dependencies
pip install -r requirements.txt

# Run
python main.py
```

### Option 2: Deploy to GCP VM (Production)

```powershell
# Create the VM
.\deploy\gcp-vm-deploy.ps1

# Wait 2 minutes, then copy code
gcloud compute scp --recurse . openclaw-swarm:/home/$USER/openclaw --zone=us-central1-a

# SSH and start
gcloud compute ssh openclaw-swarm --zone=us-central1-a
cd openclaw
sudo docker-compose up -d
```

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Service status |
| `/start` | POST | Start the orchestrator |
| `/spawn` | POST | Spawn a specific agent |
| `/agents` | GET | List active agents |
| `/metrics` | GET | Business metrics |
| `/feedback` | GET | Collected feedback |
| `/improve` | POST | Trigger improvement cycle |

---

## Start the Swarm

```bash
# Start with default settings
curl -X POST http://localhost:8080/start \
  -H "Content-Type: application/json" \
  -d '{"goal": "$1M MRR", "initial_channels": ["twitter", "linkedin"], "targets_per_channel": 20}'
```

## Spawn Individual Agents

```bash
# Marketing agent
curl -X POST http://localhost:8080/spawn \
  -H "Content-Type: application/json" \
  -d '{"agent_type": "marketing", "platform": "twitter"}'

# Feedback agent
curl -X POST http://localhost:8080/spawn \
  -H "Content-Type: application/json" \
  -d '{"agent_type": "feedback"}'

# Improvement agent
curl -X POST http://localhost:8080/spawn \
  -H "Content-Type: application/json" \
  -d '{"agent_type": "improver", "focus_area": "pricing"}'
```

---

## Architecture

```
                    ┌─────────────────┐
                    │   ORCHESTRATOR  │
                    │    (Queen)      │
                    └────────┬────────┘
                             │
           ┌─────────────────┼─────────────────┐
           │                 │                 │
           ▼                 ▼                 ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
    │  MARKETING   │  │  FEEDBACK    │  │  IMPROVER    │
    │   AGENTS     │  │   AGENTS     │  │   AGENTS     │
    └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
           │                 │                 │
           └─────────────────┼─────────────────┘
                             │
                    ┌────────▼────────┐
                    │  SHARED MEMORY  │
                    │   (PostgreSQL)  │
                    └─────────────────┘
```

---

## The Autonomous Loop

1. **Queen** checks metrics
2. **Queen** spawns Marketing agents for outreach
3. Marketing agents send messages, log results
4. **Queen** spawns Feedback agent to analyze responses
5. Feedback agent extracts insights, stores in memory
6. **Queen** spawns Improver agent
7. Improver proposes changes based on feedback
8. Changes get implemented → Loop repeats

---

## Environment Variables

```bash
# Required
GEMINI_API_KEY=your-gemini-key

# Product Info
PRODUCT_NAME=TestGuard AI
PRODUCT_URL=https://testguard.ai
PRODUCT_PITCH=AI-powered QA testing

# Optional - Social APIs
TWITTER_API_KEY=
TWITTER_API_SECRET=
TWITTER_ACCESS_TOKEN=
TWITTER_ACCESS_SECRET=
```

---

## Connecting to Real Platforms

### Twitter/X
1. Apply for Twitter Developer account
2. Create app, get API keys
3. Add to `.env`
4. Update `agents/marketing.py` to use Tweepy

### LinkedIn
1. Create LinkedIn app
2. Get OAuth tokens
3. Use official API for posts (DMs require Sales Navigator)

### Reddit
1. Create Reddit app
2. Get client ID/secret
3. Use PRAW library

---

## Monitoring

```bash
# View active agents
curl http://localhost:8080/agents

# View metrics
curl http://localhost:8080/metrics

# View feedback
curl http://localhost:8080/feedback
```

---

## Cost Estimate

| Component | Cost/Month |
|-----------|------------|
| GCP VM (e2-standard-4) | ~$100 |
| Gemini API (10k requests/day) | ~$50 |
| PostgreSQL (Cloud SQL) | ~$25 |
| **Total** | **~$175/mo** |

With Google Startup credits ($350k), this runs free for ~2 years.

---

## What's Next

1. Deploy to GCP VM
2. Connect Twitter API for real outreach
3. Let it run for 24 hours
4. Check feedback and let Improver propose changes
5. Iterate

**The swarm will grow your business while you sleep.**
