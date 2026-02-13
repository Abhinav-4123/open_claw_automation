# TestGuard AI - Launch Guide

## Quick Start (5 minutes)

### 1. Set Your API Key (Pick ONE)

**Gemini (Recommended - Cheapest)**
```bash
# Windows PowerShell
$env:GEMINI_API_KEY = "your-gemini-key"

# Mac/Linux
export GEMINI_API_KEY="your-gemini-key"
```

**OpenAI**
```bash
$env:OPENAI_API_KEY = "sk-your-key"
```

**Anthropic**
```bash
$env:ANTHROPIC_API_KEY = "sk-ant-your-key"
```

**Auto Mode (tries all, uses first that works)**
```bash
$env:LLM_PROVIDER = "auto"
# Set any/all API keys above
```

### 2. Deploy to GCP
```powershell
# Windows
cd qa-agent
.\scripts\deploy.ps1
```

```bash
# Mac/Linux
cd qa-agent
chmod +x scripts/deploy.sh
./scripts/deploy.sh
```

### 3. Test It
```bash
curl -X POST https://YOUR-API-URL/test \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "objective": "login"}'
```

---

## What You Built

```
qa-agent/
├── app/
│   ├── main.py          # FastAPI server
│   ├── agent.py         # Claude-powered QA agent
│   ├── browser.py       # Playwright automation
│   ├── reporter.py      # Markdown reports
│   ├── alerts.py        # Slack/Email notifications
│   └── billing.py       # Stripe integration
├── landing/
│   ├── index.html       # Marketing landing page
│   └── Dockerfile
├── dashboard/
│   └── index.html       # Client dashboard UI
├── terraform/
│   └── main.tf          # GCP infrastructure
├── scripts/
│   ├── deploy.sh        # Linux/Mac deploy
│   └── deploy.ps1       # Windows deploy
├── outreach/
│   ├── linkedin_dm.md   # DM templates
│   └── email_sequences.md
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/test` | POST | Start a new QA test |
| `/test/{id}` | GET | Get test status |
| `/tests` | GET | List all tests |
| `/report/{id}` | GET | Get markdown report |
| `/run-scheduled` | POST | Run daily scheduled tests |
| `/billing/plans` | GET | Get pricing plans |
| `/billing/checkout-session` | POST | Create Stripe checkout |

---

## Environment Variables

```bash
# LLM Provider (pick one or use "auto")
LLM_PROVIDER=gemini  # or: openai, anthropic, auto

# API Keys (set at least one)
GEMINI_API_KEY=xxx        # Cheapest option
OPENAI_API_KEY=sk-xxx
ANTHROPIC_API_KEY=sk-ant-xxx

# Optional - Alerts
SLACK_WEBHOOK_URL=https://hooks.slack.com/xxx
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@gmail.com
SMTP_PASS=app-password

# Optional - Billing
STRIPE_SECRET_KEY=sk_live_xxx
STRIPE_WEBHOOK_SECRET=whsec_xxx
STRIPE_STARTER_PRICE_ID=price_xxx
STRIPE_GROWTH_PRICE_ID=price_xxx

# Optional - Scheduled Tests (pipe-separated)
SCHEDULED_TESTS=https://app1.com|login,https://app2.com|checkout
```

---

## Go-To-Market Checklist

### Today
- [ ] Deploy to GCP (run `deploy.ps1`)
- [ ] Buy domain on Namecheap/Cloudflare
- [ ] Point domain to Cloud Run URL
- [ ] Set up Stripe account + products
- [ ] Send 20 LinkedIn DMs using templates in `/outreach`

### This Week
- [ ] Get 3 beta users running free trials
- [ ] Collect testimonials
- [ ] Set up cold email infrastructure (Instantly.ai)

### This Month
- [ ] Convert 5-10 paying customers ($7,500-$15,000 MRR)
- [ ] Hire VA for outreach ($500/mo)
- [ ] Build case studies

---

## Pricing (Pre-configured)

| Plan | Price | Flows | Features |
|------|-------|-------|----------|
| Starter | $499/mo | 3 | Daily tests, Email alerts |
| Growth | $1,499/mo | 10 | Hourly tests, Slack alerts, Priority support |
| Enterprise | $2,500/mo | Unlimited | Custom integrations, SLA |

---

## Support Commands

```bash
# View logs
gcloud run logs read qa-agent-api --region us-central1

# Update deployment
gcloud run deploy qa-agent-api --image gcr.io/PROJECT/qa-agent/api:latest

# Check service status
gcloud run services describe qa-agent-api --region us-central1
```

---

## Your $1M MRR Path

| Month | Target MRR | Customers | How |
|-------|------------|-----------|-----|
| 1 | $10,000 | 7 | Founder sales, beta conversions |
| 3 | $30,000 | 20 | Cold outreach, referrals |
| 6 | $100,000 | 67 | Hire SDR, content marketing |
| 12 | $500,000 | 333 | Sales team, partnerships |
| 18 | $1,000,000 | 667 | Enterprise deals, expansion |

**Go ship it.**
