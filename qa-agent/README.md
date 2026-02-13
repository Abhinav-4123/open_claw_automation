# TestGuard AI

AI-Powered QA Testing Platform with Security Framework Scanning

## Features

- **AI-Powered QA Testing**: Autonomous testing of login, signup, checkout, and custom flows
- **Security Framework Scanning**: OWASP Top 10, VAPT, ISO 27001, SOC 2, PCI DSS, GDPR
- **Multi-LLM Support**: Gemini, OpenAI, and Anthropic with automatic fallback
- **Real-time Dashboard**: Beautiful, responsive dashboard with live updates
- **Visual Reports**: Markdown reports with screenshots and recommendations

## Quick Start

### 1. Install Dependencies

```bash
cd qa-agent
pip install -r requirements.txt
playwright install chromium
```

### 2. Set Environment Variables

```bash
# Required for AI features
export GEMINI_API_KEY=your_gemini_api_key

# Optional fallbacks
export OPENAI_API_KEY=your_openai_key
export ANTHROPIC_API_KEY=your_anthropic_key
```

### 3. Run the Demo Server

```bash
python run_demo.py
```

### 4. Access the Application

- **Landing Page**: http://localhost:8000/
- **Dashboard**: http://localhost:8000/dashboard
- **API Docs**: http://localhost:8000/docs

## Running Demo Tests

```bash
# Make sure the server is running first
python demo_tests.py
```

## API Endpoints

### QA Testing

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/test` | POST | Create new QA test |
| `/tests` | GET | List all tests |
| `/test/{id}` | GET | Get test status |
| `/report/{id}` | GET | Get test report |

### Security Scanning

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/security/scan` | POST | Start security scan |
| `/security/scans` | GET | List all scans |
| `/security/scan/{id}` | GET | Get scan results |
| `/security/report/{id}` | GET | Get security report |

## Example: Run a QA Test

```python
import httpx

response = httpx.post("http://localhost:8000/test", json={
    "url": "https://github.com",
    "objective": "login"
})
print(response.json())
```

## Example: Run a Security Scan

```python
import httpx

response = httpx.post("http://localhost:8000/security/scan", json={
    "url": "https://example.com",
    "frameworks": ["owasp_top_10", "vapt", "iso_27001"]
})
print(response.json())
```

## Security Frameworks Supported

| Framework | Description |
|-----------|-------------|
| **OWASP Top 10** | Common web application security risks |
| **VAPT** | Vulnerability Assessment & Penetration Testing |
| **ISO 27001** | Information Security Management System |
| **SOC 2** | Trust Service Criteria |
| **PCI DSS** | Payment Card Industry Security |
| **GDPR** | Data Protection Compliance |

## Architecture

```
qa-agent/
├── app/
│   ├── main.py           # FastAPI application
│   ├── agent.py          # QA testing agent
│   ├── browser.py        # Playwright browser control
│   ├── security_scanner.py # Security framework scanning
│   ├── llm_provider.py   # Multi-LLM support
│   ├── reporter.py       # Report generation
│   ├── billing.py        # Stripe integration
│   └── alerts.py         # Alert system
├── landing/
│   └── index.html        # Landing page
├── dashboard/
│   └── index.html        # Dashboard
├── run_demo.py           # Demo runner
├── demo_tests.py         # Demo test script
└── requirements.txt
```

## Pricing

| Plan | Price | Features |
|------|-------|----------|
| Starter | $49/mo | 3 flows, daily tests, email alerts |
| Growth | $149/mo | 10 flows, hourly tests, Slack + email, OWASP scanning |
| Enterprise | Custom | Unlimited flows, compliance reports, SLA |

## License

Proprietary - All rights reserved
