"""
QA Testing Agent API
Autonomous QA testing for SaaS applications
With integrated Security Framework Scanning
"""
import os
import uuid
from datetime import datetime
from pathlib import Path

# Load environment variables from .env file
from dotenv import load_dotenv
env_path = Path(__file__).parent.parent / ".env"
load_dotenv(env_path)

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import Optional, List, Dict, Any
import asyncio

from .agent import QAAgent
from .reporter import ReportGenerator
from .alerts import AlertManager
from .billing import router as billing_router
from .security_scanner import SecurityScanner, generate_security_report, Framework

app = FastAPI(
    title="TestGuard AI",
    description="AI-powered autonomous QA testing with security framework scanning",
    version="2.0.0"
)

# Enable CORS for dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include billing routes
app.include_router(billing_router)

# Initialize alert manager
alert_manager = AlertManager()

# Store test results in memory (use Redis/DB in production)
test_results = {}


class Credentials(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    login_url: Optional[str] = None


class TestRequest(BaseModel):
    url: HttpUrl
    objective: str  # e.g., "signup", "checkout", "login", "full_flow"
    credentials: Optional[Credentials] = None
    steps: Optional[List[str]] = None  # Custom steps to execute
    webhook_url: Optional[HttpUrl] = None  # Notify on completion


class TestResult(BaseModel):
    test_id: str
    status: str  # "pending", "running", "completed", "failed"
    url: str
    objective: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    report_path: Optional[str] = None
    summary: Optional[dict] = None


@app.get("/")
async def root():
    return {
        "service": "QA Testing Agent",
        "status": "operational",
        "endpoints": {
            "POST /test": "Start a new test",
            "GET /test/{test_id}": "Get test status/results",
            "GET /tests": "List all tests"
        }
    }


@app.post("/test", response_model=TestResult)
async def create_test(request: TestRequest, background_tasks: BackgroundTasks):
    """
    Start a new QA test for the specified URL and objective.

    Objectives:
    - "signup": Test the signup/registration flow
    - "login": Test the login flow
    - "checkout": Test the checkout/payment flow
    - "full_flow": Test signup -> login -> core action
    - "custom": Execute custom steps provided in 'steps' field
    """
    test_id = str(uuid.uuid4())[:8]

    result = TestResult(
        test_id=test_id,
        status="pending",
        url=str(request.url),
        objective=request.objective,
        started_at=datetime.now()
    )

    test_results[test_id] = result

    # Run test in background
    background_tasks.add_task(
        run_test,
        test_id,
        request
    )

    return result


async def run_test(test_id: str, request: TestRequest):
    """Execute the QA test asynchronously"""
    test_results[test_id].status = "running"

    try:
        agent = QAAgent(
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
            openai_api_key=os.getenv("OPENAI_API_KEY")
        )

        results = await agent.run_test(
            url=str(request.url),
            objective=request.objective,
            credentials=request.credentials.model_dump() if request.credentials else None,
            custom_steps=request.steps
        )

        # Generate report
        reporter = ReportGenerator()
        report_path = reporter.generate(
            test_id=test_id,
            url=str(request.url),
            objective=request.objective,
            results=results
        )

        test_results[test_id].status = "completed"
        test_results[test_id].completed_at = datetime.now()
        test_results[test_id].report_path = report_path
        test_results[test_id].summary = {
            "passed": results.get("passed", 0),
            "failed": results.get("failed", 0),
            "steps_completed": results.get("steps_completed", []),
            "errors": results.get("errors", [])
        }

        # Send webhook notification if provided
        if request.webhook_url:
            await notify_webhook(str(request.webhook_url), test_results[test_id])

    except Exception as e:
        test_results[test_id].status = "failed"
        test_results[test_id].completed_at = datetime.now()
        test_results[test_id].summary = {"error": str(e)}


async def notify_webhook(url: str, result: TestResult):
    """Send test results to webhook URL"""
    import httpx
    async with httpx.AsyncClient() as client:
        try:
            await client.post(url, json=result.model_dump(mode="json"))
        except Exception:
            pass  # Log in production


@app.get("/test/{test_id}", response_model=TestResult)
async def get_test(test_id: str):
    """Get the status and results of a specific test"""
    if test_id not in test_results:
        raise HTTPException(status_code=404, detail="Test not found")
    return test_results[test_id]


@app.get("/tests", response_model=List[TestResult])
async def list_tests():
    """List all tests"""
    return list(test_results.values())


@app.get("/report/{test_id}")
async def get_report(test_id: str):
    """Get the markdown report for a completed test"""
    if test_id not in test_results:
        raise HTTPException(status_code=404, detail="Test not found")

    result = test_results[test_id]
    if not result.report_path:
        raise HTTPException(status_code=400, detail="Report not yet available")

    with open(result.report_path, "r") as f:
        return {"report": f.read()}


@app.post("/run-scheduled")
async def run_scheduled_tests(background_tasks: BackgroundTasks):
    """
    Run all scheduled daily tests.
    Called by Cloud Scheduler every morning.
    """
    # In production, load configured tests from database
    scheduled_tests = os.getenv("SCHEDULED_TESTS", "").split(",")

    results = []
    for test_config in scheduled_tests:
        if not test_config.strip():
            continue

        parts = test_config.strip().split("|")
        if len(parts) >= 2:
            url, objective = parts[0], parts[1]
            request = TestRequest(url=url, objective=objective)

            test_id = str(uuid.uuid4())[:8]
            result = TestResult(
                test_id=test_id,
                status="pending",
                url=url,
                objective=objective,
                started_at=datetime.now()
            )
            test_results[test_id] = result

            background_tasks.add_task(run_test, test_id, request)
            results.append({"test_id": test_id, "url": url})

    return {"scheduled": len(results), "tests": results}


@app.get("/health")
async def health_check():
    """Health check endpoint for Cloud Run"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


# Security Scanning Endpoints
security_scan_results = {}


class SecurityScanRequest(BaseModel):
    url: HttpUrl
    frameworks: Optional[List[str]] = None  # OWASP, VAPT, ISO_27001, SOC_2, PCI_DSS, GDPR


class SecurityScanResponse(BaseModel):
    scan_id: str
    status: str
    url: str
    started_at: datetime


@app.post("/security/scan", response_model=SecurityScanResponse)
async def start_security_scan(request: SecurityScanRequest, background_tasks: BackgroundTasks):
    """
    Start a security scan for the specified URL.

    Supported frameworks:
    - owasp_top_10: OWASP Top 10 2021
    - vapt: Vulnerability Assessment
    - iso_27001: ISO 27001 Compliance
    - soc_2: SOC 2 Trust Criteria
    - pci_dss: PCI DSS Payment Security
    - gdpr: GDPR Data Protection
    """
    scan_id = f"sec_{uuid.uuid4().hex[:8]}"

    result = SecurityScanResponse(
        scan_id=scan_id,
        status="pending",
        url=str(request.url),
        started_at=datetime.now()
    )

    security_scan_results[scan_id] = {
        "scan_id": scan_id,
        "status": "pending",
        "url": str(request.url),
        "started_at": datetime.now().isoformat(),
        "frameworks": request.frameworks or ["owasp_top_10", "vapt", "iso_27001", "soc_2"]
    }

    background_tasks.add_task(
        run_security_scan,
        scan_id,
        str(request.url),
        request.frameworks
    )

    return result


async def run_security_scan(scan_id: str, url: str, frameworks: Optional[List[str]]):
    """Execute security scan asynchronously"""
    security_scan_results[scan_id]["status"] = "running"

    try:
        from .browser import BrowserController

        browser = BrowserController()
        await browser.start()

        try:
            # Navigate and collect data
            await browser.navigate(url)
            content = await browser.get_page_content()

            # Get headers and cookies from page context
            headers = {}
            cookies = []
            forms = []

            # Extract page data
            page_data = await browser.page.evaluate("""() => {
                const forms = Array.from(document.forms).map(f => ({
                    action: f.action,
                    method: f.method,
                    inputs: Array.from(f.elements).map(e => ({
                        type: e.type,
                        name: e.name,
                        id: e.id,
                        autocomplete: e.autocomplete
                    }))
                }));
                return { forms };
            }""")
            forms = page_data.get("forms", [])

            # Get cookies
            cookies_raw = await browser.context.cookies()
            cookies = [
                {
                    "name": c.get("name"),
                    "secure": c.get("secure", False),
                    "httpOnly": c.get("httpOnly", False),
                    "sameSite": c.get("sameSite")
                }
                for c in cookies_raw
            ]

            # Run security scanner
            scanner = SecurityScanner()

            # Convert framework strings to enums
            framework_enums = None
            if frameworks:
                framework_enums = []
                for f in frameworks:
                    try:
                        framework_enums.append(Framework(f.lower()))
                    except ValueError:
                        pass

            result = await scanner.scan(
                url=url,
                page_content=content,
                headers=headers,
                cookies=cookies,
                forms=forms,
                frameworks=framework_enums
            )

            # Generate report
            report = generate_security_report(result)

            # Save results
            security_scan_results[scan_id].update({
                "status": "completed",
                "completed_at": datetime.now().isoformat(),
                "overall_score": result.overall_score,
                "framework_scores": result.framework_scores,
                "vulnerabilities_count": len(result.vulnerabilities),
                "summary": result.summary,
                "report": report,
                "vulnerabilities": [
                    {
                        "id": v.id,
                        "title": v.title,
                        "severity": v.severity.value,
                        "category": v.category,
                        "recommendation": v.recommendation
                    }
                    for v in result.vulnerabilities
                ]
            })

        finally:
            await browser.stop()

    except Exception as e:
        security_scan_results[scan_id].update({
            "status": "failed",
            "error": str(e),
            "completed_at": datetime.now().isoformat()
        })


@app.get("/security/scan/{scan_id}")
async def get_security_scan(scan_id: str):
    """Get security scan results"""
    if scan_id not in security_scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    return security_scan_results[scan_id]


@app.get("/security/scans")
async def list_security_scans():
    """List all security scans"""
    return list(security_scan_results.values())


@app.get("/security/report/{scan_id}")
async def get_security_report(scan_id: str):
    """Get security scan report in markdown format"""
    if scan_id not in security_scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    result = security_scan_results[scan_id]
    if result.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Scan not yet complete")

    return {"report": result.get("report", "No report available")}


# Stats endpoint for dashboard
@app.get("/stats")
async def get_stats():
    """Get overall testing statistics"""
    total_tests = len(test_results)
    completed = [t for t in test_results.values() if t.status == "completed"]
    failed = [t for t in test_results.values() if t.status == "failed" or (t.summary and t.summary.get("failed", 0) > 0)]

    total_scans = len(security_scan_results)
    completed_scans = [s for s in security_scan_results.values() if s.get("status") == "completed"]

    avg_score = 0
    if completed_scans:
        avg_score = sum(s.get("overall_score", 0) for s in completed_scans) / len(completed_scans)

    return {
        "tests": {
            "total": total_tests,
            "passed": len(completed) - len(failed),
            "failed": len(failed),
            "running": len([t for t in test_results.values() if t.status in ["pending", "running"]])
        },
        "security": {
            "total_scans": total_scans,
            "completed": len(completed_scans),
            "average_score": round(avg_score)
        }
    }


# Serve static files for landing page and dashboard
import os
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "landing")
DASHBOARD_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "dashboard")

@app.get("/", response_class=HTMLResponse)
async def serve_landing():
    """Serve landing page"""
    landing_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(landing_file):
        with open(landing_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>TestGuard AI</h1><p>Landing page not found</p>")


@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve dashboard"""
    dashboard_file = os.path.join(DASHBOARD_DIR, "index.html")
    if os.path.exists(dashboard_file):
        with open(dashboard_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>Dashboard</h1><p>Dashboard not found</p>")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
