"""
NEXUS QA - Quality Intelligence Platform
AI-powered autonomous QA testing with comprehensive security scanning
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
from .security_scanner import SecurityScanner as LegacySecurityScanner, generate_security_report, Framework

# NEXUS QA imports
from .security import SecurityScanner, get_scanner, ScanConfig
from .journeys import JourneyDetector, JourneyMapper, detect_journeys
from .engines import (
    ClarificationEngine, ClarificationType, ClarificationRequest,
    RecommendationsEngine, Priority, get_recommendations_engine
)
from .database import get_db

app = FastAPI(
    title="NEXUS QA",
    description="Quality Intelligence Platform - AI-powered QA testing with 80+ security checks",
    version="3.0.0"
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

# Initialize NEXUS QA engines
clarification_engine = ClarificationEngine()
recommendations_engine = get_recommendations_engine()
journey_mapper = JourneyMapper()

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


# ============================================================
# NEXUS QA - Enhanced Security Endpoints (80+ checks)
# ============================================================

nexus_scan_results = {}


class NexusScanRequest(BaseModel):
    url: HttpUrl
    categories: Optional[List[str]] = None  # Filter categories
    include_passive: bool = True
    include_active: bool = True


@app.get("/security/categories")
async def get_security_categories():
    """Get all 8 security check categories with their check counts."""
    scanner = get_scanner()
    return {
        "categories": [
            {
                "id": "data_security",
                "name": "Data Security",
                "description": "PII detection, encryption, data masking",
                "check_count": 10,
                "compliance": ["GDPR", "PCI-DSS", "ISO 27001"]
            },
            {
                "id": "credentials",
                "name": "Credentials & Secrets",
                "description": "API keys, tokens, hardcoded secrets",
                "check_count": 10,
                "compliance": ["OWASP", "CWE", "SOC 2"]
            },
            {
                "id": "rate_limiting",
                "name": "Rate Limiting & DoS",
                "description": "Brute force protection, rate limits",
                "check_count": 10,
                "compliance": ["OWASP", "NIST"]
            },
            {
                "id": "cache_storage",
                "name": "Cache & Storage",
                "description": "localStorage, cookies, CDN caching",
                "check_count": 10,
                "compliance": ["OWASP", "PCI-DSS"]
            },
            {
                "id": "auth",
                "name": "Authentication & Authorization",
                "description": "Session management, RBAC, IDOR",
                "check_count": 12,
                "compliance": ["OWASP", "CWE", "ISO 27001"]
            },
            {
                "id": "injection",
                "name": "Injection Vulnerabilities",
                "description": "SQL, XSS, SSTI, command injection",
                "check_count": 12,
                "compliance": ["OWASP", "CWE", "PCI-DSS"]
            },
            {
                "id": "infrastructure",
                "name": "Infrastructure Security",
                "description": "TLS, HSTS, CSP, CORS headers",
                "check_count": 10,
                "compliance": ["OWASP", "NIST", "ISO 27001"]
            },
            {
                "id": "business_logic",
                "name": "Business Logic",
                "description": "Workflow bypass, race conditions",
                "check_count": 8,
                "compliance": ["OWASP", "CWE"]
            }
        ],
        "total_checks": 82
    }


@app.get("/security/checks")
async def get_security_checks(category: Optional[str] = None):
    """Get all 82 security checks, optionally filtered by category."""
    # Import all checkers
    from .security.checks import (
        DataSecurityChecker, CredentialsChecker, RateLimitingChecker,
        CacheStorageChecker, AuthenticationChecker, InjectionChecker,
        InfrastructureChecker, BusinessLogicChecker
    )

    checkers = {
        "data_security": DataSecurityChecker(),
        "credentials": CredentialsChecker(),
        "rate_limiting": RateLimitingChecker(),
        "cache_storage": CacheStorageChecker(),
        "auth": AuthenticationChecker(),
        "injection": InjectionChecker(),
        "infrastructure": InfrastructureChecker(),
        "business_logic": BusinessLogicChecker()
    }

    all_checks = []
    for cat_id, checker in checkers.items():
        if category and cat_id != category:
            continue
        for check in checker.checks:
            all_checks.append({
                "id": check.id,
                "name": check.name,
                "description": check.description,
                "category": cat_id,
                "severity": check.severity.value,
                "compliance": check.compliance,
                "passive": check.passive
            })

    return {
        "checks": all_checks,
        "total": len(all_checks)
    }


@app.post("/security/scan/full")
async def start_full_security_scan(
    request: NexusScanRequest,
    background_tasks: BackgroundTasks
):
    """
    Start comprehensive security scan with 80+ checks.

    Categories:
    - data_security, credentials, rate_limiting, cache_storage
    - auth, injection, infrastructure, business_logic
    """
    scan_id = f"nexus_{uuid.uuid4().hex[:8]}"

    nexus_scan_results[scan_id] = {
        "scan_id": scan_id,
        "status": "pending",
        "url": str(request.url),
        "started_at": datetime.now().isoformat(),
        "categories": request.categories or ["all"]
    }

    background_tasks.add_task(
        run_nexus_scan,
        scan_id,
        str(request.url),
        request.categories,
        request.include_passive,
        request.include_active
    )

    return {
        "scan_id": scan_id,
        "status": "pending",
        "url": str(request.url),
        "message": "Full security scan started with 82 checks"
    }


async def run_nexus_scan(
    scan_id: str,
    url: str,
    categories: Optional[List[str]],
    include_passive: bool,
    include_active: bool
):
    """Execute comprehensive NEXUS security scan."""
    nexus_scan_results[scan_id]["status"] = "running"

    try:
        scanner = get_scanner()

        # Convert category strings to enums if provided
        category_enums = None
        if categories:
            from .models.security import SecurityCategory
            category_enums = []
            for cat in categories:
                try:
                    category_enums.append(SecurityCategory(cat))
                except ValueError:
                    pass

        config = ScanConfig(
            url=url,
            categories=category_enums
        )

        result = await scanner.scan(config)

        # Build category scores from results
        category_scores = {}
        category_data = {}
        for cat_result in result.category_results:
            category_scores[cat_result.category.value] = cat_result.score
            category_data[cat_result.category.value] = {
                "name": cat_result.category_name,
                "score": cat_result.score,
                "passed": cat_result.checks_passed,
                "failed": cat_result.checks_failed,
                "total": cat_result.checks_run
            }

        nexus_scan_results[scan_id].update({
            "status": "completed",
            "completed_at": datetime.now().isoformat(),
            "overall_score": result.overall_score,
            "category_scores": category_scores,
            "total_checks": result.total_checks,
            "passed": result.checks_passed,
            "failed": result.checks_failed,
            "categories": category_data,
            "recommendations_count": len(result.recommendations)
        })

    except Exception as e:
        nexus_scan_results[scan_id].update({
            "status": "failed",
            "error": str(e),
            "completed_at": datetime.now().isoformat()
        })


@app.get("/security/scan/full/{scan_id}")
async def get_nexus_scan(scan_id: str):
    """Get NEXUS security scan results."""
    if scan_id not in nexus_scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")
    return nexus_scan_results[scan_id]


# ============================================================
# NEXUS QA - Feature Flags & Classification
# ============================================================

from .security.feature_flags import CHECK_FLAGS, AI_FEATURES, get_summary, get_check_flags

@app.get("/security/feature-flags")
async def get_feature_flags():
    """
    Get feature classification for all security checks.

    Returns breakdown of:
    - DETERMINISTIC: Pure regex/header checks, 100% accurate
    - HEURISTIC: Rule-based guessing, may have false positives
    - AI_REQUIRED: Needs LLM/VLM (Premium)
    """
    summary = get_summary()

    return {
        "summary": summary,
        "checks": {
            check_id: {
                "check_type": flags["check_type"].value,
                "accuracy": flags["accuracy"].value,
                "method": flags["method"],
                "can_verify": flags["can_verify"],
                "requires_ai": flags["requires_ai"],
                "description": flags["description"]
            }
            for check_id, flags in CHECK_FLAGS.items()
        },
        "ai_features": {
            name: {
                "requires_ai": feat["requires_ai"],
                "ai_type": feat["ai_type"],
                "description": feat["description"]
            }
            for name, feat in AI_FEATURES.items()
        },
        "recommendations": {
            "free_tier": f"{summary['by_type']['deterministic']} deterministic checks available",
            "premium_tier": f"{len(AI_FEATURES)} AI-powered features",
            "accuracy_note": f"{summary['by_accuracy']['low']} checks are heuristic (may have false positives)"
        }
    }


@app.get("/security/checks/{check_id}/flags")
async def get_check_feature_flags(check_id: str):
    """Get feature flags for a specific check."""
    flags = get_check_flags(check_id)
    if not flags:
        raise HTTPException(status_code=404, detail=f"Check {check_id} not found")

    return {
        "check_id": check_id,
        "check_type": flags["check_type"].value,
        "accuracy": flags["accuracy"].value,
        "method": flags["method"],
        "can_verify": flags["can_verify"],
        "requires_ai": flags["requires_ai"],
        "description": flags["description"]
    }


class BulkTestRequest(BaseModel):
    """Request for bulk testing mapped journeys."""
    journey_id: Optional[str] = None
    url: Optional[HttpUrl] = None
    test_types: List[str] = ["headers", "cookies", "patterns"]
    skip_ai: bool = True  # Default to no AI for bulk testing


@app.post("/security/bulk-test")
async def run_bulk_test(
    request: BulkTestRequest,
    background_tasks: BackgroundTasks
):
    """
    Run deterministic security tests only (no AI required).

    This endpoint runs all DETERMINISTIC checks that don't require AI:
    - Header checks (HSTS, CSP, CORS, etc.)
    - Cookie security flags
    - Pattern detection (secrets, PII)
    - Protocol checks (HTTPS)

    These checks can run on mapped journeys without AI costs.
    """
    test_id = f"bulk_{uuid.uuid4().hex[:8]}"
    url = str(request.url) if request.url else None

    if not url and request.journey_id:
        # Get URL from journey
        if request.journey_id in journey_results:
            journey = journey_results[request.journey_id]
            url = journey.get("url")

    if not url:
        raise HTTPException(
            status_code=400,
            detail="Either url or valid journey_id required"
        )

    bulk_test_results[test_id] = {
        "test_id": test_id,
        "status": "pending",
        "url": url,
        "skip_ai": request.skip_ai,
        "test_types": request.test_types,
        "started_at": datetime.now().isoformat(),
        "deterministic_only": True
    }

    background_tasks.add_task(
        run_deterministic_tests,
        test_id,
        url,
        request.test_types
    )

    return {
        "test_id": test_id,
        "status": "started",
        "message": "Running deterministic tests (no AI)",
        "url": url
    }


bulk_test_results = {}


async def run_deterministic_tests(test_id: str, url: str, test_types: List[str]):
    """Run only deterministic checks (no AI)."""
    try:
        scanner = get_scanner()
        config = ScanConfig(url=url)

        # Run the scan
        result = await scanner.scan(config)

        # Filter to only deterministic/high-accuracy checks
        filtered_results = []
        for cat_result in result.category_results:
            filtered_checks = []
            for check_result in cat_result.results:
                flags = get_check_flags(check_result.check_id)
                # Only include deterministic checks
                if flags.get("check_type") == "deterministic" or \
                   (flags.get("accuracy") and flags["accuracy"].value in ["high", "medium"]):
                    filtered_checks.append({
                        "check_id": check_result.check_id,
                        "check_name": check_result.check_name,
                        "status": check_result.status.value,
                        "severity": check_result.severity.value,
                        "message": check_result.message,
                        "evidence": check_result.evidence,
                        "accuracy": flags.get("accuracy", {}).value if hasattr(flags.get("accuracy", {}), "value") else "unknown",
                        "method": flags.get("method", "unknown"),
                        "can_verify": flags.get("can_verify", False)
                    })

            if filtered_checks:
                filtered_results.append({
                    "category": cat_result.category.value,
                    "category_name": cat_result.category_name,
                    "checks": filtered_checks,
                    "passed": sum(1 for c in filtered_checks if c["status"] == "pass"),
                    "failed": sum(1 for c in filtered_checks if c["status"] == "fail"),
                    "warnings": sum(1 for c in filtered_checks if c["status"] == "warn")
                })

        total_checks = sum(len(r["checks"]) for r in filtered_results)
        total_passed = sum(r["passed"] for r in filtered_results)
        total_failed = sum(r["failed"] for r in filtered_results)

        bulk_test_results[test_id].update({
            "status": "completed",
            "completed_at": datetime.now().isoformat(),
            "results": filtered_results,
            "summary": {
                "total_deterministic_checks": total_checks,
                "passed": total_passed,
                "failed": total_failed,
                "score": round((total_passed / total_checks * 100) if total_checks > 0 else 0, 1),
                "ai_checks_skipped": 82 - total_checks  # Total checks minus deterministic
            }
        })

    except Exception as e:
        bulk_test_results[test_id].update({
            "status": "failed",
            "error": str(e),
            "completed_at": datetime.now().isoformat()
        })


@app.get("/security/bulk-test/{test_id}")
async def get_bulk_test_results(test_id: str):
    """Get bulk test results."""
    if test_id not in bulk_test_results:
        raise HTTPException(status_code=404, detail="Test not found")
    return bulk_test_results[test_id]


# ============================================================
# NEXUS QA - Journey Detection Endpoints
# ============================================================

journey_results = {}


class JourneyDetectRequest(BaseModel):
    url: HttpUrl
    max_depth: int = 2
    include_forms: bool = True


@app.post("/journeys/detect")
async def detect_user_journeys(
    request: JourneyDetectRequest,
    background_tasks: BackgroundTasks
):
    """Auto-detect user journeys from a web application."""
    journey_id = f"journey_{uuid.uuid4().hex[:8]}"

    journey_results[journey_id] = {
        "journey_id": journey_id,
        "status": "pending",
        "url": str(request.url),
        "started_at": datetime.now().isoformat()
    }

    background_tasks.add_task(
        run_journey_detection,
        journey_id,
        str(request.url),
        request.max_depth
    )

    return {
        "journey_id": journey_id,
        "status": "pending",
        "url": str(request.url)
    }


async def run_journey_detection(journey_id: str, url: str, max_depth: int):
    """Execute journey detection."""
    journey_results[journey_id]["status"] = "running"

    try:
        detector = JourneyDetector()
        journeys = await detector.detect(url, max_depth=max_depth)

        journey_results[journey_id].update({
            "status": "completed",
            "completed_at": datetime.now().isoformat(),
            "journeys_found": len(journeys),
            "journeys": [j.to_dict() for j in journeys]
        })

    except Exception as e:
        journey_results[journey_id].update({
            "status": "failed",
            "error": str(e),
            "completed_at": datetime.now().isoformat()
        })


@app.get("/journeys")
async def list_detected_journeys():
    """List all detected journeys."""
    return list(journey_results.values())


@app.get("/journeys/{journey_id}")
async def get_journey(journey_id: str):
    """Get a specific journey detection result."""
    if journey_id not in journey_results:
        raise HTTPException(status_code=404, detail="Journey not found")
    return journey_results[journey_id]


@app.get("/journeys/templates")
async def get_journey_templates():
    """Get standard journey templates."""
    return {
        "categories": journey_mapper.get_categories(),
        "templates": journey_mapper.get_all_templates()
    }


# ============================================================
# NEXUS QA - Clarification Endpoints
# ============================================================

@app.get("/clarifications")
async def get_pending_clarifications():
    """Get all pending clarification requests."""
    return {
        "pending": [c.to_dict() for c in clarification_engine.get_pending_clarifications()],
        "count": len(clarification_engine.get_pending_clarifications())
    }


@app.get("/clarifications/{clarification_id}")
async def get_clarification(clarification_id: str):
    """Get a specific clarification request."""
    clarification = clarification_engine.get_clarification(clarification_id)
    if not clarification:
        raise HTTPException(status_code=404, detail="Clarification not found")
    return clarification.to_dict()


class ClarificationResponse(BaseModel):
    response: str


@app.post("/clarifications/{clarification_id}/respond")
async def respond_to_clarification(
    clarification_id: str,
    response: ClarificationResponse
):
    """Respond to a clarification request."""
    success = clarification_engine.respond_to_clarification(
        clarification_id,
        response.response
    )
    if not success:
        raise HTTPException(status_code=404, detail="Clarification not found")
    return {"status": "responded", "clarification_id": clarification_id}


# ============================================================
# NEXUS QA - Recommendations Endpoints
# ============================================================

@app.get("/recommendations")
async def get_all_recommendations():
    """Get all open recommendations."""
    return {
        "recommendations": [r.to_dict() for r in recommendations_engine.get_all_recommendations()],
        "summary": recommendations_engine.get_summary()
    }


@app.get("/recommendations/{priority}")
async def get_recommendations_by_priority(priority: str):
    """Get recommendations by priority (P0, P1, P2)."""
    try:
        priority_enum = Priority(priority.upper())
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid priority. Use P0, P1, or P2")

    recs = recommendations_engine.get_by_priority(priority_enum)
    return {
        "priority": priority.upper(),
        "recommendations": [r.to_dict() for r in recs],
        "count": len(recs)
    }


@app.post("/recommendations/{rec_id}/resolve")
async def resolve_recommendation(rec_id: str, resolved_by: Optional[str] = None):
    """Mark a recommendation as resolved."""
    success = recommendations_engine.resolve_recommendation(rec_id, resolved_by)
    if not success:
        raise HTTPException(status_code=404, detail="Recommendation not found")
    return {"status": "resolved", "recommendation_id": rec_id}


@app.get("/recommendations/export/{format}")
async def export_recommendations(format: str):
    """Export recommendations (json, csv, markdown)."""
    if format not in ["json", "csv", "markdown"]:
        raise HTTPException(status_code=400, detail="Invalid format. Use json, csv, or markdown")

    return {
        "format": format,
        "data": recommendations_engine.export_recommendations(format)
    }


# ============================================================
# NEXUS QA v4.0 - Autonomous Multi-Agent Deep Scan
# ============================================================

from .agents import (
    Orchestrator, PMAgent, ExplorerAgent, DevToolsAgent,
    PlannerAgent, SecurityAgent, ReportAgent
)

# Store autonomous scan sessions
autonomous_scan_results = {}


class AutonomousScanRequest(BaseModel):
    url: HttpUrl
    deep_scan: bool = True  # Full multi-agent analysis
    timeout_minutes: int = 60  # Max scan duration


class AutonomousScanResponse(BaseModel):
    scan_id: str
    status: str
    url: str
    started_at: str
    estimated_duration_minutes: int


@app.post("/autonomous/scan", response_model=AutonomousScanResponse)
async def start_autonomous_scan(
    request: AutonomousScanRequest,
    background_tasks: BackgroundTasks
):
    """
    Start a fully autonomous deep security scan.

    This uses a multi-agent system to:
    1. Understand the product (PM Agent with VLM)
    2. Explore and map user journeys (Explorer Agent)
    3. Analyze APIs and network traffic (DevTools Agent)
    4. Create contextual test plan (Planner Agent)
    5. Execute 82+ security checks (Security Agent)
    6. Generate comprehensive PDF report (Report Agent)

    Expected duration: 30-60 minutes for thorough analysis.
    """
    scan_id = f"auto_{uuid.uuid4().hex[:12]}"
    url = str(request.url)

    # Initialize session
    session_data = {
        "id": scan_id,
        "url": url,
        "status": "starting",
        "phase": "initializing",
        "started_at": datetime.now().isoformat(),
        "completed_at": None,
        "progress": 0,
        "product_profile": None,
        "journeys": [],
        "api_inventory": [],
        "security_findings": [],
        "report_path": None,
        "errors": []
    }
    autonomous_scan_results[scan_id] = session_data

    # Run in background
    background_tasks.add_task(run_autonomous_scan, scan_id, url, request.timeout_minutes)

    return AutonomousScanResponse(
        scan_id=scan_id,
        status="starting",
        url=url,
        started_at=session_data["started_at"],
        estimated_duration_minutes=45
    )


async def run_autonomous_scan(scan_id: str, url: str, timeout_minutes: int):
    """Run the full autonomous scan with all agents."""
    session = autonomous_scan_results[scan_id]

    try:
        session["status"] = "running"
        session["phase"] = "product_analysis"

        # Create orchestrator
        orchestrator = Orchestrator()

        # Define agent classes to use
        agent_classes = [
            PMAgent,
            ExplorerAgent,
            DevToolsAgent,
            PlannerAgent,
            SecurityAgent,
            ReportAgent
        ]

        # Run the full scan
        result = await asyncio.wait_for(
            orchestrator.run_scan(url, agent_classes, {}),
            timeout=timeout_minutes * 60
        )

        # Update session with results
        session["status"] = "completed"
        session["phase"] = result.phase.value
        session["completed_at"] = datetime.now().isoformat()
        session["progress"] = 100
        session["product_profile"] = result.product_profile
        session["journeys"] = result.journeys
        session["api_inventory"] = result.api_inventory
        session["security_findings"] = result.security_findings
        session["report_path"] = result.report_path
        session["errors"] = result.errors

    except asyncio.TimeoutError:
        session["status"] = "timeout"
        session["errors"].append(f"Scan exceeded {timeout_minutes} minute timeout")

    except Exception as e:
        session["status"] = "failed"
        session["errors"].append(str(e))
        import traceback
        session["errors"].append(traceback.format_exc())


@app.get("/autonomous/scan/{scan_id}")
async def get_autonomous_scan(scan_id: str):
    """Get autonomous scan status and results."""
    if scan_id not in autonomous_scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    session = autonomous_scan_results[scan_id]

    return {
        "id": session["id"],
        "url": session["url"],
        "status": session["status"],
        "phase": session["phase"],
        "progress": session.get("progress", 0),
        "started_at": session["started_at"],
        "completed_at": session.get("completed_at"),
        "product_profile": session.get("product_profile"),
        "journeys_count": len(session.get("journeys", [])),
        "apis_count": len(session.get("api_inventory", [])),
        "findings_count": len(session.get("security_findings", [])),
        "report_path": session.get("report_path"),
        "errors": session.get("errors", [])[-5:]  # Last 5 errors
    }


@app.get("/autonomous/scan/{scan_id}/report")
async def get_autonomous_report(scan_id: str):
    """Get the full report for an autonomous scan."""
    if scan_id not in autonomous_scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    session = autonomous_scan_results[scan_id]

    if session["status"] != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Scan not completed. Current status: {session['status']}"
        )

    return {
        "id": session["id"],
        "url": session["url"],
        "completed_at": session["completed_at"],
        "product_analysis": session.get("product_profile", {}),
        "user_journeys": session.get("journeys", []),
        "api_inventory": session.get("api_inventory", []),
        "security_findings": session.get("security_findings", []),
        "report_path": session.get("report_path")
    }


@app.get("/autonomous/scan/{scan_id}/download")
async def download_autonomous_report(scan_id: str, format: str = "pdf"):
    """Download the report file."""
    if scan_id not in autonomous_scan_results:
        raise HTTPException(status_code=404, detail="Scan not found")

    session = autonomous_scan_results[scan_id]
    report_path = session.get("report_path")

    if not report_path or not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail="Report file not found")

    return FileResponse(
        report_path,
        filename=f"nexus_qa_report_{scan_id}.{format}",
        media_type="application/pdf" if format == "pdf" else "text/html"
    )


@app.get("/autonomous/scans")
async def list_autonomous_scans():
    """List all autonomous scans."""
    return {
        "scans": [
            {
                "id": s["id"],
                "url": s["url"],
                "status": s["status"],
                "phase": s["phase"],
                "started_at": s["started_at"],
                "completed_at": s.get("completed_at")
            }
            for s in autonomous_scan_results.values()
        ],
        "total": len(autonomous_scan_results)
    }


# ============================================================
# NEXUS QA - Enhanced Stats Endpoints
# ============================================================

@app.get("/stats/overview")
async def get_stats_overview():
    """Get comprehensive NEXUS QA statistics overview."""
    db = get_db()

    # Get recent scans
    recent_scans = len(nexus_scan_results)
    completed_scans = [s for s in nexus_scan_results.values() if s.get("status") == "completed"]

    # Calculate average score
    avg_score = 0
    if completed_scans:
        avg_score = sum(s.get("overall_score", 0) for s in completed_scans) / len(completed_scans)

    # Get recommendations summary
    rec_summary = recommendations_engine.get_summary()

    # Get test stats
    total_tests = len(test_results)
    passed_tests = len([t for t in test_results.values() if t.status == "completed"])

    return {
        "health_score": round(avg_score),
        "security_score": round(avg_score),
        "test_coverage": round((passed_tests / max(total_tests, 1)) * 100),
        "scans": {
            "total": recent_scans,
            "completed": len(completed_scans),
            "average_score": round(avg_score)
        },
        "tests": {
            "total": total_tests,
            "passed": passed_tests,
            "failed": total_tests - passed_tests
        },
        "recommendations": rec_summary,
        "journeys": {
            "detected": len(journey_results),
            "categories": journey_mapper.get_categories()
        },
        "clarifications": {
            "pending": len(clarification_engine.get_pending_clarifications())
        }
    }


@app.get("/stats/trends")
async def get_stats_trends(days: int = 7):
    """Get trend data for the past N days."""
    db = get_db()
    trends = db.get_trend_data(days)

    return {
        "days": days,
        "trends": trends
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
