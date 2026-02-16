"""
NEXUS QA - Quality Intelligence Platform
AI-powered autonomous QA testing with comprehensive security scanning
"""
import os
import uuid
from datetime import datetime
from pathlib import Path
from contextlib import asynccontextmanager

# Load environment variables from .env file
from dotenv import load_dotenv
env_path = Path(__file__).parent.parent / ".env"
load_dotenv(env_path)

# Initialize new infrastructure
from app.core import settings, setup_logging, get_logger
from app.db import init_db, close_db, check_db_health, get_db_stats

# Setup structured logging
setup_logging(
    level=settings.log_level,
    format=settings.log_format
)
logger = get_logger(__name__)

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Depends, Header, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl, validator
from typing import Optional, List, Dict, Any
import asyncio
import ipaddress
import re
import hashlib
import hmac
import time
from urllib.parse import urlparse

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


# Application lifespan for startup/shutdown events
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown."""
    # Startup
    logger.info("Starting NEXUS QA application...")
    try:
        await init_db()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.warning(f"Database initialization skipped (SQLite fallback): {e}")

    yield

    # Shutdown
    logger.info("Shutting down NEXUS QA application...")
    try:
        await close_db()
        logger.info("Database connection closed")
    except Exception as e:
        logger.warning(f"Database close error: {e}")


app = FastAPI(
    title="NEXUS QA",
    description="Quality Intelligence Platform - AI-powered QA testing with 80+ security checks",
    version="3.0.0",
    lifespan=lifespan
)

# Security: CORS configuration - restrict to known origins
ALLOWED_ORIGINS = [
    "https://vibesecurity.in",
    "https://www.vibesecurity.in",
    "https://app.vibesecurity.in",
    "http://localhost:3000",  # Local development
    "http://localhost:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)


# Security headers middleware
from starlette.middleware.base import BaseHTTPMiddleware

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

app.add_middleware(SecurityHeadersMiddleware)


# ============================================================
# SECURITY UTILITIES
# ============================================================

# API Key for authentication (should be in env vars in production)
API_KEYS = set(os.getenv("API_KEYS", "").split(",")) if os.getenv("API_KEYS") else set()
REQUIRE_AUTH = os.getenv("REQUIRE_AUTH", "false").lower() == "true"

# Rate limiting (simple in-memory, use Redis in production)
rate_limit_store: Dict[str, List[float]] = {}
RATE_LIMIT_REQUESTS = 100  # requests per window
RATE_LIMIT_WINDOW = 3600  # 1 hour


def check_rate_limit(client_ip: str) -> bool:
    """Check if client has exceeded rate limit."""
    now = time.time()
    if client_ip not in rate_limit_store:
        rate_limit_store[client_ip] = []

    # Clean old entries
    rate_limit_store[client_ip] = [
        t for t in rate_limit_store[client_ip]
        if now - t < RATE_LIMIT_WINDOW
    ]

    if len(rate_limit_store[client_ip]) >= RATE_LIMIT_REQUESTS:
        return False

    rate_limit_store[client_ip].append(now)
    return True


async def verify_api_key(x_api_key: Optional[str] = Header(None)):
    """Verify API key if authentication is required."""
    if not REQUIRE_AUTH:
        return True

    if not x_api_key or x_api_key not in API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key"
        )
    return True


def is_safe_url(url: str) -> bool:
    """
    Validate URL to prevent SSRF attacks.
    Blocks internal IPs, localhost, and metadata endpoints.
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return False

        # Block localhost and common internal hostnames
        blocked_hosts = [
            'localhost', '127.0.0.1', '0.0.0.0',
            'metadata.google.internal', '169.254.169.254',
            'metadata', 'kubernetes.default'
        ]

        if hostname.lower() in blocked_hosts:
            return False

        # Check if hostname is an IP address
        try:
            ip = ipaddress.ip_address(hostname)
            # Block private and reserved IPs
            if ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_link_local:
                return False
        except ValueError:
            # Not an IP address, check for internal domain patterns
            internal_patterns = [
                r'.*\.local$',
                r'.*\.internal$',
                r'.*\.corp$',
                r'^10\.\d+\.\d+\.\d+$',
                r'^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$',
                r'^192\.168\.\d+\.\d+$',
            ]
            for pattern in internal_patterns:
                if re.match(pattern, hostname.lower()):
                    return False

        # Only allow http/https
        if parsed.scheme not in ('http', 'https'):
            return False

        return True
    except Exception:
        return False


def sanitize_path(path: str, base_dir: str) -> Optional[str]:
    """Sanitize file path to prevent path traversal."""
    try:
        # Resolve to absolute path
        resolved = os.path.realpath(path)
        base_resolved = os.path.realpath(base_dir)

        # Ensure path is within base directory
        if resolved.startswith(base_resolved):
            return resolved
        return None
    except Exception:
        return None

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

    @validator('url')
    def validate_target_url(cls, v):
        url_str = str(v)
        if not is_safe_url(url_str):
            raise ValueError('URL targets internal or restricted resources')
        return v

    @validator('webhook_url')
    def validate_webhook_url(cls, v):
        if v:
            url_str = str(v)
            if not is_safe_url(url_str):
                raise ValueError('Webhook URL targets internal or restricted resources')
        return v


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
async def create_test(
    request: TestRequest,
    background_tasks: BackgroundTasks,
    req: Request,
    _: bool = Depends(verify_api_key)
):
    """
    Start a new QA test for the specified URL and objective.

    Objectives:
    - "signup": Test the signup/registration flow
    - "login": Test the login flow
    - "checkout": Test the checkout/payment flow
    - "full_flow": Test signup -> login -> core action
    - "custom": Execute custom steps provided in 'steps' field
    """
    # Rate limiting
    client_ip = req.client.host if req.client else "unknown"
    if not check_rate_limit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later."
        )

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
    # Validate test_id format to prevent injection
    if not re.match(r'^[a-f0-9]{8}$', test_id):
        raise HTTPException(status_code=400, detail="Invalid test ID format")

    if test_id not in test_results:
        raise HTTPException(status_code=404, detail="Test not found")

    result = test_results[test_id]
    if not result.report_path:
        raise HTTPException(status_code=400, detail="Report not yet available")

    # Sanitize path to prevent path traversal
    base_dir = os.path.dirname(os.path.dirname(__file__))
    safe_path = sanitize_path(result.report_path, base_dir)

    if not safe_path or not os.path.exists(safe_path):
        raise HTTPException(status_code=404, detail="Report file not found")

    with open(safe_path, "r") as f:
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
    # Check database health
    db_healthy = False
    try:
        db_healthy = await check_db_health()
    except Exception:
        pass

    db_stats = {}
    try:
        db_stats = await get_db_stats()
    except Exception:
        db_stats = {"status": "unavailable"}

    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": settings.app_version,
        "environment": settings.environment,
        "database": {
            "healthy": db_healthy,
            "stats": db_stats
        }
    }


# Security Scanning Endpoints
security_scan_results = {}


class SecurityScanRequest(BaseModel):
    url: HttpUrl
    frameworks: Optional[List[str]] = None  # OWASP, VAPT, ISO_27001, SOC_2, PCI_DSS, GDPR

    @validator('url')
    def validate_target_url(cls, v):
        url_str = str(v)
        if not is_safe_url(url_str):
            raise ValueError('URL targets internal or restricted resources')
        return v


class SecurityScanResponse(BaseModel):
    scan_id: str
    status: str
    url: str
    started_at: datetime


@app.post("/security/scan", response_model=SecurityScanResponse)
async def start_security_scan(
    request: SecurityScanRequest,
    background_tasks: BackgroundTasks,
    req: Request,
    _: bool = Depends(verify_api_key)
):
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
    # Rate limiting
    client_ip = req.client.host if req.client else "unknown"
    if not check_rate_limit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later."
        )

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

            # Run security scanner (use Legacy scanner for OWASP framework checks)
            scanner = LegacySecurityScanner()

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

    @validator('url')
    def validate_target_url(cls, v):
        url_str = str(v)
        if not is_safe_url(url_str):
            raise ValueError('URL targets internal or restricted resources')
        return v

    @validator('timeout_minutes')
    def validate_timeout(cls, v):
        # Limit timeout to prevent resource exhaustion
        if v < 1 or v > 120:
            raise ValueError('Timeout must be between 1 and 120 minutes')
        return v


class AutonomousScanResponse(BaseModel):
    scan_id: str
    status: str
    url: str
    started_at: str
    estimated_duration_minutes: int


@app.post("/autonomous/scan", response_model=AutonomousScanResponse)
async def start_autonomous_scan(
    request: AutonomousScanRequest,
    background_tasks: BackgroundTasks,
    req: Request,
    _: bool = Depends(verify_api_key)
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


# ============================================================
# NEXUS QA v5.0 - Live Scan with Real-Time Updates (SSE)
# ============================================================

from fastapi.responses import StreamingResponse
from .live_scan import (
    create_live_scan, get_live_scan, LiveScanner,
    live_scan_sessions, LiveScanSession
)


class LiveScanRequest(BaseModel):
    url: HttpUrl
    credentials: Optional[Dict[str, str]] = None  # {email, password}

    @validator('url')
    def validate_target_url(cls, v):
        url_str = str(v)
        if not is_safe_url(url_str):
            raise ValueError('URL targets internal or restricted resources')
        return v

    @validator('credentials')
    def sanitize_credentials(cls, v):
        """Sanitize credentials - don't store actual password in logs."""
        if v:
            # Return sanitized version
            return {
                'email': v.get('email', v.get('username', '')),
                'password': v.get('password', ''),  # Stored securely, not logged
                '_sanitized': True
            }
        return v


@app.post("/live/scan")
async def start_live_scan(
    request: LiveScanRequest,
    background_tasks: BackgroundTasks,
    req: Request,
    _: bool = Depends(verify_api_key)
):
    """
    Start a live scan with real-time SSE updates.

    Connect to /live/scan/{scan_id}/stream for real-time events.
    """
    # Rate limiting - stricter for live scans (resource intensive)
    client_ip = req.client.host if req.client else "unknown"
    if not check_rate_limit(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Please try again later."
        )

    session = create_live_scan(str(request.url))

    if request.credentials:
        session.provide_credentials(request.credentials)

    # Start scan in background
    async def run_scan():
        scanner = LiveScanner(session)
        await scanner.run()

    background_tasks.add_task(run_scan)

    return {
        "scan_id": session.scan_id,
        "url": session.url,
        "status": "starting",
        "stream_url": f"/live/scan/{session.scan_id}/stream",
        "status_url": f"/live/scan/{session.scan_id}",
        "message": "Connect to stream_url for real-time updates"
    }


@app.get("/live/scan/{scan_id}/stream")
async def live_scan_stream(scan_id: str):
    """
    SSE stream of live scan events.

    Events include:
    - browser_launched: Browser started on Linux VM
    - page_loaded: Page loaded with screenshot
    - screenshot_captured: New screenshot taken
    - form_detected: Form found on page
    - login_required: Credentials needed
    - journey_step: User journey step captured
    - api_call_detected: API call intercepted
    - context_note: Developer observation
    - finding_detected: Security issue found
    - scan_complete: Scan finished
    """
    session = get_live_scan(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")

    return StreamingResponse(
        session.event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@app.get("/live/scan/{scan_id}")
async def get_live_scan_status(scan_id: str):
    """Get current status of a live scan."""
    session = get_live_scan(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")

    return session.get_status()


@app.post("/live/scan/{scan_id}/credentials")
async def provide_scan_credentials(scan_id: str, credentials: Dict[str, str]):
    """Provide credentials for a scan awaiting login."""
    session = get_live_scan(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")

    if not session.awaiting_credentials:
        raise HTTPException(status_code=400, detail="Scan not awaiting credentials")

    session.provide_credentials(credentials)
    return {"status": "credentials_received", "scan_id": scan_id}


@app.get("/live/scan/{scan_id}/screenshots")
async def get_scan_screenshots(scan_id: str):
    """Get all screenshots from a scan."""
    session = get_live_scan(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": scan_id,
        "screenshots": session.screenshots,
        "count": len(session.screenshots)
    }


@app.get("/live/scan/{scan_id}/api-calls")
async def get_scan_api_calls(scan_id: str):
    """Get all intercepted API calls."""
    session = get_live_scan(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": scan_id,
        "api_calls": [call.to_dict() for call in session.api_calls],
        "count": len(session.api_calls)
    }


@app.get("/live/scan/{scan_id}/journey")
async def get_scan_journey(scan_id: str):
    """Get the discovered user journey."""
    session = get_live_scan(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": scan_id,
        "steps": [
            {
                "step": s.step_number,
                "url": s.url,
                "title": s.page_title,
                "action": s.action,
                "notes": s.notes,
                "timestamp": s.timestamp
            }
            for s in session.journey_steps
        ],
        "context_notes": session.context_notes
    }


@app.get("/live/scans")
async def list_live_scans():
    """List all live scans."""
    return {
        "scans": [s.get_status() for s in live_scan_sessions.values()],
        "total": len(live_scan_sessions)
    }


@app.post("/live/scan/{scan_id}/skip-login")
async def skip_login(scan_id: str):
    """Skip login and continue scan without authentication."""
    session = get_live_scan(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")

    session.awaiting_credentials = False
    return {"status": "login_skipped", "scan_id": scan_id}


@app.get("/live/scan/{scan_id}/report")
async def get_live_scan_report(scan_id: str):
    """Generate and download comprehensive PDF report for a live scan."""
    session = get_live_scan(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")

    from datetime import datetime

    # CWE and remediation mapping
    finding_details = {
        "X-Content-Type-Options": {
            "cwe": "CWE-16",
            "owasp": "A05:2021 - Security Misconfiguration",
            "risk": "MIME-type sniffing can lead to XSS attacks",
            "remediation": "Add header: X-Content-Type-Options: nosniff",
            "priority": "P2"
        },
        "X-Frame-Options": {
            "cwe": "CWE-1021",
            "owasp": "A05:2021 - Security Misconfiguration",
            "risk": "Clickjacking attacks can trick users into unintended actions",
            "remediation": "Add header: X-Frame-Options: DENY or SAMEORIGIN",
            "priority": "P1"
        },
        "Strict-Transport-Security": {
            "cwe": "CWE-319",
            "owasp": "A02:2021 - Cryptographic Failures",
            "risk": "Man-in-the-middle attacks, SSL stripping",
            "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "priority": "P1"
        },
        "Content-Security-Policy": {
            "cwe": "CWE-79",
            "owasp": "A03:2021 - Injection",
            "risk": "XSS attacks, data injection, clickjacking",
            "remediation": "Implement CSP: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
            "priority": "P1"
        },
        "X-XSS-Protection": {
            "cwe": "CWE-79",
            "owasp": "A03:2021 - Injection",
            "risk": "Reflected XSS attacks in older browsers",
            "remediation": "Add header: X-XSS-Protection: 1; mode=block (Note: Deprecated, use CSP instead)",
            "priority": "P3"
        },
        "Referrer-Policy": {
            "cwe": "CWE-200",
            "owasp": "A01:2021 - Broken Access Control",
            "risk": "Sensitive URL parameters leaked to third parties",
            "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
            "priority": "P2"
        },
        "Information Disclosure": {
            "cwe": "CWE-200",
            "owasp": "A05:2021 - Security Misconfiguration",
            "risk": "Server technology exposed aids targeted attacks",
            "remediation": "Remove or obscure Server header in web server configuration",
            "priority": "P3"
        },
        "Password": {
            "cwe": "CWE-522",
            "owasp": "A07:2021 - Identification and Authentication Failures",
            "risk": "Stored passwords may be auto-filled, increasing credential theft risk",
            "remediation": "Add autocomplete='new-password' to password fields",
            "priority": "P2"
        },
        "Cookie": {
            "cwe": "CWE-614",
            "owasp": "A07:2021 - Identification and Authentication Failures",
            "risk": "Session hijacking, XSS cookie theft",
            "remediation": "Set HttpOnly, Secure, and SameSite=Strict flags on all cookies",
            "priority": "P1"
        }
    }

    def get_finding_details(title):
        for key, details in finding_details.items():
            if key.lower() in title.lower():
                return details
        return {"cwe": "CWE-Unknown", "owasp": "A05:2021", "risk": "Security misconfiguration", "remediation": "Review and fix according to security best practices", "priority": "P2"}

    # Calculate score and severity counts
    severity_scores = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
    total_deduction = sum(severity_scores.get(f.get("severity", "info").lower(), 0) for f in session.findings)
    score = max(0, 100 - total_deduction)

    critical_count = len([f for f in session.findings if f.get("severity", "").lower() == "critical"])
    high_count = len([f for f in session.findings if f.get("severity", "").lower() == "high"])
    medium_count = len([f for f in session.findings if f.get("severity", "").lower() == "medium"])
    low_count = len([f for f in session.findings if f.get("severity", "").lower() == "low"])

    # Risk level
    if critical_count > 0 or high_count > 2:
        risk_level = "HIGH"
        risk_color = "#ef4444"
    elif high_count > 0 or medium_count > 3:
        risk_level = "MEDIUM"
        risk_color = "#f59e0b"
    else:
        risk_level = "LOW"
        risk_color = "#22c55e"

    # Build findings HTML with detailed info
    findings_html = ""
    p1_actions = []
    p2_actions = []
    p3_actions = []

    for idx, f in enumerate(session.findings, 1):
        severity = f.get("severity", "info").lower()
        title = f.get('title', f.get('id', 'Unknown'))
        details = get_finding_details(title)

        severity_colors = {"critical": "#ef4444", "high": "#f59e0b", "medium": "#eab308", "low": "#3b82f6", "info": "#6b7280"}
        severity_color = severity_colors.get(severity, "#6b7280")

        findings_html += f"""
        <div style="border: 1px solid #e5e7eb; padding: 20px; margin: 15px 0; border-radius: 8px; border-left: 4px solid {severity_color}; background: white; page-break-inside: avoid;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px;">
                <div>
                    <span style="display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: bold; color: white; background: {severity_color}; text-transform: uppercase;">
                        {severity}
                    </span>
                    <span style="display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 11px; background: #f3f4f6; color: #374151; margin-left: 8px;">
                        {details['cwe']}
                    </span>
                </div>
                <span style="font-size: 11px; color: #9ca3af;">#{idx}</span>
            </div>
            <h4 style="margin: 0 0 10px 0; color: #111827; font-size: 16px;">{title}</h4>
            <table style="width: 100%; font-size: 13px; margin-bottom: 12px;">
                <tr><td style="color: #6b7280; width: 120px; padding: 4px 0;">OWASP:</td><td style="color: #374151;">{details['owasp']}</td></tr>
                <tr><td style="color: #6b7280; padding: 4px 0;">Evidence:</td><td style="color: #374151; font-family: monospace; background: #f9fafb; padding: 4px 8px; border-radius: 4px;">{f.get('evidence', 'N/A')}</td></tr>
                <tr><td style="color: #6b7280; padding: 4px 0;">URL:</td><td style="color: #374151;">{f.get('url', session.url)}</td></tr>
                <tr><td style="color: #6b7280; padding: 4px 0;">Risk:</td><td style="color: #dc2626;">{details['risk']}</td></tr>
            </table>
            <div style="background: #f0fdf4; border: 1px solid #bbf7d0; padding: 12px; border-radius: 6px;">
                <div style="font-weight: 600; color: #166534; margin-bottom: 4px;">Remediation ({details['priority']})</div>
                <div style="color: #15803d; font-family: monospace; font-size: 12px;">{details['remediation']}</div>
            </div>
        </div>
        """

        action = f"{title}: {details['remediation']}"
        if details['priority'] == 'P1':
            p1_actions.append(action)
        elif details['priority'] == 'P2':
            p2_actions.append(action)
        else:
            p3_actions.append(action)

    if not findings_html:
        findings_html = "<p style='color: #22c55e; font-size: 18px;'>✅ No security vulnerabilities detected!</p>"

    # Build API analysis HTML
    api_html = ""
    for api in session.api_calls[:10]:
        method = api.method.upper() if hasattr(api, 'method') else api.get('method', 'GET').upper()
        path = api.path if hasattr(api, 'path') else api.get('path', api.get('url', 'N/A'))
        status = api.response_status if hasattr(api, 'response_status') else api.get('response_status', 0)
        headers = api.response_headers if hasattr(api, 'response_headers') else api.get('response_headers', {})

        method_colors = {"GET": "#22c55e", "POST": "#3b82f6", "PUT": "#f59e0b", "DELETE": "#ef4444"}
        method_color = method_colors.get(method, "#6b7280")

        # Check for missing security headers
        headers_lower = {k.lower(): v for k, v in headers.items()} if headers else {}
        missing = []
        if 'x-content-type-options' not in headers_lower: missing.append("X-Content-Type-Options")
        if 'x-frame-options' not in headers_lower: missing.append("X-Frame-Options")
        if 'strict-transport-security' not in headers_lower: missing.append("HSTS")
        if 'content-security-policy' not in headers_lower: missing.append("CSP")

        missing_html = f"<span style='color: #ef4444; font-size: 11px;'>Missing: {', '.join(missing)}</span>" if missing else "<span style='color: #22c55e; font-size: 11px;'>✓ Headers OK</span>"

        api_html += f"""
        <tr style="border-bottom: 1px solid #e5e7eb;">
            <td style="padding: 10px;"><span style="background: {method_color}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold;">{method}</span></td>
            <td style="padding: 10px; font-family: monospace; font-size: 12px; max-width: 300px; overflow: hidden; text-overflow: ellipsis;">{path}</td>
            <td style="padding: 10px; text-align: center;"><span style="color: {'#22c55e' if status < 400 else '#ef4444'}; font-weight: bold;">{status}</span></td>
            <td style="padding: 10px;">{missing_html}</td>
        </tr>
        """

    # Compliance mapping
    compliance_html = f"""
    <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
        <tr style="background: #f3f4f6;">
            <th style="padding: 12px; text-align: left; border-bottom: 2px solid #e5e7eb;">Framework</th>
            <th style="padding: 12px; text-align: left; border-bottom: 2px solid #e5e7eb;">Status</th>
            <th style="padding: 12px; text-align: left; border-bottom: 2px solid #e5e7eb;">Issues</th>
        </tr>
        <tr><td style="padding: 10px; border-bottom: 1px solid #e5e7eb;"><strong>OWASP Top 10</strong></td>
            <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;"><span style="color: {'#ef4444' if medium_count + high_count > 0 else '#22c55e'};">{'FAIL' if medium_count + high_count > 0 else 'PASS'}</span></td>
            <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">{medium_count + high_count + critical_count} issues</td></tr>
        <tr><td style="padding: 10px; border-bottom: 1px solid #e5e7eb;"><strong>PCI-DSS 4.0</strong></td>
            <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;"><span style="color: {'#ef4444' if high_count > 0 else '#22c55e'};">{'FAIL' if high_count > 0 else 'PASS'}</span></td>
            <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">Req 6.4.1, 6.4.2</td></tr>
        <tr><td style="padding: 10px; border-bottom: 1px solid #e5e7eb;"><strong>ISO 27001</strong></td>
            <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;"><span style="color: {'#f59e0b' if len(session.findings) > 5 else '#22c55e'};">{'REVIEW' if len(session.findings) > 5 else 'PASS'}</span></td>
            <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">A.14.1.2, A.14.1.3</td></tr>
        <tr><td style="padding: 10px; border-bottom: 1px solid #e5e7eb;"><strong>SOC 2 Type II</strong></td>
            <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;"><span style="color: {'#f59e0b' if medium_count > 2 else '#22c55e'};">{'REVIEW' if medium_count > 2 else 'PASS'}</span></td>
            <td style="padding: 10px; border-bottom: 1px solid #e5e7eb;">CC6.1, CC6.6</td></tr>
    </table>
    """

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Assessment Report - {scan_id}</title>
    <style>
        @page {{ size: A4; margin: 20mm; }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; line-height: 1.6; color: #1f2937; background: #fff; margin: 0; padding: 20px; }}
        .page-break {{ page-break-before: always; }}
        .header {{ background: linear-gradient(135deg, #6366f1, #8b5cf6); color: white; padding: 40px; margin: -20px -20px 30px -20px; }}
        .header h1 {{ margin: 0; font-size: 32px; }}
        .header p {{ margin: 10px 0 0 0; opacity: 0.9; }}
        .section {{ margin-bottom: 30px; }}
        .section-title {{ font-size: 20px; font-weight: 600; color: #111827; border-bottom: 2px solid #6366f1; padding-bottom: 8px; margin-bottom: 20px; }}
        .card {{ background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 20px; margin-bottom: 15px; }}
        .score-box {{ text-align: center; padding: 30px; background: white; border: 1px solid #e5e7eb; border-radius: 12px; }}
        .score-value {{ font-size: 64px; font-weight: bold; color: {'#22c55e' if score >= 80 else '#f59e0b' if score >= 60 else '#ef4444'}; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: white; border: 1px solid #e5e7eb; border-radius: 8px; padding: 15px; text-align: center; }}
        .stat-value {{ font-size: 28px; font-weight: bold; }}
        .stat-label {{ font-size: 12px; color: #6b7280; text-transform: uppercase; }}
        .risk-badge {{ display: inline-block; padding: 8px 20px; border-radius: 20px; font-weight: bold; font-size: 14px; background: {risk_color}; color: white; }}
        .priority-section {{ margin: 15px 0; padding: 15px; border-radius: 8px; }}
        .p1 {{ background: #fef2f2; border-left: 4px solid #ef4444; }}
        .p2 {{ background: #fffbeb; border-left: 4px solid #f59e0b; }}
        .p3 {{ background: #f0fdf4; border-left: 4px solid #22c55e; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ text-align: left; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #e5e7eb; text-align: center; color: #9ca3af; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Assessment Report</h1>
        <p>Comprehensive Security Analysis by VibeSecurity NEXUS QA</p>
    </div>

    <div class="section">
        <h2 class="section-title">Executive Summary</h2>
        <div class="card">
            <table style="width: 100%;">
                <tr><td style="width: 150px; color: #6b7280; padding: 8px 0;"><strong>Target URL:</strong></td><td>{session.url}</td></tr>
                <tr><td style="color: #6b7280; padding: 8px 0;"><strong>Scan ID:</strong></td><td style="font-family: monospace;">{scan_id}</td></tr>
                <tr><td style="color: #6b7280; padding: 8px 0;"><strong>Scan Date:</strong></td><td>{session.started_at}</td></tr>
                <tr><td style="color: #6b7280; padding: 8px 0;"><strong>Overall Risk:</strong></td><td><span class="risk-badge">{risk_level} RISK</span></td></tr>
            </table>
        </div>

        <div class="score-box">
            <div style="color: #6b7280; font-size: 14px; margin-bottom: 10px;">SECURITY SCORE</div>
            <div class="score-value">{score}<span style="font-size: 24px; color: #9ca3af;">/100</span></div>
        </div>

        <div class="stats-grid">
            <div class="stat-card"><div class="stat-value" style="color: #ef4444;">{critical_count}</div><div class="stat-label">Critical</div></div>
            <div class="stat-card"><div class="stat-value" style="color: #f59e0b;">{high_count}</div><div class="stat-label">High</div></div>
            <div class="stat-card"><div class="stat-value" style="color: #eab308;">{medium_count}</div><div class="stat-label">Medium</div></div>
            <div class="stat-card"><div class="stat-value" style="color: #3b82f6;">{low_count}</div><div class="stat-label">Low</div></div>
        </div>

        <div class="card">
            <strong>Scan Coverage:</strong>
            <div class="stats-grid" style="margin-top: 10px;">
                <div><strong>{len(session.api_calls)}</strong> API Calls Analyzed</div>
                <div><strong>{len(session.screenshots)}</strong> Screenshots Captured</div>
                <div><strong>{len(session.journey_steps)}</strong> User Journeys</div>
                <div><strong>82</strong> Security Checks Run</div>
            </div>
        </div>
    </div>

    <div class="section">
        <h2 class="section-title">Prioritized Action Items</h2>
        {'<div class="priority-section p1"><strong style="color: #dc2626;">🔴 Priority 1 - Immediate Action Required</strong><ul style="margin: 10px 0; padding-left: 20px;">' + "".join(f"<li>{a}</li>" for a in p1_actions) + '</ul></div>' if p1_actions else ''}
        {'<div class="priority-section p2"><strong style="color: #d97706;">🟡 Priority 2 - Address Soon</strong><ul style="margin: 10px 0; padding-left: 20px;">' + "".join(f"<li>{a}</li>" for a in p2_actions) + '</ul></div>' if p2_actions else ''}
        {'<div class="priority-section p3"><strong style="color: #16a34a;">🟢 Priority 3 - Best Practice</strong><ul style="margin: 10px 0; padding-left: 20px;">' + "".join(f"<li>{a}</li>" for a in p3_actions) + '</ul></div>' if p3_actions else ''}
    </div>

    <div class="page-break"></div>

    <div class="section">
        <h2 class="section-title">Compliance Mapping</h2>
        {compliance_html}
    </div>

    <div class="section">
        <h2 class="section-title">Detailed Findings ({len(session.findings)})</h2>
        {findings_html}
    </div>

    <div class="page-break"></div>

    <div class="section">
        <h2 class="section-title">API Security Analysis</h2>
        <p style="color: #6b7280; margin-bottom: 15px;">Analysis of {len(session.api_calls)} intercepted API calls for security header compliance.</p>
        <table style="background: white; border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden;">
            <thead style="background: #f3f4f6;">
                <tr>
                    <th style="padding: 12px; width: 80px;">Method</th>
                    <th style="padding: 12px;">Endpoint</th>
                    <th style="padding: 12px; width: 80px;">Status</th>
                    <th style="padding: 12px;">Security Headers</th>
                </tr>
            </thead>
            <tbody>
                {api_html if api_html else '<tr><td colspan="4" style="padding: 20px; text-align: center; color: #6b7280;">No API calls intercepted</td></tr>'}
            </tbody>
        </table>
    </div>

    <div class="footer">
        <p><strong>VibeSecurity NEXUS QA</strong> - Enterprise Security Assessment Platform</p>
        <p>https://vibesecurity.in | Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        <p style="margin-top: 10px; font-size: 10px;">This report is confidential and intended for authorized recipients only.</p>
    </div>
</body>
</html>
    """

    # Try to generate PDF using weasyprint
    try:
        from weasyprint import HTML
        import io

        pdf_buffer = io.BytesIO()
        HTML(string=html_content).write_pdf(pdf_buffer)
        pdf_buffer.seek(0)

        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=security_report_{scan_id}.pdf"
            }
        )
    except ImportError:
        # Fallback to HTML if weasyprint not available
        return HTMLResponse(
            content=html_content,
            headers={
                "Content-Disposition": f"attachment; filename=security_report_{scan_id}.html"
            }
        )


# Serve static files for landing page and dashboard
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
