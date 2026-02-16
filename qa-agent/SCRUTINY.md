# NEXUS QA - Comprehensive Architecture Scrutiny

**Document Version:** 1.0
**Date:** 2026-02-16
**Authors:** Product Manager & Solution Architect
**Classification:** Internal - Architecture Review

---

## Executive Summary

This document provides a comprehensive scrutiny of the NEXUS QA Security Testing Platform from both Product Management and Solution Architecture perspectives. The analysis identifies critical gaps, architectural weaknesses, and provides a prioritized roadmap for improvement.

**Overall Assessment:** The platform has a solid foundation but requires significant architectural improvements to be production-ready for enterprise customers.

| Category | Current State | Target State | Priority |
|----------|--------------|--------------|----------|
| Scalability | Poor | High | P0 |
| Reliability | Medium | High | P0 |
| Security | Medium | High | P0 |
| Observability | Poor | High | P1 |
| Code Quality | Medium | High | P1 |
| User Experience | Medium | High | P1 |

---

## Part 1: Product Management Analysis

### 1.1 Current Product Capabilities

#### Core Features
| Feature | Status | Maturity | Notes |
|---------|--------|----------|-------|
| Live Security Scanning | Implemented | Beta | AI-driven exploration works |
| 82 Security Checks | Implemented | Production | Comprehensive coverage |
| Multi-Agent System | Implemented | Alpha | Needs stabilization |
| Real-time Dashboard | Implemented | Beta | Missing event handlers |
| PDF Report Generation | Implemented | Beta | Basic formatting |
| Journey Detection | Implemented | Alpha | Limited accuracy |
| API Discovery | Implemented | Beta | Good interception |

#### User Journeys Supported
1. **Quick Scan** - Basic security header analysis (~2 min)
2. **Deep Scan** - AI-driven exploration with authentication (~30-60 min)
3. **Autonomous Scan** - Full 6-agent analysis (~45-60 min)
4. **Bulk Testing** - Deterministic checks only (~5 min)

### 1.2 Product Gaps

#### Critical (P0) - Blocking Revenue
| Gap | Impact | Effort | Resolution |
|-----|--------|--------|------------|
| Scan failures not recoverable | Lost customer trust | Medium | Implement checkpoint/resume |
| No scan scheduling | Missing enterprise feature | Low | Add cron-based scheduler |
| No multi-tenant support | Can't serve enterprise | High | Implement tenant isolation |
| No SSO integration | Enterprise blocker | Medium | Add SAML/OIDC support |

#### High (P1) - Impacting Growth
| Gap | Impact | Effort | Resolution |
|-----|--------|--------|------------|
| No comparison reports | Can't show progress | Medium | Add diff engine |
| Limited integrations | No CI/CD integration | Medium | Add GitHub/GitLab/Jenkins |
| No API rate info | Confusing for developers | Low | Add rate limit headers |
| No webhook notifications | No async alerting | Low | Implement webhooks |

#### Medium (P2) - Nice to Have
| Gap | Impact | Effort | Resolution |
|-----|--------|--------|------------|
| No mobile support | Limited accessibility | High | Responsive redesign |
| No team collaboration | Single-user focus | High | Add team features |
| No custom checks | Limited flexibility | Medium | Check plugin system |

### 1.3 Competitive Analysis

| Feature | NEXUS QA | Burp Suite | OWASP ZAP | Acunetix |
|---------|----------|------------|-----------|----------|
| AI-Driven | Yes | No | No | Limited |
| VLM Analysis | Yes | No | No | No |
| Multi-Agent | Yes | No | No | No |
| Real-time UI | Yes | Yes | Yes | Yes |
| API Discovery | Yes | Yes | Yes | Yes |
| Auth Handling | Manual | Manual | Manual | Automatic |
| CI/CD Integration | No | Yes | Yes | Yes |
| Price | $499/mo | $449/yr | Free | $4,495/yr |

**Unique Value Proposition:** Only platform using Vision Language Models for intelligent UI exploration and multi-agent autonomous testing.

### 1.4 Customer Feedback Themes

Based on usage patterns and the conversation history:

1. **"Scan exits too quickly"** - Need longer exploration with checkpoints
2. **"Can't see what's happening"** - Need better real-time visualization
3. **"Login always fails"** - Need better auth handling with 2FA support
4. **"Report not detailed enough"** - Need executive + technical views
5. **"Can't integrate with CI/CD"** - Need CLI tool and API improvements

---

## Part 2: Solution Architecture Analysis

### 2.1 Current Architecture

```
                    ┌─────────────────────────────────────────┐
                    │            CURRENT STATE                │
                    └─────────────────────────────────────────┘

    ┌─────────────┐      ┌─────────────────────────────────────┐
    │   Client    │◄────►│           FastAPI Server            │
    │  (Browser)  │      │                                     │
    └─────────────┘      │  ┌─────────┐  ┌─────────────────┐  │
                         │  │ In-Mem  │  │   Background    │  │
                         │  │ Storage │  │     Tasks       │  │
                         │  └─────────┘  └─────────────────┘  │
                         │                                     │
                         │  ┌─────────────────────────────────┐│
                         │  │        Multi-Agent System       ││
                         │  │  ┌────┐┌────┐┌────┐┌────┐┌────┐││
                         │  │  │ PM ││Expl││Plan││Sec ││Rpt │││
                         │  │  └────┘└────┘└────┘└────┘└────┘││
                         │  └─────────────────────────────────┘│
                         │                                     │
                         │  ┌──────────┐  ┌─────────────────┐  │
                         │  │ SQLite   │  │   Playwright    │  │
                         │  │   DB     │  │    Browser      │  │
                         │  └──────────┘  └─────────────────┘  │
                         │                                     │
                         │  ┌─────────────────────────────────┐│
                         │  │      External APIs              ││
                         │  │  Gemini │ OpenAI │ Anthropic    ││
                         │  └─────────────────────────────────┘│
                         └─────────────────────────────────────┘
```

### 2.2 Architecture Anti-Patterns Identified

#### 2.2.1 Stateful In-Memory Storage
```python
# CURRENT - Anti-pattern
test_results = {}
security_scan_results = {}
nexus_scan_results = {}
autonomous_scan_results = {}
live_scan_sessions = {}
```

**Issues:**
- Data lost on server restart
- Can't scale horizontally
- Memory grows unbounded
- No persistence guarantees

#### 2.2.2 Synchronous Long-Running Tasks
```python
# CURRENT - Blocking operation
@app.post("/autonomous/scan")
async def start_autonomous_scan(...):
    background_tasks.add_task(run_autonomous_scan, ...)
```

**Issues:**
- Background tasks not durable
- No retry on failure
- No progress persistence
- Server restart kills all scans

#### 2.2.3 Single Browser Instance
```python
# CURRENT - Resource contention
async def run_scan():
    playwright = await async_playwright().start()
    browser = await playwright.chromium.launch()
```

**Issues:**
- New browser per scan (slow)
- No connection pooling
- Resource exhaustion under load
- No browser reuse

#### 2.2.4 Monolithic Rate Limiting
```python
# CURRENT - Non-distributed
rate_limit_store = {}  # In-memory

def check_rate_limit(client_ip: str) -> bool:
    # Only works on single instance
```

**Issues:**
- Doesn't work with multiple servers
- Memory-based, lost on restart
- No sliding window
- Easy to bypass

### 2.3 Critical Technical Debt

| Area | Debt | Risk | Remediation Cost |
|------|------|------|-----------------|
| Storage | In-memory dicts | High | 2 weeks |
| Job Queue | BackgroundTasks | High | 1 week |
| Database | SQLite | Medium | 1 week |
| Caching | None | Medium | 3 days |
| Logging | Print statements | High | 3 days |
| Monitoring | None | High | 1 week |
| Testing | No tests | Critical | 2 weeks |
| Error Handling | Basic | High | 1 week |

### 2.4 Scalability Bottlenecks

#### Current Limits (Single Instance)
| Resource | Limit | Bottleneck |
|----------|-------|------------|
| Concurrent Scans | ~5 | Playwright memory |
| Requests/Second | ~100 | CPU-bound analysis |
| Memory Usage | ~2GB | In-memory storage |
| Storage | Unlimited growth | No cleanup |

#### Required for Production
| Metric | Target | Solution |
|--------|--------|----------|
| Concurrent Scans | 100+ | Browser pool + job queue |
| Requests/Second | 1000+ | Horizontal scaling |
| Availability | 99.9% | Multi-region deployment |
| Data Retention | Configurable | Automated cleanup |

### 2.5 Security Vulnerabilities in Platform

| Issue | Severity | Location | Fix |
|-------|----------|----------|-----|
| API keys in environment | Medium | .env | Use secrets manager |
| No request signing | Medium | All endpoints | Add HMAC signatures |
| Session tokens predictable | High | Live scan IDs | Use cryptographic IDs |
| No audit logging | High | All actions | Add audit trail |
| Credentials in memory | High | live_scan.py | Encrypt at rest |
| No input sanitization | Medium | Report generation | Escape HTML |

---

## Part 3: Gap Analysis

### 3.1 Feature Gaps

```
┌─────────────────────────────────────────────────────────────┐
│                    FEATURE GAP MATRIX                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  MUST HAVE (P0)          │  SHOULD HAVE (P1)               │
│  ─────────────────────   │  ─────────────────────          │
│  ☐ Scan checkpointing    │  ☐ CI/CD integrations           │
│  ☐ Proper job queue      │  ☐ Webhook notifications        │
│  ☐ Database migration    │  ☐ Comparison reports           │
│  ☐ Multi-tenant support  │  ☐ Team collaboration           │
│  ☐ SSO integration       │  ☐ Custom check plugins         │
│  ☐ Error recovery        │  ☐ API versioning               │
│                          │                                  │
│  NICE TO HAVE (P2)       │  FUTURE (P3)                    │
│  ─────────────────────   │  ─────────────────────          │
│  ☐ Mobile app            │  ☐ On-premise deployment        │
│  ☐ CLI tool              │  ☐ Custom AI models             │
│  ☐ Slack bot             │  ☐ Marketplace                  │
│  ☐ Browser extension     │  ☐ White-label                  │
│                          │                                  │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Technical Gaps

| Layer | Current | Required | Gap |
|-------|---------|----------|-----|
| **Compute** | Single VM | Auto-scaling group | No scaling |
| **Database** | SQLite | PostgreSQL + Redis | No production DB |
| **Queue** | BackgroundTasks | Celery + Redis | No durability |
| **Storage** | Local filesystem | Cloud Storage | No persistence |
| **CDN** | None | CloudFlare/Fastly | No edge caching |
| **Monitoring** | None | Prometheus + Grafana | Blind operations |
| **Logging** | Print | ELK/Cloud Logging | No searchability |
| **Tracing** | None | Jaeger/Zipkin | No debugging |
| **Secrets** | Environment vars | Vault/Cloud Secrets | Exposed secrets |

### 3.3 Process Gaps

| Area | Current | Required |
|------|---------|----------|
| **CI/CD** | Manual deploy | Automated pipeline |
| **Testing** | None | Unit + Integration + E2E |
| **Code Review** | None | PR-based workflow |
| **Documentation** | Minimal | OpenAPI + Guides |
| **Incident Response** | None | Runbooks + PagerDuty |
| **Change Management** | None | Versioned releases |

---

## Part 4: Recommended Architecture

### 4.1 Target Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        TARGET ARCHITECTURE                          │
└─────────────────────────────────────────────────────────────────────┘

                          ┌─────────────┐
                          │   CloudFlare│
                          │     CDN     │
                          └──────┬──────┘
                                 │
                          ┌──────▼──────┐
                          │   Load      │
                          │  Balancer   │
                          └──────┬──────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         │                       │                       │
   ┌─────▼─────┐          ┌─────▼─────┐          ┌─────▼─────┐
   │  API      │          │  API      │          │  API      │
   │  Server 1 │          │  Server 2 │          │  Server N │
   └─────┬─────┘          └─────┬─────┘          └─────┬─────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
    ┌────────────────────────────┼────────────────────────────┐
    │                            │                            │
┌───▼───┐  ┌───────────┐  ┌─────▼─────┐  ┌───────────┐  ┌────▼────┐
│Redis  │  │PostgreSQL │  │  Celery   │  │  Browser  │  │  Cloud  │
│Cache  │  │  Primary  │  │  Workers  │  │   Pool    │  │ Storage │
└───────┘  └─────┬─────┘  └─────┬─────┘  └───────────┘  └─────────┘
                 │              │
           ┌─────▼─────┐  ┌─────▼─────┐
           │PostgreSQL │  │  Celery   │
           │  Replica  │  │  Worker N │
           └───────────┘  └───────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                         OBSERVABILITY                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐            │
│  │Prometheus│  │  Grafana │  │   ELK    │  │  Sentry  │            │
│  │  Metrics │  │ Dashbd's │  │  Logging │  │  Errors  │            │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘            │
└─────────────────────────────────────────────────────────────────────┘
```

### 4.2 Component Design

#### 4.2.1 API Layer
```python
# New structure
api/
├── v1/
│   ├── __init__.py
│   ├── scans.py          # Scan CRUD operations
│   ├── reports.py        # Report generation
│   ├── webhooks.py       # Webhook management
│   └── auth.py           # Authentication
├── middleware/
│   ├── rate_limit.py     # Redis-based rate limiting
│   ├── auth.py           # JWT/API key validation
│   ├── logging.py        # Structured logging
│   └── tracing.py        # Distributed tracing
└── dependencies.py       # Shared dependencies
```

#### 4.2.2 Worker Layer
```python
# Celery task structure
workers/
├── __init__.py
├── tasks/
│   ├── scan_tasks.py     # Scan execution
│   ├── report_tasks.py   # Report generation
│   └── cleanup_tasks.py  # Data retention
├── agents/               # Moved from app/agents
│   ├── base.py
│   ├── orchestrator.py
│   └── ...
└── celery_app.py         # Celery configuration
```

#### 4.2.3 Data Layer
```python
# SQLAlchemy models
database/
├── __init__.py
├── models/
│   ├── scan.py           # Scan model
│   ├── finding.py        # Finding model
│   ├── user.py           # User model
│   └── tenant.py         # Multi-tenant support
├── repositories/
│   ├── scan_repo.py      # Scan CRUD
│   └── finding_repo.py   # Finding CRUD
└── migrations/           # Alembic migrations
```

### 4.3 Data Flow

```
┌──────────────────────────────────────────────────────────────────┐
│                    SCAN EXECUTION FLOW                           │
└──────────────────────────────────────────────────────────────────┘

1. REQUEST
   Client ─────► API Server ─────► Validate ─────► Create Scan Record
                                                          │
2. QUEUE                                                  ▼
   Scan Record ─────► Redis Queue ─────► Celery Worker picks up
                                                          │
3. EXECUTION                                              ▼
   Worker ─────► Browser Pool ─────► Get Browser Instance
                      │
                      ▼
   ┌─────────────────────────────────────────────────────┐
   │              AGENT PIPELINE                         │
   │  PM ──► Explorer ──► Planner ──► Security ──► Report│
   │   │         │           │           │          │    │
   │   ▼         ▼           ▼           ▼          ▼    │
   │  Redis   Redis      Redis      Redis       Redis    │
   │  (state) (state)    (state)    (state)     (state)  │
   └─────────────────────────────────────────────────────┘
                      │
4. STORAGE            ▼
   Results ─────► PostgreSQL ─────► Cloud Storage (PDF)
                      │
5. NOTIFICATION       ▼
   Complete ─────► Webhook ─────► Slack/Email
                      │
6. RESPONSE           ▼
   Client ◄───── Poll/SSE ◄───── API Server ◄───── Redis PubSub
```

### 4.4 Database Schema

```sql
-- Core tables
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    plan VARCHAR(50) NOT NULL DEFAULT 'starter',
    api_key_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    settings JSONB DEFAULT '{}'
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255),
    role VARCHAR(50) DEFAULT 'member',
    sso_provider VARCHAR(50),
    sso_id VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    user_id UUID REFERENCES users(id),
    url VARCHAR(2048) NOT NULL,
    scan_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    progress INTEGER DEFAULT 0,
    phase VARCHAR(50),
    config JSONB DEFAULT '{}',
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    -- Checkpoint data for resume
    checkpoint JSONB,
    checkpoint_at TIMESTAMP WITH TIME ZONE,

    -- Results summary
    score INTEGER,
    findings_count INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0
);

CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    check_id VARCHAR(100) NOT NULL,
    category VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    evidence TEXT,
    remediation TEXT,
    cwe VARCHAR(50),
    owasp VARCHAR(50),
    cvss_score DECIMAL(3,1),
    false_positive BOOLEAN DEFAULT FALSE,
    resolved BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE scan_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL,
    message TEXT,
    data JSONB,
    screenshot_url VARCHAR(2048),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
    format VARCHAR(20) NOT NULL,  -- pdf, html, json
    storage_url VARCHAR(2048),
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),
    url VARCHAR(2048) NOT NULL,
    events VARCHAR(255)[] NOT NULL,  -- ['scan.completed', 'finding.critical']
    secret_hash VARCHAR(255) NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_scans_tenant ON scans(tenant_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created ON scans(created_at DESC);
CREATE INDEX idx_findings_scan ON findings(scan_id);
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_events_scan ON scan_events(scan_id);
CREATE INDEX idx_events_created ON scan_events(created_at);
```

---

## Part 5: Implementation Roadmap

### 5.1 Phase 1: Foundation (Week 1-2)

| Task | Priority | Effort | Owner |
|------|----------|--------|-------|
| Set up PostgreSQL | P0 | 2 days | Backend |
| Migrate to SQLAlchemy | P0 | 3 days | Backend |
| Set up Redis | P0 | 1 day | DevOps |
| Implement Celery | P0 | 3 days | Backend |
| Add structured logging | P0 | 2 days | Backend |
| Set up error tracking (Sentry) | P0 | 1 day | DevOps |

### 5.2 Phase 2: Reliability (Week 3-4)

| Task | Priority | Effort | Owner |
|------|----------|--------|-------|
| Implement checkpointing | P0 | 3 days | Backend |
| Add scan resume capability | P0 | 2 days | Backend |
| Browser pool implementation | P1 | 3 days | Backend |
| Distributed rate limiting | P1 | 2 days | Backend |
| Health check improvements | P1 | 1 day | Backend |
| Retry logic for agents | P1 | 2 days | Backend |

### 5.3 Phase 3: Features (Week 5-6)

| Task | Priority | Effort | Owner |
|------|----------|--------|-------|
| Webhook system | P1 | 3 days | Backend |
| CI/CD integrations | P1 | 5 days | Backend |
| Comparison reports | P1 | 3 days | Backend |
| API versioning (v1) | P1 | 2 days | Backend |
| Enhanced dashboard | P1 | 5 days | Frontend |

### 5.4 Phase 4: Enterprise (Week 7-8)

| Task | Priority | Effort | Owner |
|------|----------|--------|-------|
| Multi-tenant support | P0 | 5 days | Backend |
| SSO integration | P0 | 3 days | Backend |
| Team management | P1 | 3 days | Backend |
| Audit logging | P1 | 2 days | Backend |
| Role-based access | P1 | 2 days | Backend |

### 5.5 Phase 5: Scale (Week 9-10)

| Task | Priority | Effort | Owner |
|------|----------|--------|-------|
| Kubernetes deployment | P1 | 5 days | DevOps |
| Auto-scaling policies | P1 | 2 days | DevOps |
| CDN integration | P2 | 2 days | DevOps |
| Multi-region support | P2 | 3 days | DevOps |
| Disaster recovery | P1 | 3 days | DevOps |

---

## Part 6: Success Metrics

### 6.1 Technical KPIs

| Metric | Current | Target | Timeline |
|--------|---------|--------|----------|
| API Response Time (p99) | ~2s | <200ms | 4 weeks |
| Scan Success Rate | ~80% | >99% | 4 weeks |
| System Uptime | Unknown | 99.9% | 6 weeks |
| Mean Time to Recovery | N/A | <5 min | 6 weeks |
| Concurrent Scans | ~5 | 100+ | 8 weeks |

### 6.2 Product KPIs

| Metric | Current | Target | Timeline |
|--------|---------|--------|----------|
| Scan Completion Rate | ~70% | >95% | 4 weeks |
| User Activation | Unknown | >80% | 6 weeks |
| Feature Adoption | Unknown | >60% | 8 weeks |
| NPS Score | Unknown | >50 | 12 weeks |
| Churn Rate | Unknown | <5% | 12 weeks |

---

## Part 7: Risk Assessment

### 7.1 Technical Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Data loss on migration | Medium | High | Backup + staged rollout |
| Performance regression | Medium | Medium | Load testing + rollback plan |
| Integration failures | Low | Medium | Comprehensive testing |
| Security vulnerabilities | Medium | High | Security audit + pen testing |

### 7.2 Business Risks

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Development delays | Medium | Medium | Buffer time in schedule |
| Resource constraints | Medium | High | Prioritize P0 items |
| Customer impact during migration | Low | High | Blue-green deployment |

---

## Appendix A: Current vs Target Comparison

| Aspect | Current | Target |
|--------|---------|--------|
| **Architecture** | Monolith | Microservices-ready |
| **Database** | SQLite + In-memory | PostgreSQL + Redis |
| **Job Queue** | Background tasks | Celery + Redis |
| **Caching** | None | Redis with TTL |
| **Rate Limiting** | In-memory | Redis distributed |
| **Logging** | Print statements | Structured JSON (ELK) |
| **Monitoring** | Health endpoint | Prometheus + Grafana |
| **Error Tracking** | None | Sentry |
| **Authentication** | Optional API key | JWT + API keys + SSO |
| **Multi-tenancy** | None | Full isolation |
| **Testing** | None | Unit + Integration + E2E |
| **CI/CD** | Manual | GitHub Actions |
| **Deployment** | Single VM | Kubernetes auto-scale |

---

## Appendix B: Technology Stack Decisions

| Layer | Current | Recommended | Reason |
|-------|---------|-------------|--------|
| **Runtime** | Python 3.10 | Python 3.11+ | Performance improvements |
| **Framework** | FastAPI | FastAPI | Keep - excellent async support |
| **ORM** | Raw SQL | SQLAlchemy 2.0 | Type safety, migrations |
| **Database** | SQLite | PostgreSQL 15 | ACID, JSON support, scale |
| **Cache** | None | Redis 7 | Speed, pub/sub, queues |
| **Queue** | BackgroundTasks | Celery 5 | Durability, monitoring |
| **Browser** | Playwright | Playwright | Keep - best automation |
| **Container** | Docker | Docker | Keep - standard |
| **Orchestration** | None | Kubernetes | Auto-scaling, resilience |
| **CDN** | None | CloudFlare | Edge caching, DDoS protection |
| **Secrets** | .env | GCP Secret Manager | Secure, audited |
| **Monitoring** | None | Prometheus + Grafana | Industry standard |
| **Logging** | Print | ELK Stack | Searchable, alertable |
| **Errors** | None | Sentry | Automatic grouping |

---

## Appendix C: Implementation Status

**Updated:** 2026-02-16

### Implemented Components

| Component | Status | Location | Description |
|-----------|--------|----------|-------------|
| Core Config | Done | `app/core/config.py` | Pydantic settings with validation |
| Structured Logging | Done | `app/core/logging.py` | JSON logging with context vars |
| Exception Hierarchy | Done | `app/core/exceptions.py` | Error codes, recoverable flags |
| Database Base | Done | `app/db/base.py` | Async SQLAlchemy engine |
| ORM Models | Done | `app/db/models.py` | Full schema with indexes |
| Repositories | Done | `app/db/repositories.py` | Data access layer |
| Celery Config | Done | `app/queue/celery_app.py` | Task routing, rate limits |
| Async Tasks | Done | `app/queue/tasks.py` | Scan, report, webhook tasks |
| Checkpointing | Done | `app/scanner/checkpoint.py` | State serialization |
| Orchestrator | Done | `app/scanner/orchestrator.py` | Scan coordination with resume |

### New Module Structure

```
app/
├── core/
│   ├── __init__.py      # Exports
│   ├── config.py        # Settings management
│   ├── logging.py       # Structured logging
│   └── exceptions.py    # Custom exceptions
├── db/
│   ├── __init__.py      # Exports
│   ├── base.py          # Async engine
│   ├── models.py        # ORM models
│   └── repositories.py  # Data access
├── queue/
│   ├── __init__.py      # Exports
│   ├── celery_app.py    # Celery config
│   └── tasks.py         # Async tasks
└── scanner/
    ├── __init__.py      # Exports
    ├── checkpoint.py    # State management
    └── orchestrator.py  # Scan coordination
```

### Dependencies Added

```
# Database
sqlalchemy[asyncio]==2.0.25
asyncpg==0.29.0
aiosqlite==0.19.0

# Job Queue
celery[redis]==5.3.4
redis==5.0.1
kombu==5.3.4

# Settings
pydantic-settings==2.1.0

# Observability
sentry-sdk[fastapi]==1.39.1
```

### Remaining Work

| Task | Priority | Effort |
|------|----------|--------|
| Integrate new modules with main.py | P0 | Low |
| Add Alembic migrations | P0 | Medium |
| Deploy Redis and PostgreSQL | P0 | Low |
| Start Celery workers | P0 | Low |
| Add API versioning (v1 router) | P1 | Medium |
| Implement SSO (SAML/OIDC) | P1 | High |
| Add Prometheus metrics | P2 | Medium |

---

**Document Status:** Implementation In Progress
**Next Steps:** Integrate modules with main application
**Review Date:** Weekly during implementation
