# NEXUS QA v4.0 - Autonomous Multi-Agent Security Analysis Framework

## Vision
A fully autonomous system that analyzes any web application like a PM + Senior QA + Security Researcher would, producing comprehensive reports in ~1 hour.

---

## Multi-Agent Architecture

```
                                    ┌─────────────────────────────────┐
                                    │      ORCHESTRATOR AGENT         │
                                    │  (Central Coordinator + State)  │
                                    │  - Task distribution            │
                                    │  - Agent health monitoring      │
                                    │  - Failure recovery             │
                                    │  - Progress aggregation         │
                                    └─────────────┬───────────────────┘
                                                  │
                    ┌─────────────────────────────┼─────────────────────────────┐
                    │                             │                             │
                    ▼                             ▼                             ▼
    ┌───────────────────────────┐  ┌───────────────────────────┐  ┌───────────────────────────┐
    │     PM AGENT (Phase 1)    │  │   EXPLORER AGENT (Phase 2)│  │  DEVTOOLS AGENT (Phase 2) │
    │                           │  │                           │  │                           │
    │  VLM: Visual Analysis     │  │  Browser: Playwright      │  │  Browser DevTools API     │
    │  - Screenshot homepage    │  │  - Deep crawl all links   │  │  - Network tab capture    │
    │  - Identify app type      │  │  - Form discovery         │  │  - API endpoint logging   │
    │  - Map core features      │  │  - Click exploration      │  │  - WebSocket monitoring   │
    │  - Business domain        │  │  - State machine build    │  │  - Callback detection     │
    │  - User personas          │  │  - Journey recording      │  │  - Request/Response       │
    │                           │  │                           │  │  - Cookie/Storage         │
    └───────────┬───────────────┘  └───────────┬───────────────┘  └───────────┬───────────────┘
                │                               │                               │
                │    ┌──────────────────────────┴───────────────────────────────┘
                │    │
                ▼    ▼
    ┌───────────────────────────────────────────────────────────────────────────┐
    │                      CONTEXT AGGREGATOR                                    │
    │  Merges: Product Understanding + Journeys + APIs → Unified Context        │
    └───────────────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
    ┌───────────────────────────────────────────────────────────────────────────┐
    │                      PLANNER AGENT (Phase 3)                               │
    │                                                                            │
    │  LLM: Create contextual test plan based on:                               │
    │  - Product type (SaaS, E-commerce, Social, etc.)                          │
    │  - Discovered journeys (auth, payment, profile, etc.)                     │
    │  - API inventory (REST, GraphQL, WebSocket)                               │
    │  - Known attack surfaces per product type                                  │
    │  - Priority ordering (critical paths first)                                │
    └───────────────────────────────────────────────────────────────────────────┘
                                          │
                    ┌─────────────────────┼─────────────────────┐
                    │                     │                     │
                    ▼                     ▼                     ▼
    ┌───────────────────────┐ ┌───────────────────────┐ ┌───────────────────────┐
    │  SECURITY AGENT       │ │  API TESTER AGENT     │ │  UI TESTER AGENT      │
    │  (Phase 4a)           │ │  (Phase 4b)           │ │  (Phase 4c)           │
    │                       │ │                       │ │                       │
    │  82 Security Checks   │ │  API-specific tests:  │ │  UI-based tests:      │
    │  - OWASP Top 10       │ │  - Auth bypass        │ │  - Form validation    │
    │  - Header analysis    │ │  - IDOR testing       │ │  - XSS via inputs     │
    │  - Injection testing  │ │  - Rate limit probing │ │  - CSRF tokens        │
    │  - Auth vulnerabilities│ │  - Parameter fuzzing  │ │  - Clickjacking       │
    │  - Business logic     │ │  - Error disclosure   │ │  - Session handling   │
    └───────────┬───────────┘ └───────────┬───────────┘ └───────────┬───────────┘
                │                         │                         │
                └─────────────────────────┴─────────────────────────┘
                                          │
                                          ▼
    ┌───────────────────────────────────────────────────────────────────────────┐
    │                      REPORT AGENT (Phase 5)                                │
    │                                                                            │
    │  Aggregates all findings → Generates PDF Report:                          │
    │  - Executive Summary (VLM: product screenshots annotated)                  │
    │  - Product Analysis (what it is, who uses it)                              │
    │  - Journey Maps (visual flow diagrams)                                     │
    │  - API Inventory (endpoints, methods, auth)                                │
    │  - Security Findings (severity, evidence, remediation)                     │
    │  - Compliance Status (OWASP, PCI-DSS, GDPR, SOC2)                          │
    │  - Test Evidence (screenshots, curl commands, responses)                   │
    └───────────────────────────────────────────────────────────────────────────┘
```

---

## Agent Communication Protocol

### Message Types

```python
class AgentMessage:
    id: str                    # Unique message ID
    from_agent: str            # Sender agent type
    to_agent: str              # Recipient (or "orchestrator")
    message_type: MessageType  # See below
    payload: dict              # Type-specific data
    timestamp: datetime
    requires_response: bool
    timeout_seconds: int

class MessageType(Enum):
    # Status updates
    HEARTBEAT = "heartbeat"           # I'm alive
    PROGRESS = "progress"             # X% complete
    PHASE_COMPLETE = "phase_complete" # Phase done, results attached

    # Coordination
    REQUEST_DATA = "request_data"     # I need X from agent Y
    DATA_RESPONSE = "data_response"   # Here's the data you requested
    HANDOFF = "handoff"               # Task complete, next agent go

    # Errors
    ERROR = "error"                   # Something went wrong
    BLOCKED = "blocked"               # Can't proceed, need help
    RETRY = "retry"                   # Please retry with new params

    # Human in loop
    CLARIFICATION_NEEDED = "clarification_needed"
    CLARIFICATION_RESPONSE = "clarification_response"
```

### Bidirectional Communication Flow

```
Explorer Agent                    Orchestrator                    DevTools Agent
     │                                │                                │
     │─── PROGRESS(10%)──────────────▶│                                │
     │                                │◀────── PROGRESS(5%)───────────│
     │                                │                                │
     │─── REQUEST_DATA(cookies)──────▶│                                │
     │                                │─── REQUEST_DATA(cookies)──────▶│
     │                                │◀── DATA_RESPONSE(cookies)─────│
     │◀── DATA_RESPONSE(cookies)─────│                                │
     │                                │                                │
     │─── BLOCKED(login required)────▶│                                │
     │                                │ [Orchestrator decides action]  │
     │◀── RETRY(with_credentials)────│                                │
```

---

## Phase Breakdown

### Phase 1: Product Understanding (PM Agent) - ~5 min
1. Navigate to URL
2. Take full-page screenshot
3. VLM Analysis:
   - What type of app is this? (SaaS, E-commerce, Social, Fintech, etc.)
   - What industry/domain?
   - Core value proposition
   - Primary user personas
   - Key features visible
4. Identify main navigation areas
5. Output: `ProductProfile` object

### Phase 2: Deep Exploration (Explorer + DevTools) - ~20 min
**Run in parallel:**

**Explorer Agent:**
1. Crawl all visible links (BFS, max depth 3)
2. Identify all forms (login, signup, search, etc.)
3. Detect interactive elements
4. Build page state machine
5. Record potential user journeys
6. Output: `JourneyMap[]`

**DevTools Agent:**
1. Open CDP (Chrome DevTools Protocol)
2. Monitor Network tab
3. Log all API calls:
   - Endpoint URL
   - Method (GET/POST/etc.)
   - Request headers
   - Request body
   - Response status
   - Response body (truncated)
4. Detect WebSocket connections
5. Identify callback patterns
6. Monitor localStorage/sessionStorage
7. Output: `APIInventory`

### Phase 3: Test Planning (Planner Agent) - ~5 min
1. Receive context from Phase 2
2. LLM generates test plan:
   ```
   Given:
   - Product: E-commerce SaaS
   - Journeys: [signup, login, checkout, admin]
   - APIs: [/api/v1/users, /api/v1/products, /api/v1/orders]

   Generate prioritized test plan:
   1. Critical: Auth bypass on /api/v1/users
   2. Critical: Payment manipulation in checkout
   3. High: IDOR on /api/v1/orders/{id}
   ...
   ```
3. Output: `TestPlan` with ordered `TestCase[]`

### Phase 4: Execution (Security + API + UI Agents) - ~25 min
**Run in parallel with coordination:**

**Security Agent:**
- Run 82 deterministic checks
- Header analysis
- Injection pattern detection
- Output: `SecurityCheckResult[]`

**API Tester Agent:**
- For each discovered API:
  - Test auth requirements
  - Try IDOR patterns
  - Check rate limits
  - Fuzz parameters
  - Analyze error responses
- Output: `APITestResult[]`

**UI Tester Agent:**
- For each journey:
  - Test form validations
  - Check XSS in inputs
  - Verify CSRF protection
  - Test session handling
- Output: `UITestResult[]`

### Phase 5: Report Generation - ~5 min
1. Aggregate all results
2. Generate sections:
   - Executive Summary (VLM: annotated screenshots)
   - Product Analysis
   - Journey Maps (Mermaid diagrams)
   - API Documentation
   - Security Findings (grouped by severity)
   - Compliance Status
   - Evidence Appendix
3. Render PDF
4. Output: `comprehensive_report.pdf`

---

## Failure Recovery

### Agent-Level Recovery
```python
async def run_with_recovery(agent, task, max_retries=3):
    for attempt in range(max_retries):
        try:
            return await agent.execute(task)
        except RecoverableError as e:
            await orchestrator.notify(ERROR, e)
            task = await orchestrator.get_recovery_task(e)
        except FatalError as e:
            # Mark agent as failed, continue without it
            await orchestrator.mark_agent_failed(agent, e)
            return PartialResult(skipped=True, reason=str(e))
```

### Orchestrator Recovery
- If PM Agent fails → Use fallback heuristics for product type
- If Explorer fails → Use DevTools API data only
- If DevTools fails → Use HTML analysis only
- If Security Agent fails → Return partial results
- If Report fails → Return JSON/Markdown instead of PDF

### Communication Timeout Handling
```python
async def send_with_timeout(msg: AgentMessage):
    try:
        return await asyncio.wait_for(
            send_to_agent(msg),
            timeout=msg.timeout_seconds
        )
    except asyncio.TimeoutError:
        # Agent unresponsive
        await orchestrator.handle_timeout(msg.to_agent)
        raise AgentUnresponsive(msg.to_agent)
```

---

## Data Models

### Core Models

```python
@dataclass
class ProductProfile:
    app_type: str              # "e-commerce", "saas", "social", etc.
    industry: str              # "fintech", "healthcare", "retail", etc.
    features: List[str]        # ["user_auth", "payments", "dashboard"]
    user_personas: List[str]   # ["admin", "customer", "guest"]
    tech_stack_hints: List[str] # ["React", "Node.js", "PostgreSQL"]
    screenshots: List[bytes]   # Full page screenshots
    vlm_analysis: str          # Raw VLM output

@dataclass
class UserJourney:
    id: str
    name: str                  # "User Signup Flow"
    steps: List[JourneyStep]
    entry_point: str           # URL
    forms_involved: List[str]
    auth_required: bool
    estimated_criticality: str # "critical", "high", "medium"

@dataclass
class JourneyStep:
    order: int
    action: str                # "navigate", "click", "type", "submit"
    target: str                # Selector or URL
    screenshot: bytes
    page_state: dict           # Captured state

@dataclass
class APIEndpoint:
    url: str
    method: str
    discovered_via: str        # "network_log", "html_analysis"
    request_headers: dict
    request_body_sample: str
    response_status: int
    response_body_sample: str
    auth_type: str             # "bearer", "cookie", "api_key", "none"
    parameters: List[dict]

@dataclass
class SecurityFinding:
    id: str
    check_id: str
    severity: str
    title: str
    description: str
    evidence: str              # Curl command, screenshot, etc.
    remediation: str
    compliance: List[str]      # ["OWASP A01", "CWE-89"]
    verified: bool             # Actually exploited vs pattern match

@dataclass
class ScanSession:
    id: str
    url: str
    started_at: datetime
    status: str                # "running", "completed", "failed"
    phase: str                 # Current phase
    agents: Dict[str, AgentStatus]
    product_profile: ProductProfile
    journeys: List[UserJourney]
    api_inventory: List[APIEndpoint]
    security_findings: List[SecurityFinding]
    report_path: str
```

---

## Implementation Plan

### Week 1: Core Infrastructure
- [ ] Agent base class with lifecycle management
- [ ] Orchestrator with message queue (Redis or in-memory)
- [ ] Agent communication protocol
- [ ] State persistence (SQLite)

### Week 2: PM + Explorer Agents
- [ ] PM Agent with VLM integration
- [ ] Explorer Agent with Playwright crawling
- [ ] DevTools Agent with CDP integration
- [ ] Context aggregator

### Week 3: Planner + Security Agents
- [ ] Planner Agent with LLM integration
- [ ] Refactor 82 checks into Security Agent
- [ ] API Tester Agent
- [ ] UI Tester Agent

### Week 4: Report + Polish
- [ ] PDF generation with ReportLab/WeasyPrint
- [ ] Evidence capture system
- [ ] Failure recovery testing
- [ ] Performance optimization

---

## Technology Stack

| Component | Technology |
|-----------|------------|
| Framework | FastAPI (async) |
| Browser | Playwright (with CDP) |
| LLM | Gemini 2.0 Flash (primary), GPT-4o (fallback) |
| VLM | Gemini 2.0 Flash Vision |
| Message Queue | asyncio.Queue (in-memory) / Redis (prod) |
| Database | SQLite (local) / PostgreSQL (prod) |
| PDF | WeasyPrint + Jinja2 templates |
| Screenshots | Playwright + PIL |

---

## Expected Timeline for Deep Scan

| Phase | Duration | Parallel |
|-------|----------|----------|
| Product Understanding | 3-5 min | No |
| Deep Exploration | 15-20 min | Yes (2 agents) |
| Test Planning | 3-5 min | No |
| Security Testing | 20-30 min | Yes (3 agents) |
| Report Generation | 5-10 min | No |
| **Total** | **45-70 min** | |

---

## Next Steps

1. Create `app/agents/` directory structure
2. Implement `BaseAgent` class
3. Implement `Orchestrator`
4. Build PM Agent first (quickest win)
5. Iterate from there
