"""
NEXUS QA - Security Check Feature Flags
Comprehensive mapping of all 82 security checks to their classification.

Classification:
- DETERMINISTIC: Pure regex/header checks, 100% accurate for what they detect
- HEURISTIC: Rule-based guessing, may have false positives/negatives
- AI_REQUIRED: Uses LLM/VLM, premium feature

Accuracy:
- HIGH: Can definitively detect the issue
- MEDIUM: Strong indicators but may miss some cases
- LOW: Best-effort guess, requires manual verification
"""

from typing import Dict, Any
from ..models.security import CheckType, Accuracy

# Feature flags for all 82 security checks
CHECK_FLAGS: Dict[str, Dict[str, Any]] = {
    # ============== DATA SECURITY (10 checks) ==============
    "DS-001": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "PII Detection - regex patterns for emails, phones, SSN"
    },
    "DS-002": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "SSN Detection - specific format regex"
    },
    "DS-003": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "Credit Card Detection - Luhn validation possible"
    },
    "DS-004": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "Email Harvesting - regex count threshold"
    },
    "DS-005": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "Phone Number Detection - format patterns"
    },
    "DS-006": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.MEDIUM,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "Address Detection - coordinate/address patterns"
    },
    "DS-007": {
        "check_type": CheckType.HEURISTIC,
        "accuracy": Accuracy.LOW,
        "method": "keyword",
        "can_verify": False,
        "requires_ai": False,
        "description": "Health Data (HIPAA) - keyword matching only, not semantic"
    },
    "DS-008": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "header",
        "can_verify": True,
        "requires_ai": False,
        "description": "Encryption at Rest - HTTPS/HSTS header check"
    },
    "DS-009": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "Data Masking - masking pattern detection"
    },
    "DS-010": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.MEDIUM,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "Response Filtering - debug pattern detection"
    },

    # ============== CREDENTIALS (10 checks) ==============
    "CR-001": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "JWT in URL - JWT pattern in query params"
    },
    "CR-002": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "API Keys in Code - known key patterns"
    },
    "CR-003": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "Hardcoded Secrets - password/secret patterns"
    },
    "CR-004": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "Password in GET - form method check"
    },
    "CR-005": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "localStorage Token - storage pattern detection"
    },
    "CR-006": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "cookie",
        "can_verify": True,
        "requires_ai": False,
        "description": "Session Token Security - cookie attribute check"
    },
    "CR-007": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "OAuth Token Exposure - token patterns"
    },
    "CR-008": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "Cloud Provider Keys - AWS/GCP/Azure patterns"
    },
    "CR-009": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "Database Connection String - connection string patterns"
    },
    "CR-010": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "Private Key Exposure - PEM header detection"
    },

    # ============== RATE LIMITING (10 checks) ==============
    "RL-001": {
        "check_type": CheckType.HEURISTIC,
        "accuracy": Accuracy.LOW,
        "method": "keyword",
        "can_verify": False,
        "requires_ai": False,
        "description": "Login Brute Force - keyword presence only, NOT tested"
    },
    "RL-002": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "header",
        "can_verify": True,
        "requires_ai": False,
        "description": "API Rate Limiting Headers - header presence check"
    },
    "RL-003": {
        "check_type": CheckType.HEURISTIC,
        "accuracy": Accuracy.LOW,
        "method": "keyword",
        "can_verify": False,
        "requires_ai": False,
        "description": "Registration Spam - CAPTCHA keyword only"
    },
    "RL-004": {
        "check_type": CheckType.HEURISTIC,
        "accuracy": Accuracy.LOW,
        "method": "form_detect",
        "can_verify": False,
        "requires_ai": False,
        "description": "Password Reset Flood - form detection, NOT tested"
    },
    "RL-005": {
        "check_type": CheckType.HEURISTIC,
        "accuracy": Accuracy.LOW,
        "method": "form_detect",
        "can_verify": False,
        "requires_ai": False,
        "description": "Search Rate Limiting - form detection, NOT tested"
    },
    "RL-006": {
        "check_type": CheckType.HEURISTIC,
        "accuracy": Accuracy.LOW,
        "method": "input_detect",
        "can_verify": False,
        "requires_ai": False,
        "description": "Upload Rate Limiting - input detection, NOT tested"
    },
    "RL-007": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.MEDIUM,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "Account Enumeration - error message patterns"
    },
    "RL-008": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "keyword",
        "can_verify": True,
        "requires_ai": False,
        "description": "CAPTCHA Implementation - CAPTCHA keyword search"
    },
    "RL-009": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "header",
        "can_verify": True,
        "requires_ai": False,
        "description": "IP-Based Blocking - WAF header presence"
    },
    "RL-010": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "header",
        "can_verify": True,
        "requires_ai": False,
        "description": "DDoS Protection - CDN header patterns"
    },

    # ============== CACHE & STORAGE (10 checks) ==============
    "CS-001": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "header",
        "can_verify": True,
        "requires_ai": False,
        "description": "Browser Cache Control - header value check"
    },
    "CS-002": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "header",
        "can_verify": True,
        "requires_ai": False,
        "description": "CDN Cache Config - CDN headers + cache status"
    },
    "CS-003": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "localStorage Sensitive Data - storage patterns"
    },
    "CS-004": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "sessionStorage Analysis - storage patterns"
    },
    "CS-005": {
        "check_type": CheckType.HEURISTIC,
        "accuracy": Accuracy.LOW,
        "method": "keyword",
        "can_verify": False,
        "requires_ai": False,
        "description": "IndexedDB Security - presence + encryption keyword"
    },
    "CS-006": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "Service Worker Cache - SW registration detection"
    },
    "CS-007": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "header",
        "can_verify": True,
        "requires_ai": False,
        "description": "Sensitive Page Cache - header + keyword check"
    },
    "CS-008": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "header",
        "can_verify": True,
        "requires_ai": False,
        "description": "ETag Information Leakage - inode-style ETag regex"
    },
    "CS-009": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "header",
        "can_verify": True,
        "requires_ai": False,
        "description": "Pragma No-Cache - header presence"
    },
    "CS-010": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "header",
        "can_verify": True,
        "requires_ai": False,
        "description": "Vary Header Config - header + auth keyword"
    },

    # ============== AUTHENTICATION (12 checks) ==============
    "AU-001": {
        "check_type": CheckType.HEURISTIC,
        "accuracy": Accuracy.LOW,
        "method": "keyword",
        "can_verify": False,
        "requires_ai": False,
        "description": "Session Fixation - keyword only, CANNOT verify regeneration"
    },
    "AU-002": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "cookie",
        "can_verify": True,
        "requires_ai": False,
        "description": "Session Hijacking Prevention - HTTPS + cookie checks"
    },
    "AU-003": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "cookie",
        "can_verify": True,
        "requires_ai": False,
        "description": "Cookie Security Flags - cookie attribute parsing"
    },
    "AU-004": {
        "check_type": CheckType.HEURISTIC,
        "accuracy": Accuracy.LOW,
        "method": "keyword",
        "can_verify": False,
        "requires_ai": False,
        "description": "RBAC Implementation - keyword presence only"
    },
    "AU-005": {
        "check_type": CheckType.HEURISTIC,
        "accuracy": Accuracy.LOW,
        "method": "regex",
        "can_verify": False,
        "requires_ai": False,
        "description": "Privilege Escalation - isAdmin pattern, client-side only"
    },
    "AU-006": {
        "check_type": CheckType.HEURISTIC,
        "accuracy": Accuracy.LOW,
        "method": "regex",
        "can_verify": False,
        "requires_ai": False,
        "description": "IDOR Indicators - URL pattern, CANNOT test authorization"
    },
    "AU-007": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "decode",
        "can_verify": True,
        "requires_ai": False,
        "description": "JWT Algorithm - base64 decode + algorithm check"
    },
    "AU-008": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.MEDIUM,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "Token Expiration - expiry value regex"
    },
    "AU-009": {
        "check_type": CheckType.HEURISTIC,
        "accuracy": Accuracy.LOW,
        "method": "keyword",
        "can_verify": False,
        "requires_ai": False,
        "description": "Password Policy - keyword presence only"
    },
    "AU-010": {
        "check_type": CheckType.HEURISTIC,
        "accuracy": Accuracy.LOW,
        "method": "keyword",
        "can_verify": False,
        "requires_ai": False,
        "description": "MFA Implementation - keyword search only"
    },
    "AU-011": {
        "check_type": CheckType.HEURISTIC,
        "accuracy": Accuracy.LOW,
        "method": "keyword",
        "can_verify": False,
        "requires_ai": False,
        "description": "Account Lockout - keyword presence only"
    },
    "AU-012": {
        "check_type": CheckType.HEURISTIC,
        "accuracy": Accuracy.LOW,
        "method": "keyword",
        "can_verify": False,
        "requires_ai": False,
        "description": "Logout Invalidation - CANNOT verify server-side"
    },

    # ============== INJECTION (12 checks) ==============
    "IN-001": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.MEDIUM,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "Reflected XSS - URL param reflection + dangerous context"
    },
    "IN-002": {
        "check_type": CheckType.HEURISTIC,
        "accuracy": Accuracy.LOW,
        "method": "keyword",
        "can_verify": False,
        "requires_ai": False,
        "description": "Stored XSS - UGC detection + sanitization keyword"
    },
    "IN-003": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "DOM-based XSS - dangerous sinks/sources regex"
    },
    "IN-004": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "SQL Injection Indicators - error message regex"
    },
    "IN-005": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "NoSQL Injection - MongoDB operator regex"
    },
    "IN-006": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.MEDIUM,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "SSTI - template syntax + URL param check"
    },
    "IN-007": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.MEDIUM,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "Command Injection - command chars + error messages"
    },
    "IN-008": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.MEDIUM,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "LDAP Injection - regex + error messages"
    },
    "IN-009": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "XML/XXE - ENTITY/SYSTEM patterns"
    },
    "IN-010": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "Header Injection - URL-encoded CRLF check"
    },
    "IN-011": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "Path Traversal - ../ patterns"
    },
    "IN-012": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "regex",
        "can_verify": True,
        "requires_ai": False,
        "description": "CRLF Injection - CRLF pattern check"
    },

    # ============== INFRASTRUCTURE (10 checks) ==============
    "IF-001": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.MEDIUM,
        "method": "protocol",
        "can_verify": False,
        "requires_ai": False,
        "description": "TLS Config - HTTPS check only, not TLS version"
    },
    "IF-002": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "header",
        "can_verify": True,
        "requires_ai": False,
        "description": "HSTS - header + max-age parsing"
    },
    "IF-003": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "header",
        "can_verify": True,
        "requires_ai": False,
        "description": "CSP - header parsing + directive analysis"
    },
    "IF-004": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "header",
        "can_verify": True,
        "requires_ai": False,
        "description": "X-Content-Type-Options - header presence + value"
    },
    "IF-005": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "header",
        "can_verify": True,
        "requires_ai": False,
        "description": "X-Frame-Options - header + CSP directive"
    },
    "IF-006": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "header",
        "can_verify": True,
        "requires_ai": False,
        "description": "CORS Config - header value analysis"
    },
    "IF-007": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "header",
        "can_verify": True,
        "requires_ai": False,
        "description": "Server Disclosure - header + version regex"
    },
    "IF-008": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "header",
        "can_verify": True,
        "requires_ai": False,
        "description": "Referrer Policy - header + meta tag"
    },
    "IF-009": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "header",
        "can_verify": True,
        "requires_ai": False,
        "description": "Permissions Policy - header presence + feature"
    },
    "IF-010": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.MEDIUM,
        "method": "protocol",
        "can_verify": False,
        "requires_ai": False,
        "description": "Certificate Validity - HTTPS success only"
    },

    # ============== BUSINESS LOGIC (8 checks) ==============
    "BL-001": {
        "check_type": CheckType.HEURISTIC,
        "accuracy": Accuracy.LOW,
        "method": "regex",
        "can_verify": False,
        "requires_ai": False,
        "description": "Workflow Bypass - step/stage patterns, WARNS only"
    },
    "BL-002": {
        "check_type": CheckType.HEURISTIC,
        "accuracy": Accuracy.LOW,
        "method": "input_detect",
        "can_verify": False,
        "requires_ai": False,
        "description": "Price Manipulation - hidden field, CANNOT verify server"
    },
    "BL-003": {
        "check_type": CheckType.HEURISTIC,
        "accuracy": Accuracy.LOW,
        "method": "keyword",
        "can_verify": False,
        "requires_ai": False,
        "description": "Race Conditions - keyword + AJAX, WARNS only"
    },
    "BL-004": {
        "check_type": CheckType.DETERMINISTIC,
        "accuracy": Accuracy.HIGH,
        "method": "keyword",
        "can_verify": True,
        "requires_ai": False,
        "description": "Anti-Automation - CAPTCHA/CSRF/honeypot keyword"
    },
    "BL-005": {
        "check_type": CheckType.HEURISTIC,
        "accuracy": Accuracy.LOW,
        "method": "input_detect",
        "can_verify": False,
        "requires_ai": False,
        "description": "Mass Assignment - hidden field analysis"
    },
    "BL-006": {
        "check_type": CheckType.HEURISTIC,
        "accuracy": Accuracy.LOW,
        "method": "regex",
        "can_verify": False,
        "requires_ai": False,
        "description": "Functional IDOR - URL pattern, CANNOT test auth"
    },
    "BL-007": {
        "check_type": CheckType.HEURISTIC,
        "accuracy": Accuracy.LOW,
        "method": "keyword",
        "can_verify": False,
        "requires_ai": False,
        "description": "Transaction Integrity - keyword search only"
    },
    "BL-008": {
        "check_type": CheckType.HEURISTIC,
        "accuracy": Accuracy.LOW,
        "method": "regex",
        "can_verify": False,
        "requires_ai": False,
        "description": "Trust Boundary - client validation pattern"
    },
}

# AI-Required Features (Premium)
AI_FEATURES = {
    "test_planning": {
        "requires_ai": True,
        "ai_type": "llm",
        "description": "Generate test plans from objectives"
    },
    "action_decision": {
        "requires_ai": True,
        "ai_type": "llm",
        "description": "Decide next action based on page state"
    },
    "element_selection": {
        "requires_ai": True,
        "ai_type": "llm",
        "description": "Interpret selectors and page context"
    },
    "error_recovery": {
        "requires_ai": True,
        "ai_type": "llm",
        "description": "Determine alternative approaches"
    },
    "result_summary": {
        "requires_ai": True,
        "ai_type": "llm",
        "description": "Generate test summary"
    },
    "screenshot_analysis": {
        "requires_ai": True,
        "ai_type": "vlm",
        "description": "Interpret visual state"
    },
    "journey_understanding": {
        "requires_ai": True,
        "ai_type": "llm",
        "description": "Understand complex user journeys"
    },
}


def get_check_flags(check_id: str) -> Dict[str, Any]:
    """Get feature flags for a specific check."""
    return CHECK_FLAGS.get(check_id, {
        "check_type": CheckType.HEURISTIC,
        "accuracy": Accuracy.LOW,
        "method": "unknown",
        "can_verify": False,
        "requires_ai": False,
        "description": "Unknown check"
    })


def get_summary() -> Dict[str, Any]:
    """Get summary statistics of all checks."""
    deterministic = sum(1 for c in CHECK_FLAGS.values()
                        if c["check_type"] == CheckType.DETERMINISTIC)
    heuristic = sum(1 for c in CHECK_FLAGS.values()
                    if c["check_type"] == CheckType.HEURISTIC)
    ai_required = sum(1 for c in CHECK_FLAGS.values()
                      if c["check_type"] == CheckType.AI_REQUIRED)

    high_accuracy = sum(1 for c in CHECK_FLAGS.values()
                        if c["accuracy"] == Accuracy.HIGH)
    medium_accuracy = sum(1 for c in CHECK_FLAGS.values()
                          if c["accuracy"] == Accuracy.MEDIUM)
    low_accuracy = sum(1 for c in CHECK_FLAGS.values()
                       if c["accuracy"] == Accuracy.LOW)

    can_verify = sum(1 for c in CHECK_FLAGS.values() if c["can_verify"])

    return {
        "total_checks": len(CHECK_FLAGS),
        "by_type": {
            "deterministic": deterministic,
            "heuristic": heuristic,
            "ai_required": ai_required
        },
        "by_accuracy": {
            "high": high_accuracy,
            "medium": medium_accuracy,
            "low": low_accuracy
        },
        "can_verify_count": can_verify,
        "ai_features_count": len(AI_FEATURES),
        "percentages": {
            "deterministic": round(deterministic / len(CHECK_FLAGS) * 100, 1),
            "high_accuracy": round(high_accuracy / len(CHECK_FLAGS) * 100, 1),
            "can_verify": round(can_verify / len(CHECK_FLAGS) * 100, 1)
        }
    }
