#!/usr/bin/env python3
"""
TestGuard AI - Demo Test Runner
Runs automated QA and security tests on public websites to demonstrate the product.

Usage:
    python demo_tests.py

Prerequisites:
    - TestGuard API running at http://localhost:8000
    - Run 'python run_demo.py' first
"""
import asyncio
import httpx
import json
from datetime import datetime
import time

API_BASE = "http://localhost:8000"

# Demo targets - publicly accessible websites
DEMO_TARGETS = [
    {
        "name": "GitHub",
        "url": "https://github.com",
        "objective": "login",
        "description": "Test GitHub login flow"
    },
    {
        "name": "HackerNews",
        "url": "https://news.ycombinator.com",
        "objective": "login",
        "description": "Test HackerNews login page"
    },
    {
        "name": "httpbin (Test API)",
        "url": "https://httpbin.org",
        "objective": "full_flow",
        "description": "Test httpbin.org functionality"
    },
    {
        "name": "Wikipedia",
        "url": "https://en.wikipedia.org",
        "objective": "login",
        "description": "Test Wikipedia login flow"
    },
    {
        "name": "Reddit",
        "url": "https://www.reddit.com",
        "objective": "login",
        "description": "Test Reddit login flow"
    }
]

# Comprehensive security scan targets
SECURITY_TARGETS = [
    {
        "name": "httpbin",
        "url": "https://httpbin.org",
        "frameworks": ["owasp_top_10", "vapt"],
        "description": "API testing endpoint - baseline security"
    },
    {
        "name": "Example.com",
        "url": "https://example.com",
        "frameworks": ["owasp_top_10", "iso_27001"],
        "description": "Simple static site - minimal attack surface"
    },
    {
        "name": "GitHub",
        "url": "https://github.com",
        "frameworks": ["owasp_top_10", "vapt", "soc_2", "iso_27001"],
        "description": "Enterprise SaaS - full compliance scan"
    },
    {
        "name": "Wikipedia",
        "url": "https://en.wikipedia.org",
        "frameworks": ["owasp_top_10", "gdpr"],
        "description": "High-traffic wiki - privacy compliance"
    },
    {
        "name": "JSONPlaceholder",
        "url": "https://jsonplaceholder.typicode.com",
        "frameworks": ["owasp_top_10", "vapt"],
        "description": "REST API testing - API security"
    },
    {
        "name": "Hacker News",
        "url": "https://news.ycombinator.com",
        "frameworks": ["owasp_top_10", "vapt"],
        "description": "Community forum - web security"
    }
]

# Quick demo - just security scans (no LLM required)
QUICK_DEMO_TARGETS = [
    {
        "name": "httpbin",
        "url": "https://httpbin.org",
        "frameworks": ["owasp_top_10"]
    },
    {
        "name": "Example.com",
        "url": "https://example.com",
        "frameworks": ["owasp_top_10"]
    }
]


async def check_api_health():
    """Check if API is running"""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{API_BASE}/health", timeout=5.0)
            if response.status_code == 200:
                return True
        except:
            pass
    return False


async def run_qa_test(target: dict):
    """Run a QA test on a target"""
    print(f"\n{'='*60}")
    print(f"QA TEST: {target['name']}")
    print(f"URL: {target['url']}")
    print(f"Objective: {target['objective']}")
    print(f"{'='*60}")

    async with httpx.AsyncClient(timeout=120.0) as client:
        # Start test
        payload = {
            "url": target["url"],
            "objective": target["objective"]
        }

        print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting test...")

        response = await client.post(f"{API_BASE}/test", json=payload)

        if response.status_code != 200:
            print(f"[ERROR] Failed to start test: {response.text}")
            return None

        test_data = response.json()
        test_id = test_data["test_id"]
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Test started: {test_id}")

        # Poll for completion
        max_wait = 120  # 2 minutes
        start_time = time.time()

        while time.time() - start_time < max_wait:
            await asyncio.sleep(5)

            status_response = await client.get(f"{API_BASE}/test/{test_id}")
            if status_response.status_code == 200:
                status_data = status_response.json()
                status = status_data.get("status")

                print(f"[{datetime.now().strftime('%H:%M:%S')}] Status: {status}")

                if status in ["completed", "failed"]:
                    # Get report
                    try:
                        report_response = await client.get(f"{API_BASE}/report/{test_id}")
                        if report_response.status_code == 200:
                            report = report_response.json().get("report", "")
                            print(f"\n--- REPORT PREVIEW ---")
                            print(report[:1000] + "..." if len(report) > 1000 else report)
                    except:
                        pass

                    return status_data

        print(f"[TIMEOUT] Test did not complete in {max_wait} seconds")
        return None


async def run_security_scan(target: dict):
    """Run a security scan on a target"""
    print(f"\n{'='*60}")
    print(f"SECURITY SCAN: {target['name']}")
    print(f"URL: {target['url']}")
    print(f"Frameworks: {', '.join(target['frameworks'])}")
    print(f"{'='*60}")

    async with httpx.AsyncClient(timeout=120.0) as client:
        # Start scan
        payload = {
            "url": target["url"],
            "frameworks": target["frameworks"]
        }

        print(f"[{datetime.now().strftime('%H:%M:%S')}] Starting security scan...")

        response = await client.post(f"{API_BASE}/security/scan", json=payload)

        if response.status_code != 200:
            print(f"[ERROR] Failed to start scan: {response.text}")
            return None

        scan_data = response.json()
        scan_id = scan_data["scan_id"]
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Scan started: {scan_id}")

        # Poll for completion
        max_wait = 120
        start_time = time.time()

        while time.time() - start_time < max_wait:
            await asyncio.sleep(5)

            status_response = await client.get(f"{API_BASE}/security/scan/{scan_id}")
            if status_response.status_code == 200:
                status_data = status_response.json()
                status = status_data.get("status")

                print(f"[{datetime.now().strftime('%H:%M:%S')}] Status: {status}")

                if status == "completed":
                    print(f"\n--- SECURITY RESULTS ---")
                    print(f"Overall Score: {status_data.get('overall_score', 'N/A')}/100")
                    print(f"Vulnerabilities Found: {status_data.get('vulnerabilities_count', 0)}")

                    if status_data.get("framework_scores"):
                        print("\nFramework Scores:")
                        for framework, score in status_data["framework_scores"].items():
                            print(f"  - {framework}: {score}%")

                    if status_data.get("vulnerabilities"):
                        print("\nVulnerabilities:")
                        for vuln in status_data["vulnerabilities"][:5]:
                            print(f"  [{vuln['severity'].upper()}] {vuln['title']}")

                    return status_data

                elif status == "failed":
                    print(f"[ERROR] Scan failed: {status_data.get('error')}")
                    return status_data

        print(f"[TIMEOUT] Scan did not complete in {max_wait} seconds")
        return None


async def show_stats():
    """Show overall statistics"""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{API_BASE}/stats")
            if response.status_code == 200:
                stats = response.json()
                print(f"\n{'='*60}")
                print("OVERALL STATISTICS")
                print(f"{'='*60}")
                print(f"\nQA Tests:")
                print(f"  Total: {stats['tests']['total']}")
                print(f"  Passed: {stats['tests']['passed']}")
                print(f"  Failed: {stats['tests']['failed']}")
                print(f"  Running: {stats['tests']['running']}")

                print(f"\nSecurity Scans:")
                print(f"  Total: {stats['security']['total_scans']}")
                print(f"  Completed: {stats['security']['completed']}")
                print(f"  Average Score: {stats['security']['average_score']}%")
        except Exception as e:
            print(f"[ERROR] Could not fetch stats: {e}")


async def quick_security_demo():
    """
    Quick demo - runs security scans only (no LLM required).
    Perfect for demonstrating the product without API keys.
    """
    print("""
================================================================
        TestGuard AI - Quick Security Demo
        (No API Key Required)
================================================================
""")

    # Check API
    print("[*] Checking API connection...")
    if not await check_api_health():
        print("[ERROR] API is not running!")
        print("        Please run 'python run_demo.py' first")
        return

    print("[+] API is healthy\n")

    # Run security scans on multiple targets
    print("="*60)
    print("SECURITY FRAMEWORK SCANNING")
    print("="*60)

    security_results = []
    for target in SECURITY_TARGETS[:4]:  # Run 4 scans
        result = await run_security_scan(target)
        if result:
            security_results.append(result)

    # Show overall stats
    await show_stats()

    # Summary
    print(f"\n{'='*60}")
    print("QUICK DEMO COMPLETE")
    print(f"{'='*60}")
    print(f"\nSecurity Scans Run: {len(security_results)}")
    if security_results:
        avg_score = sum(r.get('overall_score', 0) for r in security_results) / len(security_results)
        total_vulns = sum(r.get('vulnerabilities_count', 0) for r in security_results)
        print(f"Average Security Score: {avg_score:.0f}/100")
        print(f"Total Vulnerabilities Found: {total_vulns}")
    print(f"\nView detailed results at: http://localhost:8000/dashboard")


async def full_demo():
    """
    Full demo - runs both QA tests and security scans.
    Requires valid LLM API key for QA testing.
    """
    print("""
================================================================
            TestGuard AI - Full Demo
            (Requires API Key for QA Tests)
================================================================
""")

    # Check API
    print("[*] Checking API connection...")
    if not await check_api_health():
        print("[ERROR] API is not running!")
        print("        Please run 'python run_demo.py' first")
        return

    print("[+] API is healthy\n")

    # Run QA tests
    print("\n" + "="*60)
    print("PART 1: QA TESTING")
    print("="*60)

    qa_results = []
    for target in DEMO_TARGETS[:2]:  # Run 2 tests for demo
        result = await run_qa_test(target)
        if result:
            qa_results.append(result)

    # Run security scans
    print("\n" + "="*60)
    print("PART 2: SECURITY SCANNING")
    print("="*60)

    security_results = []
    for target in SECURITY_TARGETS[:3]:  # Run 3 scans for full demo
        result = await run_security_scan(target)
        if result:
            security_results.append(result)

    # Show overall stats
    await show_stats()

    # Summary
    print(f"\n{'='*60}")
    print("FULL DEMO COMPLETE")
    print(f"{'='*60}")
    print(f"\nQA Tests Run: {len(qa_results)}")
    print(f"Security Scans Run: {len(security_results)}")
    print(f"\nView detailed results at: http://localhost:8000/dashboard")


async def main():
    """Main entry point - runs quick security demo by default"""
    import sys

    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
        if mode == "full":
            await full_demo()
        elif mode == "security":
            await quick_security_demo()
        else:
            print("Usage: python demo_tests.py [full|security]")
            print("  full     - Run both QA tests and security scans (requires API key)")
            print("  security - Run security scans only (no API key required)")
    else:
        # Default to quick security demo
        await quick_security_demo()


if __name__ == "__main__":
    asyncio.run(main())
