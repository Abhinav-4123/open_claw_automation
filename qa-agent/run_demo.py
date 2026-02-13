#!/usr/bin/env python3
"""
TestGuard AI - Demo Runner
Run this script to start the TestGuard AI server locally for demo purposes.

Usage:
    python run_demo.py

Then open:
    - Landing page: http://localhost:8000/
    - Dashboard: http://localhost:8000/dashboard
    - API Docs: http://localhost:8000/docs
"""
import os
import sys
import subprocess
import webbrowser
import time
from pathlib import Path

# Colors for terminal output
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RED = "\033[91m"
RESET = "\033[0m"
BOLD = "\033[1m"

def print_banner():
    banner = f"""
{GREEN}{BOLD}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ████████╗███████╗███████╗████████╗ ██████╗ ██╗   ██╗       ║
║   ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ██║   ██║       ║
║      ██║   █████╗  ███████╗   ██║   ██║  ███╗██║   ██║       ║
║      ██║   ██╔══╝  ╚════██║   ██║   ██║   ██║██║   ██║       ║
║      ██║   ███████╗███████║   ██║   ╚██████╔╝╚██████╔╝       ║
║      ╚═╝   ╚══════╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝        ║
║                                                               ║
║              AI-Powered QA Testing Platform                   ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{RESET}"""
    print(banner)

def check_dependencies():
    """Check if required dependencies are installed"""
    print(f"{BLUE}[*] Checking dependencies...{RESET}")

    required = ["fastapi", "uvicorn", "playwright", "pydantic", "httpx"]
    missing = []

    for package in required:
        try:
            __import__(package.replace("-", "_"))
        except ImportError:
            missing.append(package)

    if missing:
        print(f"{YELLOW}[!] Missing packages: {', '.join(missing)}{RESET}")
        print(f"{BLUE}[*] Installing dependencies...{RESET}")
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], check=True)

    # Check Playwright browsers
    print(f"{BLUE}[*] Checking Playwright browsers...{RESET}")
    try:
        subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], check=True, capture_output=True)
    except:
        print(f"{YELLOW}[!] Run 'playwright install chromium' to install browser{RESET}")

    print(f"{GREEN}[+] Dependencies OK{RESET}")

def check_env():
    """Check environment variables"""
    print(f"{BLUE}[*] Checking environment...{RESET}")

    # Set default API key for demo if not set
    if not os.environ.get("GEMINI_API_KEY"):
        env_file = Path(__file__).parent / ".env"
        if env_file.exists():
            with open(env_file) as f:
                for line in f:
                    if line.strip() and not line.startswith("#"):
                        key, _, value = line.strip().partition("=")
                        os.environ[key] = value
                        print(f"  Loaded: {key}")

    if os.environ.get("GEMINI_API_KEY"):
        print(f"{GREEN}[+] API key found{RESET}")
    else:
        print(f"{YELLOW}[!] No GEMINI_API_KEY set - some features may not work{RESET}")
        print(f"    Set it with: export GEMINI_API_KEY=your_key")

def run_server():
    """Run the FastAPI server"""
    print(f"\n{GREEN}[+] Starting TestGuard AI server...{RESET}")
    print(f"""
{BOLD}Endpoints:{RESET}
    {BLUE}Landing Page:{RESET}  http://localhost:8000/
    {BLUE}Dashboard:{RESET}     http://localhost:8000/dashboard
    {BLUE}API Docs:{RESET}      http://localhost:8000/docs
    {BLUE}Health Check:{RESET}  http://localhost:8000/health

{BOLD}API Endpoints:{RESET}
    POST /test              - Create new QA test
    GET  /tests             - List all tests
    GET  /test/{{id}}         - Get test status
    GET  /report/{{id}}       - Get test report
    POST /security/scan     - Run security scan
    GET  /security/scans    - List security scans
    GET  /stats             - Get statistics

{YELLOW}Press Ctrl+C to stop the server{RESET}
""")

    # Open browser
    time.sleep(1)
    try:
        webbrowser.open("http://localhost:8000/")
    except:
        pass

    # Run uvicorn
    os.chdir(Path(__file__).parent)
    subprocess.run([
        sys.executable, "-m", "uvicorn",
        "app.main:app",
        "--host", "0.0.0.0",
        "--port", "8000",
        "--reload"
    ])

def main():
    print_banner()

    try:
        check_dependencies()
        check_env()
        run_server()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[*] Shutting down...{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
