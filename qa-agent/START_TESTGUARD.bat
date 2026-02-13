@echo off
title TestGuard AI - Starting...

echo.
echo ============================================================
echo                    TestGuard AI
echo           AI-Powered QA Testing Platform
echo ============================================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python from https://python.org
    pause
    exit /b 1
)

echo [*] Installing dependencies...
pip install -q fastapi uvicorn playwright pydantic httpx google-generativeai python-dotenv aiofiles stripe

echo [*] Installing Playwright browser...
python -m playwright install chromium

echo.
echo ============================================================
echo [+] Starting TestGuard AI Server
echo ============================================================
echo.
echo    Landing Page:  http://localhost:8000/
echo    Dashboard:     http://localhost:8000/dashboard
echo    API Docs:      http://localhost:8000/docs
echo.
echo    Press Ctrl+C to stop the server
echo ============================================================
echo.

REM Open browser
start http://localhost:8000/

REM Start server
cd /d "%~dp0"
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

pause
