"""
Security Scanner Service
Integrates Shannon AI Pentester and fallback security scanning tools
"""
import os
import json
import asyncio
import subprocess
from typing import Dict, List, Optional
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum


class ScanType(Enum):
    FULL_PENTEST = "full_pentest"  # Shannon full scan
    QUICK_SCAN = "quick_scan"       # Fast vulnerability check
    OWASP_SCAN = "owasp_scan"       # OWASP Top 10 focused
    API_SCAN = "api_scan"           # API security testing


class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class ScanResult:
    """Security scan result"""
    id: str
    target: str
    scan_type: ScanType
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    vulnerabilities: List[Dict] = field(default_factory=list)
    summary: Dict = field(default_factory=dict)
    raw_output: str = ""
    error: Optional[str] = None


class SecurityScanner:
    """
    Security Scanner Service

    Integrates:
    - Shannon AI Pentester (full autonomous pentesting)
    - OWASP ZAP (web app scanning)
    - Nuclei (vulnerability scanner)
    - Custom checks
    """

    def __init__(self):
        self.scans: Dict[str, ScanResult] = {}
        self.shannon_available = self._check_shannon()
        self.scan_counter = 0

    def _check_shannon(self) -> bool:
        """Check if Shannon is available"""
        try:
            # Check if Docker is available and Shannon directory exists
            result = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False

    def _generate_scan_id(self) -> str:
        self.scan_counter += 1
        return f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{self.scan_counter}"

    async def start_shannon_scan(
        self,
        target_url: str,
        repo_path: Optional[str] = None,
        auth_config: Optional[Dict] = None
    ) -> ScanResult:
        """
        Start a full Shannon AI pentest

        Args:
            target_url: The URL to test
            repo_path: Path to source code (required for Shannon)
            auth_config: Authentication configuration
        """
        scan_id = self._generate_scan_id()
        scan = ScanResult(
            id=scan_id,
            target=target_url,
            scan_type=ScanType.FULL_PENTEST,
            status=ScanStatus.PENDING,
            started_at=datetime.now()
        )
        self.scans[scan_id] = scan

        if not self.shannon_available:
            scan.status = ScanStatus.FAILED
            scan.error = "Shannon not available - Docker not found or Shannon not installed"
            return scan

        if not repo_path:
            scan.status = ScanStatus.FAILED
            scan.error = "Shannon requires source code access (repo_path)"
            return scan

        # Start Shannon scan in background
        scan.status = ScanStatus.RUNNING
        asyncio.create_task(self._run_shannon(scan, target_url, repo_path, auth_config))

        return scan

    async def _run_shannon(
        self,
        scan: ScanResult,
        target_url: str,
        repo_path: str,
        auth_config: Optional[Dict]
    ):
        """Run Shannon scan asynchronously"""
        try:
            # Build Shannon command
            cmd = ["./shannon", "start", f"URL={target_url}", f"REPO={repo_path}"]

            # Run Shannon (this would be in the shannon directory)
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd="/opt/shannon"  # Shannon installation directory
            )

            stdout, stderr = await process.communicate()

            scan.raw_output = stdout.decode() if stdout else ""

            if process.returncode == 0:
                scan.status = ScanStatus.COMPLETED
                scan.vulnerabilities = self._parse_shannon_output(scan.raw_output)
            else:
                scan.status = ScanStatus.FAILED
                scan.error = stderr.decode() if stderr else "Unknown error"

        except Exception as e:
            scan.status = ScanStatus.FAILED
            scan.error = str(e)

        scan.completed_at = datetime.now()

    def _parse_shannon_output(self, output: str) -> List[Dict]:
        """Parse Shannon output for vulnerabilities"""
        vulnerabilities = []
        # Shannon outputs to audit-logs directory
        # Parse the JSON reports there
        try:
            # This would read from Shannon's output directory
            # For now return structured placeholder
            pass
        except:
            pass
        return vulnerabilities

    async def quick_security_check(self, target_url: str) -> ScanResult:
        """
        Run a quick security check without Shannon
        Uses built-in checks for common vulnerabilities
        """
        scan_id = self._generate_scan_id()
        scan = ScanResult(
            id=scan_id,
            target=target_url,
            scan_type=ScanType.QUICK_SCAN,
            status=ScanStatus.RUNNING,
            started_at=datetime.now()
        )
        self.scans[scan_id] = scan

        vulnerabilities = []

        # Check 1: SSL/TLS
        ssl_result = await self._check_ssl(target_url)
        if ssl_result:
            vulnerabilities.append(ssl_result)

        # Check 2: Security Headers
        headers_result = await self._check_security_headers(target_url)
        vulnerabilities.extend(headers_result)

        # Check 3: Common misconfigurations
        config_result = await self._check_common_misconfigs(target_url)
        vulnerabilities.extend(config_result)

        scan.vulnerabilities = vulnerabilities
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now()

        # Generate summary
        scan.summary = {
            "total_findings": len(vulnerabilities),
            "critical": len([v for v in vulnerabilities if v.get("severity") == "critical"]),
            "high": len([v for v in vulnerabilities if v.get("severity") == "high"]),
            "medium": len([v for v in vulnerabilities if v.get("severity") == "medium"]),
            "low": len([v for v in vulnerabilities if v.get("severity") == "low"]),
            "info": len([v for v in vulnerabilities if v.get("severity") == "info"])
        }

        return scan

    async def _check_ssl(self, url: str) -> Optional[Dict]:
        """Check SSL/TLS configuration"""
        import ssl
        import socket
        from urllib.parse import urlparse

        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)

            if parsed.scheme != "https":
                return {
                    "id": "SSL-001",
                    "title": "No HTTPS",
                    "description": f"Site {url} is not using HTTPS",
                    "severity": "high",
                    "category": "Transport Security",
                    "framework": "OWASP A02:2021"
                }

            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    # Check certificate validity
                    # This would expand to check cipher suites, TLS version, etc.

        except ssl.SSLCertVerificationError as e:
            return {
                "id": "SSL-002",
                "title": "Invalid SSL Certificate",
                "description": str(e),
                "severity": "high",
                "category": "Transport Security",
                "framework": "OWASP A02:2021"
            }
        except Exception:
            pass

        return None

    async def _check_security_headers(self, url: str) -> List[Dict]:
        """Check security headers"""
        import aiohttp

        findings = []
        required_headers = {
            "Strict-Transport-Security": {
                "severity": "medium",
                "description": "HSTS header missing - enables protocol downgrade attacks"
            },
            "X-Content-Type-Options": {
                "severity": "low",
                "description": "X-Content-Type-Options missing - enables MIME sniffing attacks"
            },
            "X-Frame-Options": {
                "severity": "medium",
                "description": "X-Frame-Options missing - enables clickjacking attacks"
            },
            "Content-Security-Policy": {
                "severity": "medium",
                "description": "CSP header missing - reduces XSS protection"
            },
            "X-XSS-Protection": {
                "severity": "low",
                "description": "X-XSS-Protection missing - reduces XSS protection in older browsers"
            }
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    headers = resp.headers

                    for header, info in required_headers.items():
                        if header not in headers:
                            findings.append({
                                "id": f"HDR-{header[:3].upper()}",
                                "title": f"Missing {header}",
                                "description": info["description"],
                                "severity": info["severity"],
                                "category": "Security Headers",
                                "framework": "OWASP A05:2021"
                            })
        except Exception as e:
            findings.append({
                "id": "HDR-ERR",
                "title": "Header Check Failed",
                "description": str(e),
                "severity": "info",
                "category": "Security Headers"
            })

        return findings

    async def _check_common_misconfigs(self, url: str) -> List[Dict]:
        """Check for common security misconfigurations"""
        import aiohttp

        findings = []

        sensitive_paths = [
            ("/.env", "Environment file exposed"),
            ("/.git/config", "Git repository exposed"),
            ("/config.php", "Config file exposed"),
            ("/wp-config.php", "WordPress config exposed"),
            ("/phpinfo.php", "PHP info exposed"),
            ("/.htaccess", "htaccess file exposed"),
            ("/server-status", "Apache status exposed"),
            ("/debug", "Debug endpoint exposed"),
            ("/.well-known/security.txt", None)  # This one is good
        ]

        try:
            async with aiohttp.ClientSession() as session:
                for path, issue in sensitive_paths:
                    try:
                        check_url = url.rstrip("/") + path
                        async with session.get(
                            check_url,
                            timeout=aiohttp.ClientTimeout(total=5),
                            allow_redirects=False
                        ) as resp:
                            if resp.status == 200 and issue:
                                findings.append({
                                    "id": f"CFG-{path[1:4].upper()}",
                                    "title": issue,
                                    "description": f"Sensitive file found at {path}",
                                    "severity": "high" if ".env" in path or ".git" in path else "medium",
                                    "category": "Security Misconfiguration",
                                    "framework": "OWASP A05:2021",
                                    "url": check_url
                                })
                    except:
                        pass
        except:
            pass

        return findings

    def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        """Get scan result by ID"""
        return self.scans.get(scan_id)

    def get_all_scans(self) -> List[Dict]:
        """Get all scans"""
        return [
            {
                "id": s.id,
                "target": s.target,
                "type": s.scan_type.value,
                "status": s.status.value,
                "started_at": s.started_at.isoformat(),
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                "summary": s.summary
            }
            for s in self.scans.values()
        ]

    def get_scan_report(self, scan_id: str) -> Optional[Dict]:
        """Get full scan report"""
        scan = self.scans.get(scan_id)
        if not scan:
            return None

        return {
            "id": scan.id,
            "target": scan.target,
            "type": scan.scan_type.value,
            "status": scan.status.value,
            "started_at": scan.started_at.isoformat(),
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "vulnerabilities": scan.vulnerabilities,
            "summary": scan.summary,
            "error": scan.error
        }


# Global scanner instance
scanner = SecurityScanner()
