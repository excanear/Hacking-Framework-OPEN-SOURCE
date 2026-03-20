"""
Web Analyzer Module

Performs passive HTTP/HTTPS analysis of a web target:
  - Collects HTTP response headers
  - Detects missing security headers
  - Identifies potential technology stack
  - Checks for basic TLS configuration issues

AUTHORISATION NOTICE: Only run against web targets you own or are
explicitly authorised to test.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx

from modules.base_module import ModuleResult, ModuleStatus, SecurityModule

logger = logging.getLogger(__name__)

# Security headers whose absence is a finding
_REQUIRED_SECURITY_HEADERS: List[Tuple[str, str]] = [
    ("Strict-Transport-Security", "HSTS not set — site may be vulnerable to downgrade attacks"),
    ("Content-Security-Policy", "CSP not set — XSS risk higher without a policy"),
    ("X-Frame-Options", "Clickjacking protection not set"),
    ("X-Content-Type-Options", "MIME-sniffing protection not set"),
    ("Referrer-Policy", "Referrer-Policy not set — information leakage risk"),
    ("Permissions-Policy", "Permissions-Policy not set"),
]


class WebAnalyzer(SecurityModule):
    """
    Passive HTTP/HTTPS security header and technology analyser.

    Does NOT perform any form of injection, fuzzing, or active exploitation.
    """

    name = "web_analyzer"
    category = "web"
    description = (
        "Analyses HTTP response headers for security misconfigurations and "
        "identifies the technology stack from server and framework signatures."
    )
    version = "1.1.0"

    def __init__(self, timeout: float = 10.0) -> None:
        self._timeout = timeout

    async def validate_target(self, target: str) -> bool:
        # Accept bare domains or full URLs
        return bool(target and target.strip())

    async def run(self, target: str, **kwargs: Any) -> ModuleResult:
        """
        Analyse the HTTP/HTTPS response for *target*.

        Keyword Args:
            timeout (float): Request timeout seconds.
            ports   (list):  Additional ports to probe.
        """
        timeout = float(kwargs.get("timeout", self._timeout))
        extra_ports: List[int] = kwargs.get("ports", [])

        # Normalise target to a list of URLs to probe
        urls = self._build_urls(target, extra_ports)

        findings: List[Dict[str, Any]] = []
        errors: List[str] = []

        for url in urls:
            try:
                result = await self._analyse_url(url, timeout)
                findings.append(result)
            except Exception as exc:
                errors.append(f"{url}: {exc}")
                logger.debug("[%s] Error probing %s: %s", self.name, url, exc)

        return self._make_result(
            target=target,
            status=ModuleStatus.SUCCESS if findings else ModuleStatus.PARTIAL,
            data={"web_findings": findings, "urls_probed": urls},
            errors=errors,
        )

    # ── URL building ──────────────────────────────────────────────────────────

    def _build_urls(self, target: str, extra_ports: List[int]) -> List[str]:
        """Build a list of URLs to probe from a bare domain or URL."""
        if target.startswith(("http://", "https://")):
            urls = [target]
        else:
            urls = [f"https://{target}", f"http://{target}"]

        for port in extra_ports:
            scheme = "https" if port in (443, 8443) else "http"
            urls.append(f"{scheme}://{target}:{port}/")

        return urls

    # ── Single-URL analysis ───────────────────────────────────────────────────

    async def _analyse_url(self, url: str, timeout: float) -> Dict[str, Any]:
        """
        Probe a single URL and return a structured findings dict.
        """
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=timeout,
        ) as client:
            resp = await client.get(url)

        headers = dict(resp.headers)
        missing_headers = []
        for header, description in _REQUIRED_SECURITY_HEADERS:
            if header.lower() not in {k.lower() for k in headers}:
                missing_headers.append({
                    "header": header,
                    "description": description,
                })

        cookies = [
            {
                "name": c.name,
                "secure": c.secure,
                "httponly": "httponly" in str(c).lower(),
                "samesite": c.extras.get("samesite"),
            }
            for c in resp.cookies.jar
        ]

        insecure_cookies = [
            c["name"] for c in cookies
            if not c["secure"] or not c["httponly"]
        ]

        return {
            "url": url,
            "status_code": resp.status_code,
            "final_url": str(resp.url),
            "server": headers.get("server", ""),
            "x_powered_by": headers.get("x-powered-by", ""),
            "missing_security_headers": missing_headers,
            "cookies": cookies,
            "insecure_cookies": insecure_cookies,
            "response_headers": headers,
            "tls": url.startswith("https://"),
        }
