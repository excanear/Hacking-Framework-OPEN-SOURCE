"""
Service Fingerprinting Module

Attempts to identify the software name and version running on each open port
by analysing response banners using pattern matching.

AUTHORISATION NOTICE: Only run against systems you own or are authorised to test.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import httpx

from modules.base_module import ModuleResult, ModuleStatus, SecurityModule

logger = logging.getLogger(__name__)


# ─── Banner signature database ────────────────────────────────────────────────
# Each entry: (pattern regex, product name, version group index or None)
# These are generic patterns; a production system would use a richer database.

_BANNER_SIGNATURES: List[Tuple[re.Pattern, str, Optional[int]]] = [
    (re.compile(r"OpenSSH[_\s]([\d.]+)", re.I), "OpenSSH", 1),
    (re.compile(r"Apache[/\s]([\d.]+)", re.I), "Apache HTTP Server", 1),
    (re.compile(r"nginx[/\s]([\d.]+)", re.I), "nginx", 1),
    (re.compile(r"Microsoft-IIS[/\s]([\d.]+)", re.I), "Microsoft IIS", 1),
    (re.compile(r"vsftpd\s+([\d.]+)", re.I), "vsftpd", 1),
    (re.compile(r"ProFTPD\s+([\d.]+)", re.I), "ProFTPD", 1),
    (re.compile(r"Postfix", re.I), "Postfix SMTP", None),
    (re.compile(r"Exim\s+([\d.]+)", re.I), "Exim", 1),
    (re.compile(r"MySQL.*?([\d.]+)", re.I), "MySQL", 1),
    (re.compile(r"PostgreSQL.*?([\d.]+)", re.I), "PostgreSQL", 1),
    (re.compile(r"Redis\s+([\d.]+)", re.I), "Redis", 1),
    (re.compile(r"MongoDB.*?([\d.]+)", re.I), "MongoDB", 1),
    (re.compile(r"Elasticsearch.*?([\d.]+)", re.I), "Elasticsearch", 1),
    (re.compile(r"RabbitMQ\s+([\d.]+)", re.I), "RabbitMQ", 1),
    (re.compile(r"OpenVPN", re.I), "OpenVPN", None),
]


def _match_banner(banner: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (product, version) from a banner string using known signatures."""
    for pattern, product, version_group in _BANNER_SIGNATURES:
        m = pattern.search(banner)
        if m:
            version = m.group(version_group) if version_group else None
            return product, version
    return None, None


class ServiceFingerprint(SecurityModule):
    """
    Service fingerprinting via HTTP header analysis and banner matching.

    For HTTP/HTTPS ports: sends a HEAD request and inspects Server/X-Powered-By.
    For other ports: uses banners captured by the port scanner.
    """

    name = "service_fingerprint"
    category = "network"
    description = (
        "Identifies service name and version on open ports using HTTP header "
        "inspection and banner regex matching."
    )
    version = "1.0.0"
    requires = ["port_scanner"]

    def __init__(self, http_timeout: float = 5.0) -> None:
        self._http_timeout = http_timeout

    async def run(self, target: str, **kwargs: Any) -> ModuleResult:
        """
        Fingerprint services on *target*.

        Keyword Args:
            open_ports (List[Dict]): Pre-scanned service list from port_scanner.
                                     If absent, performs HTTP probes on common ports.
            http_timeout (float):   HTTP request timeout.
        """
        open_ports: List[Dict[str, Any]] = kwargs.get("open_ports", [])
        http_timeout = float(kwargs.get("http_timeout", self._http_timeout))

        http_ports = [80, 443, 8080, 8443, 8000, 8888, 3000]

        if not open_ports:
            # No input from upstream — probe well-known HTTP ports
            open_ports = [
                {"port": p, "protocol": "tcp", "is_open": True, "service_name": None, "banner": None}
                for p in http_ports
            ]

        fingerprinted: List[Dict[str, Any]] = []
        errors: List[str] = []

        for svc in open_ports:
            port = svc.get("port", 0)
            banner = svc.get("banner") or ""
            product, version = _match_banner(banner)

            # For HTTP/S, send a real request to harvest headers
            if port in http_ports:
                scheme = "https" if port in (443, 8443) else "http"
                url = f"{scheme}://{target}:{port}/"
                try:
                    http_product, http_version, extra = await self._probe_http(
                        url, http_timeout
                    )
                    if http_product:
                        product = http_product
                        version = http_version
                    svc = {**svc, **extra}
                except Exception as exc:
                    errors.append(f"HTTP probe {url}: {exc}")

            fingerprinted.append({
                **svc,
                "product": product,
                "version": version,
            })

        assets = [{
            "value": target,
            "type": "ip",
            "ip_address": None,
            "hostname": target,
            "is_alive": True,
            "metadata": {},
            "services": fingerprinted,
        }]

        return self._make_result(
            target=target,
            status=ModuleStatus.SUCCESS,
            data={"assets": assets, "fingerprinted_services": fingerprinted},
            errors=errors,
        )

    # ── HTTP probing ──────────────────────────────────────────────────────────

    async def _probe_http(
        self, url: str, timeout: float
    ) -> Tuple[Optional[str], Optional[str], Dict[str, Any]]:
        """
        Send a HEAD request and extract product/version from response headers.

        Returns (product, version, extra_svc_fields).
        """
        extra: Dict[str, Any] = {}
        try:
            async with httpx.AsyncClient(
                verify=False,          # self-signed certs are common in internal infra
                follow_redirects=True,
                timeout=timeout,
            ) as client:
                resp = await client.head(url)
        except httpx.RequestError as exc:
            raise RuntimeError(f"HTTP request failed: {exc}") from exc

        server = resp.headers.get("server", "")
        powered = resp.headers.get("x-powered-by", "")
        extra["banner"] = f"HTTP/{resp.http_version} {resp.status_code} | Server: {server}"
        extra["metadata"] = {
            "http_status": resp.status_code,
            "server_header": server,
            "x_powered_by": powered,
            "headers": dict(resp.headers),
        }

        product, version = _match_banner(server) if server else (None, None)
        if not product and powered:
            product, version = _match_banner(powered)
        return product, version, extra
