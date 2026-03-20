"""
Port Scanner Module

Performs async TCP port scanning against a target host.
Uses asyncio streams for non-blocking connection attempts.

AUTHORISATION NOTICE: Port scanning without explicit written permission
is illegal in many jurisdictions.  Only scan systems you own or are
explicitly authorised to test.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any, Dict, List, Optional, Tuple

from modules.base_module import ModuleResult, ModuleStatus, SecurityModule

logger = logging.getLogger(__name__)

# Common ports to check when no port list is specified
_DEFAULT_PORTS: List[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 631, 993, 995, 1080, 1433, 1521, 2049, 2181, 3000,
    3306, 3389, 4444, 5000, 5432, 5900, 6379, 6443, 7001, 8000,
    8080, 8443, 8888, 9000, 9200, 9300, 9443, 10250, 27017, 27018,
]

# Rough service-name hints for common ports
_PORT_HINTS: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}


class PortScanner(SecurityModule):
    """
    Async TCP port scanner.

    Attempts a TCP connect() on each specified port and records open ports.
    Optionally grabs a service banner on successful connection.
    """

    name = "port_scanner"
    category = "network"
    description = (
        "Async TCP port scanner that identifies open ports on a target host "
        "and attempts lightweight banner grabbing."
    )
    version = "1.2.0"
    requires = ["subdomain_discovery", "dns_enumeration"]

    def __init__(
        self,
        ports: Optional[List[int]] = None,
        concurrency: int = 200,
        timeout: float = 2.0,
        grab_banner: bool = True,
    ) -> None:
        self._ports = ports or _DEFAULT_PORTS
        self._concurrency = concurrency
        self._timeout = timeout
        self._grab_banner = grab_banner

    async def validate_target(self, target: str) -> bool:
        """Accept hostnames and IPv4/IPv6 addresses."""
        return bool(target and target.strip())

    async def run(self, target: str, **kwargs: Any) -> ModuleResult:
        """
        Scan *target* for open TCP ports.

        Keyword Args:
            ports       (List[int]): Ports to scan.  Defaults to _DEFAULT_PORTS.
            concurrency (int):       Max simultaneous port probes.
            timeout     (float):     Per-port connection timeout seconds.
            grab_banner (bool):      Attempt to read a banner from open ports.
        """
        ports: List[int] = kwargs.get("ports", self._ports)
        concurrency: int = int(kwargs.get("concurrency", self._concurrency))
        timeout: float = float(kwargs.get("timeout", self._timeout))
        grab_banner: bool = bool(kwargs.get("grab_banner", self._grab_banner))

        logger.info(
            "[%s] Scanning %d ports on '%s' (concurrency=%d).",
            self.name, len(ports), target, concurrency,
        )

        semaphore = asyncio.Semaphore(concurrency)
        tasks = [
            self._probe_port(target, port, semaphore, timeout, grab_banner)
            for port in ports
        ]
        probe_results = await asyncio.gather(*tasks)

        open_ports = [r for r in probe_results if r is not None]

        logger.info(
            "[%s] Found %d open ports on '%s'.", self.name, len(open_ports), target
        )

        # Format as a single asset with embedded services
        asset = {
            "value": target,
            "type": "ip",
            "ip_address": None,  # resolved upstream
            "hostname": target,
            "is_alive": len(open_ports) > 0,
            "metadata": {"scan_type": "tcp_connect"},
            "services": open_ports,
        }

        return self._make_result(
            target=target,
            status=ModuleStatus.SUCCESS,
            data={
                "assets": [asset],
                "open_ports": [p["port"] for p in open_ports],
                "total_open": len(open_ports),
                "total_scanned": len(ports),
            },
            metadata={"ports_checked": len(ports)},
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _probe_port(
        self,
        host: str,
        port: int,
        semaphore: asyncio.Semaphore,
        timeout: float,
        grab_banner: bool,
    ) -> Optional[Dict[str, Any]]:
        """Attempt a TCP connect to host:port.  Returns a service dict or None."""
        async with semaphore:
            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None

            banner: Optional[str] = None
            if grab_banner:
                try:
                    # Send a minimal probe to elicit a banner
                    writer.write(b"\r\n")
                    await asyncio.wait_for(writer.drain(), timeout=1.0)
                    raw = await asyncio.wait_for(reader.read(512), timeout=1.5)
                    banner = raw.decode(errors="replace").strip()[:256]
                except Exception:
                    pass

            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

            return {
                "port": port,
                "protocol": "tcp",
                "is_open": True,
                "service_name": _PORT_HINTS.get(port),
                "banner": banner,
                "product": None,
                "version": None,
            }
