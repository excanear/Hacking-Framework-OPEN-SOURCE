"""
DNS Enumeration Module

Enumerates DNS resource records (A, AAAA, MX, NS, TXT, CNAME, SOA)
for a target domain to map its DNS infrastructure.

AUTHORISATION NOTICE: Only run against targets you own or are explicitly
authorised to test.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List

import dns.resolver
import dns.exception

from modules.base_module import ModuleResult, ModuleStatus, SecurityModule

logger = logging.getLogger(__name__)

# Record types to query
_RECORD_TYPES: List[str] = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


class DnsEnumeration(SecurityModule):
    """
    Comprehensive DNS record enumeration for a target domain.

    Queries all common record types and returns their values in a structured
    format suitable for infrastructure mapping.
    """

    name = "dns_enumeration"
    category = "discovery"
    description = (
        "Queries A, AAAA, MX, NS, TXT, CNAME and SOA DNS records for the "
        "target domain to map its DNS infrastructure."
    )
    version = "1.0.0"

    def __init__(self, timeout: float = 5.0) -> None:
        self._timeout = timeout

    async def validate_target(self, target: str) -> bool:
        if not target or "." not in target:
            return False
        parts = target.split(".")
        return not all(p.isdigit() for p in parts)

    async def run(self, target: str, **kwargs: Any) -> ModuleResult:
        """
        Enumerate DNS records for *target*.

        Returns a ModuleResult whose `data` contains:
            records (dict[str, list[str]]): record type → list of values
            assets  (list): A/AAAA records formatted as asset dicts
        """
        timeout = float(kwargs.get("timeout", self._timeout))
        record_types = kwargs.get("record_types", _RECORD_TYPES)

        logger.info("[%s] Enumerating DNS records for '%s'.", self.name, target)

        loop = asyncio.get_event_loop()
        all_records: Dict[str, List[str]] = {}
        errors: List[str] = []

        for rtype in record_types:
            try:
                values = await asyncio.wait_for(
                    loop.run_in_executor(None, self._query, target, rtype),
                    timeout=timeout,
                )
                if values:
                    all_records[rtype] = values
            except asyncio.TimeoutError:
                errors.append(f"Timeout querying {rtype}")
            except Exception as exc:
                errors.append(f"Error querying {rtype}: {exc}")

        # Build asset list from A and AAAA records
        assets = []
        for ip in all_records.get("A", []) + all_records.get("AAAA", []):
            assets.append({
                "value": target,
                "type": "ip",
                "ip_address": ip,
                "hostname": target,
                "is_alive": True,
                "metadata": {"source": "dns_enumeration"},
                "services": [],
            })

        return self._make_result(
            target=target,
            status=ModuleStatus.SUCCESS,
            data={"records": all_records, "assets": assets},
            errors=errors,
            metadata={"queried_types": record_types},
        )

    @staticmethod
    def _query(domain: str, record_type: str) -> List[str]:
        """Blocking DNS query — executed in a thread pool."""
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 4.0
        try:
            answers = resolver.resolve(domain, record_type)
            return [str(r) for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            return []
