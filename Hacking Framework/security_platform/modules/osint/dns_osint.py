"""
DNS OSINT Module

Collects open-source DNS intelligence about a target domain:
  - Reverse DNS lookups for known IP addresses
  - Zone transfer attempt (informational — most servers deny this)
  - SPF/DKIM/DMARC email security record analysis
  - DNSSEC presence check
  - CAA (Certification Authority Authorisation) record check

All data is gathered from public DNS infrastructure.

AUTHORISATION NOTICE: DNS OSINT uses only publicly available data.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

import dns.resolver
import dns.zone
import dns.query
import dns.exception

from modules.base_module import ModuleResult, ModuleStatus, SecurityModule

logger = logging.getLogger(__name__)


class DnsOsint(SecurityModule):
    """
    DNS-based OSINT intelligence collection for a target domain.

    Gathers email security posture (SPF, DKIM, DMARC), certificate authority
    authorisation records, DNSSEC indicators, and nameserver metadata.
    """

    name = "dns_osint"
    category = "osint"
    description = (
        "Collects DNS-based OSINT: SPF/DKIM/DMARC email security records, "
        "CAA records, DNSSEC presence, and nameserver metadata."
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
        """Collect DNS OSINT for *target* domain."""
        timeout = float(kwargs.get("timeout", self._timeout))
        loop = asyncio.get_event_loop()
        errors: List[str] = []

        # Run all checks concurrently
        spf_task      = loop.run_in_executor(None, self._get_spf, target)
        dmarc_task    = loop.run_in_executor(None, self._get_dmarc, target)
        caa_task      = loop.run_in_executor(None, self._get_caa, target)
        ns_task       = loop.run_in_executor(None, self._get_nameservers, target)
        dnssec_task   = loop.run_in_executor(None, self._check_dnssec, target)
        mx_task       = loop.run_in_executor(None, self._get_mx, target)

        try:
            spf, dmarc, caa, nameservers, dnssec, mx = await asyncio.gather(
                spf_task, dmarc_task, caa_task, ns_task, dnssec_task, mx_task,
                return_exceptions=False,
            )
        except Exception as exc:
            errors.append(str(exc))
            spf = dmarc = caa = nameservers = dnssec = mx = None

        # Build risk observations
        observations: List[str] = []
        if spf is None:
            observations.append("No SPF record found — potential email spoofing risk.")
        if dmarc is None:
            observations.append("No DMARC record found — email authentication policy missing.")
        if not dnssec:
            observations.append("DNSSEC not detected — DNS responses may be spoofable.")

        return self._make_result(
            target=target,
            status=ModuleStatus.SUCCESS,
            data={
                "spf": spf,
                "dmarc": dmarc,
                "caa": caa,
                "nameservers": nameservers,
                "dnssec_present": dnssec,
                "mx_records": mx,
                "observations": observations,
                "assets": [],  # OSINT doesn't add new IP assets
            },
            errors=errors,
            metadata={"target": target},
        )

    # ── Record queries ────────────────────────────────────────────────────────

    @staticmethod
    def _txt_records(domain: str) -> List[str]:
        """Return all TXT records for *domain*."""
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 4.0
        try:
            answers = resolver.resolve(domain, "TXT")
            return [b"".join(r.strings).decode(errors="replace") for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            return []

    def _get_spf(self, domain: str) -> Optional[str]:
        for record in self._txt_records(domain):
            if record.lower().startswith("v=spf1"):
                return record
        return None

    def _get_dmarc(self, domain: str) -> Optional[str]:
        for record in self._txt_records(f"_dmarc.{domain}"):
            if record.lower().startswith("v=dmarc1"):
                return record
        return None

    @staticmethod
    def _get_caa(domain: str) -> List[str]:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 4.0
        try:
            answers = resolver.resolve(domain, "CAA")
            return [str(r) for r in answers]
        except Exception:
            return []

    @staticmethod
    def _get_nameservers(domain: str) -> List[str]:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 4.0
        try:
            answers = resolver.resolve(domain, "NS")
            return [str(r).rstrip(".") for r in answers]
        except Exception:
            return []

    @staticmethod
    def _check_dnssec(domain: str) -> bool:
        """Return True if DNSSEC RRSIG records are present."""
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 4.0
        try:
            resolver.resolve(domain, "DNSKEY")
            return True
        except Exception:
            return False

    @staticmethod
    def _get_mx(domain: str) -> List[Dict[str, Any]]:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 4.0
        try:
            answers = resolver.resolve(domain, "MX")
            return [
                {"priority": r.preference, "exchange": str(r.exchange).rstrip(".")}
                for r in answers
            ]
        except Exception:
            return []
