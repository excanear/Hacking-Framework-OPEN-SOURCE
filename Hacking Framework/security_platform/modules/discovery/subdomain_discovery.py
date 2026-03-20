"""
Subdomain Discovery Module

Performs passive subdomain enumeration via DNS brute-force using a built-in
wordlist and DNS A/AAAA record resolution.

AUTHORISATION NOTICE: Only run against targets you are explicitly authorised
to test.  Unauthorised scanning may be illegal in your jurisdiction.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any, Dict, List, Optional

import dns.resolver
import dns.exception

from modules.base_module import ModuleResult, ModuleStatus, SecurityModule

logger = logging.getLogger(__name__)

# Common subdomain prefixes used for passive enumeration.
# This list is intentionally conservative and does not include intrusive or
# aggressive probing patterns.
_DEFAULT_WORDLIST: List[str] = [
    "www", "mail", "ftp", "api", "dev", "staging", "test", "beta",
    "admin", "portal", "vpn", "remote", "blog", "shop", "store",
    "cdn", "static", "assets", "img", "media", "docs", "support",
    "app", "mobile", "m", "status", "monitor", "dashboard", "auth",
    "login", "oauth", "sso", "smtp", "imap", "pop", "ns1", "ns2",
    "dns", "mx", "cloud", "aws", "azure", "gcp", "ci", "jenkins",
    "git", "gitlab", "jira", "confluence", "wiki",
]


class SubdomainDiscovery(SecurityModule):
    """
    Passive subdomain enumeration via DNS resolution.

    Resolves a wordlist of candidate subdomains against the target domain
    and returns those that successfully resolve to one or more IP addresses.
    """

    name = "subdomain_discovery"
    category = "discovery"
    description = (
        "Enumerates subdomains of a target domain via DNS A/AAAA resolution "
        "using a built-in wordlist."
    )
    version = "1.1.0"

    def __init__(
        self,
        wordlist: Optional[List[str]] = None,
        concurrency: int = 50,
        timeout: float = 3.0,
    ) -> None:
        self._wordlist = wordlist or _DEFAULT_WORDLIST
        self._concurrency = concurrency
        self._timeout = timeout

    # ── Validation ────────────────────────────────────────────────────────────

    async def validate_target(self, target: str) -> bool:
        """Accept only simple domain names (not IPs or CIDR ranges)."""
        if not target or "." not in target:
            return False
        # Reject targets that look like IP addresses
        parts = target.split(".")
        if all(p.isdigit() for p in parts):
            return False
        return True

    # ── Core execution ────────────────────────────────────────────────────────

    async def run(self, target: str, **kwargs: Any) -> ModuleResult:
        """
        Enumerate subdomains of *target* domain.

        Keyword Args:
            wordlist (List[str]): Override the default wordlist.
            concurrency (int):    Max concurrent DNS queries.
            timeout (float):      Per-query timeout in seconds.
        """
        wordlist = kwargs.get("wordlist", self._wordlist)
        concurrency = int(kwargs.get("concurrency", self._concurrency))
        timeout = float(kwargs.get("timeout", self._timeout))

        logger.info(
            "[%s] Enumerating subdomains for '%s' (wordlist=%d, concurrency=%d).",
            self.name, target, len(wordlist), concurrency,
        )

        semaphore = asyncio.Semaphore(concurrency)
        tasks = [
            self._resolve_candidate(f"{prefix}.{target}", semaphore, timeout)
            for prefix in wordlist
        ]
        results = await asyncio.gather(*tasks, return_exceptions=False)

        discovered = [r for r in results if r is not None]

        logger.info(
            "[%s] Found %d subdomains for '%s'.", self.name, len(discovered), target
        )

        return self._make_result(
            target=target,
            status=ModuleStatus.SUCCESS,
            data={
                "assets": [
                    {
                        "value": item["subdomain"],
                        "type": "subdomain",
                        "ip_address": item["ips"][0] if item["ips"] else None,
                        "hostname": item["subdomain"],
                        "is_alive": True,
                        "metadata": {"resolved_ips": item["ips"]},
                        "services": [],
                    }
                    for item in discovered
                ],
                "total_found": len(discovered),
                "wordlist_size": len(wordlist),
            },
            metadata={"target": target},
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _resolve_candidate(
        self,
        fqdn: str,
        semaphore: asyncio.Semaphore,
        timeout: float,
    ) -> Optional[Dict[str, Any]]:
        """Attempt to resolve *fqdn*.  Returns a result dict on success, else None."""
        async with semaphore:
            loop = asyncio.get_event_loop()
            try:
                # Run the blocking DNS query in a thread pool to stay non-blocking
                ips = await asyncio.wait_for(
                    loop.run_in_executor(None, self._dns_resolve, fqdn),
                    timeout=timeout,
                )
                if ips:
                    return {"subdomain": fqdn, "ips": ips}
            except (asyncio.TimeoutError, dns.exception.DNSException):
                pass
            except Exception as exc:
                logger.debug("Unexpected error resolving '%s': %s", fqdn, exc)
        return None

    @staticmethod
    def _dns_resolve(fqdn: str) -> List[str]:
        """Blocking DNS A/AAAA resolution — runs in thread pool."""
        ips: List[str] = []
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 2.0
        for record_type in ("A", "AAAA"):
            try:
                answers = resolver.resolve(fqdn, record_type)
                ips.extend(str(r) for r in answers)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                pass
        return ips
