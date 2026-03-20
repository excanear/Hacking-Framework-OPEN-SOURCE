"""
Cloud Asset Discovery Module

Performs passive DNS-based cloud asset detection by identifying CNAME records
that point to known cloud provider domains (AWS, Azure, GCP, Cloudflare, etc.).

This module does NOT authenticate with any cloud provider API and does NOT
attempt to access cloud resources.  It only performs DNS lookups.

AUTHORISATION NOTICE: Only enumerate targets you own or are authorised to assess.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple

import dns.resolver
import dns.exception

from modules.base_module import ModuleResult, ModuleStatus, SecurityModule

logger = logging.getLogger(__name__)


# Known cloud CNAME suffixes for passive cloud footprinting
_CLOUD_PROVIDERS: List[Tuple[str, str]] = [
    ("amazonaws.com", "AWS"),
    ("cloudfront.net", "AWS CloudFront"),
    ("s3.amazonaws.com", "AWS S3"),
    ("elasticbeanstalk.com", "AWS Elastic Beanstalk"),
    ("azurewebsites.net", "Azure App Service"),
    ("azureedge.net", "Azure CDN"),
    ("azure.com", "Microsoft Azure"),
    ("blob.core.windows.net", "Azure Blob Storage"),
    ("trafficmanager.net", "Azure Traffic Manager"),
    ("googleapis.com", "Google Cloud"),
    ("appspot.com", "Google App Engine"),
    ("storage.googleapis.com", "Google Cloud Storage"),
    ("run.app", "Google Cloud Run"),
    ("cloudfunctions.net", "Google Cloud Functions"),
    ("netlify.app", "Netlify"),
    ("vercel.app", "Vercel"),
    ("pages.dev", "Cloudflare Pages"),
    ("workers.dev", "Cloudflare Workers"),
    ("heroku.com", "Heroku"),
    ("herokudns.com", "Heroku"),
    ("fastly.net", "Fastly CDN"),
    ("akamaiedge.net", "Akamai CDN"),
    ("cloudflare.com", "Cloudflare"),
]

# Common cloud-associated subdomain prefixes to probe
_CLOUD_SUBDOMAINS: List[str] = [
    "www", "api", "cdn", "static", "assets", "media", "storage",
    "files", "uploads", "images", "app", "app2", "staging", "dev",
    "prod", "production", "s3", "backup", "data", "mail", "email",
]


class CloudDiscovery(SecurityModule):
    """
    Passive cloud asset discovery via CNAME DNS analysis.

    Identifies cloud services (AWS, Azure, GCP, CDN providers) used by a target
    by resolving CNAME chains and matching against known cloud domain suffixes.
    """

    name = "cloud_discovery"
    category = "cloud"
    description = (
        "Passively identifies cloud assets (AWS, Azure, GCP, CDN) by resolving "
        "CNAME records and matching against known cloud provider domain patterns."
    )
    version = "1.0.0"
    requires = ["subdomain_discovery"]

    def __init__(self, concurrency: int = 30, timeout: float = 3.0) -> None:
        self._concurrency = concurrency
        self._timeout = timeout

    async def validate_target(self, target: str) -> bool:
        if not target or "." not in target:
            return False
        parts = target.split(".")
        return not all(p.isdigit() for p in parts)

    async def run(self, target: str, **kwargs: Any) -> ModuleResult:
        """
        Discover cloud assets for *target* domain.

        Keyword Args:
            subdomains  (List[str]): Pre-discovered subdomains to check.
                                     Defaults to built-in _CLOUD_SUBDOMAINS.
            concurrency (int):       Max parallel DNS queries.
            timeout     (float):     Per-query timeout.
        """
        subdomains: List[str] = kwargs.get("subdomains", _CLOUD_SUBDOMAINS)
        concurrency = int(kwargs.get("concurrency", self._concurrency))
        timeout = float(kwargs.get("timeout", self._timeout))

        # Build candidate FQDNs: target itself + subdomains
        candidates = [target] + [f"{sub}.{target}" for sub in subdomains]

        logger.info(
            "[%s] Probing %d candidates for cloud assets on '%s'.",
            self.name, len(candidates), target,
        )

        semaphore = asyncio.Semaphore(concurrency)
        tasks = [
            self._check_candidate(fqdn, semaphore, timeout)
            for fqdn in candidates
        ]
        results = await asyncio.gather(*tasks)
        cloud_assets = [r for r in results if r is not None]

        logger.info(
            "[%s] Found %d cloud assets for '%s'.",
            self.name, len(cloud_assets), target,
        )

        assets = [
            {
                "value": ca["fqdn"],
                "type": "cloud_asset",
                "ip_address": None,
                "hostname": ca["fqdn"],
                "is_alive": True,
                "metadata": {
                    "provider": ca["provider"],
                    "cname": ca["cname"],
                    "source": "cloud_discovery",
                },
                "services": [],
            }
            for ca in cloud_assets
        ]

        return self._make_result(
            target=target,
            status=ModuleStatus.SUCCESS,
            data={
                "assets": assets,
                "cloud_assets": cloud_assets,
                "providers_found": list({ca["provider"] for ca in cloud_assets}),
                "total_found": len(cloud_assets),
            },
            metadata={"candidates_checked": len(candidates)},
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _check_candidate(
        self,
        fqdn: str,
        semaphore: asyncio.Semaphore,
        timeout: float,
    ) -> Optional[Dict[str, Any]]:
        """Resolve CNAME chain for *fqdn* and check against cloud provider patterns."""
        async with semaphore:
            loop = asyncio.get_event_loop()
            try:
                cname = await asyncio.wait_for(
                    loop.run_in_executor(None, self._resolve_cname, fqdn),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                return None

            if not cname:
                return None

            for suffix, provider in _CLOUD_PROVIDERS:
                if suffix in cname.lower():
                    return {"fqdn": fqdn, "cname": cname, "provider": provider}
        return None

    @staticmethod
    def _resolve_cname(fqdn: str) -> Optional[str]:
        """Return the final CNAME target for *fqdn*, or None if not a CNAME."""
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 2.5
        try:
            answers = resolver.resolve(fqdn, "CNAME")
            return str(answers[0].target).rstrip(".")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            return None
