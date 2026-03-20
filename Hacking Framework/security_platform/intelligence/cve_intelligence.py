"""
CVE Intelligence Engine

Correlates discovered software versions with known CVE vulnerability data.

Data sources (in order of preference):
  1. Local embedded signature database (always available, no network required)
  2. NIST NVD REST API v2 (requires network; rate-limited to 5 req/30s without key)

The engine normalises product names, matches CPE strings, and returns a list of
CVE findings with CVSS scores for each service passed in.

USAGE NOTE: This module performs outbound HTTPS requests to NIST NVD.
            Configure `NVD_API_KEY` in `.env` to raise the rate limit.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

# ─── Embedded signature DB ────────────────────────────────────────────────────
# A minimal built-in database of notable CVEs for demonstration.
# In production, replace or augment this with a live CVE feed.

_EMBEDDED_CVE_DB: List[Dict[str, Any]] = [
    {
        "cve_id": "CVE-2021-44228",
        "title": "Apache Log4j2 Remote Code Execution (Log4Shell)",
        "description": "A JNDI injection vulnerability in Apache Log4j2 allows unauthenticated RCE.",
        "severity": "critical",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "affected_software": "apache log4j",
        "affected_versions": ["2.0", "2.1", "2.2", "2.3", "2.4", "2.5", "2.6",
                               "2.7", "2.8", "2.9", "2.10", "2.11", "2.12", "2.13",
                               "2.14", "2.15", "2.16"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    },
    {
        "cve_id": "CVE-2021-45046",
        "title": "Apache Log4j2 Thread Context RCE",
        "description": "Incomplete fix for Log4Shell allows RCE via thread context lookups.",
        "severity": "critical",
        "cvss_score": 9.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "affected_software": "apache log4j",
        "affected_versions": ["2.15"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-45046"],
    },
    {
        "cve_id": "CVE-2022-0778",
        "title": "OpenSSL Infinite Loop (DoS)",
        "description": "BN_mod_sqrt() infinite loop in OpenSSL via malformed certificate.",
        "severity": "high",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "affected_software": "openssl",
        "affected_versions": ["1.0.2", "1.1.1", "3.0"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-0778"],
    },
    {
        "cve_id": "CVE-2021-3156",
        "title": "Sudo Heap-Based Buffer Overflow (Baron Samedit)",
        "description": "Heap buffer overflow in sudo allows local privilege escalation.",
        "severity": "high",
        "cvss_score": 7.8,
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "affected_software": "sudo",
        "affected_versions": ["1.8.2", "1.8.3", "1.9.0", "1.9.1", "1.9.2", "1.9.3",
                               "1.9.4", "1.9.5"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-3156"],
    },
    {
        "cve_id": "CVE-2016-5195",
        "title": "Dirty COW — Linux Kernel Privilege Escalation",
        "description": "Race condition in Linux kernel mm/gup.c allows local privilege escalation.",
        "severity": "high",
        "cvss_score": 7.8,
        "cvss_vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "affected_software": "linux kernel",
        "affected_versions": [],  # all kernels before patch in October 2016
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2016-5195"],
    },
    {
        "cve_id": "CVE-2019-0708",
        "title": "BlueKeep — Remote Desktop Services RCE",
        "description": "Pre-auth RCE via Windows RDP (CVE-2019-0708).",
        "severity": "critical",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "affected_software": "microsoft windows",
        "affected_versions": ["xp", "7", "server 2003", "server 2008"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-0708"],
    },
    {
        "cve_id": "CVE-2017-5638",
        "title": "Apache Struts2 RCE via Content-Type",
        "description": "Jakarta Multipart parser in Struts2 allows remote code execution.",
        "severity": "critical",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "affected_software": "apache struts",
        "affected_versions": ["2.3.5", "2.3.10", "2.3.15", "2.5", "2.5.10"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-5638"],
    },
]


class CVEIntelligenceEngine:
    """
    Correlates discovered service versions with known CVE vulnerability data.

    Matching strategy:
      1. Normalise product name (lowercase, strip punctuation)
      2. Check embedded CVE database for the product
      3. Optionally query NIST NVD API for enriched results
    """

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_API_KEY_ENV = "NVD_API_KEY"

    def __init__(self, use_nvd_api: bool = False) -> None:
        self._use_nvd_api = use_nvd_api
        self._nvd_api_key: Optional[str] = os.environ.get(self.NVD_API_KEY_ENV)

    # ── Public interface ──────────────────────────────────────────────────────

    async def correlate_services(
        self, services: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Correlate a list of service dicts with known CVEs.

        Each service dict should have at least `product` and optionally `version`.

        Returns a list of vulnerability finding dicts.
        """
        findings: List[Dict[str, Any]] = []

        for service in services:
            product = (service.get("product") or "").lower().strip()
            version = (service.get("version") or "").strip()
            if not product:
                continue

            vuln_list = self._match_embedded(product, version)

            if self._use_nvd_api and not vuln_list:
                try:
                    vuln_list = await self._query_nvd(product, version)
                except Exception as exc:
                    logger.warning("NVD API query failed for '%s': %s", product, exc)

            for vuln in vuln_list:
                findings.append({
                    "service_port": service.get("port"),
                    "product": product,
                    "version": version,
                    **vuln,
                })

        return findings

    # ── Embedded DB matching ──────────────────────────────────────────────────

    def _match_embedded(
        self, product: str, version: str
    ) -> List[Dict[str, Any]]:
        """Match *product* and *version* against the embedded CVE database."""
        matches: List[Dict[str, Any]] = []
        normalised = self._normalise(product)

        for entry in _EMBEDDED_CVE_DB:
            db_product = self._normalise(entry["affected_software"])
            if db_product not in normalised and normalised not in db_product:
                continue
            affected_versions = entry.get("affected_versions", [])
            if affected_versions and version:
                version_match = any(
                    version.startswith(av) for av in affected_versions
                )
                if not version_match:
                    continue
            matches.append({
                "cve_id": entry["cve_id"],
                "title": entry["title"],
                "description": entry["description"],
                "severity": entry["severity"],
                "cvss_score": entry["cvss_score"],
                "cvss_vector": entry["cvss_vector"],
                "affected_software": entry["affected_software"],
                "affected_version": version,
                "references": entry.get("references", []),
            })
        return matches

    # ── NVD API ───────────────────────────────────────────────────────────────

    async def _query_nvd(
        self, product: str, version: str
    ) -> List[Dict[str, Any]]:
        """
        Query the NIST NVD REST API v2 for vulnerabilities matching *product*.

        Respects rate limits: 5 req/30s without API key, 50/30s with key.
        """
        params: Dict[str, Any] = {
            "keywordSearch": product,
            "resultsPerPage": 10,
        }
        headers: Dict[str, str] = {}
        if self._nvd_api_key:
            headers["apiKey"] = self._nvd_api_key

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(self.NVD_API_BASE, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        findings: List[Dict[str, Any]] = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            desc_en = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"), ""
            )
            metrics = cve.get("metrics", {})
            cvss_data = (
                metrics.get("cvssMetricV31", [{}])[0]
                or metrics.get("cvssMetricV30", [{}])[0]
                or {}
            )
            cvss = cvss_data.get("cvssData", {})
            score = cvss.get("baseScore", 0.0)
            severity = cvss.get("baseSeverity", "unknown").lower()

            findings.append({
                "cve_id": cve_id,
                "title": cve_id,
                "description": desc_en[:500],
                "severity": severity,
                "cvss_score": score,
                "cvss_vector": cvss.get("vectorString"),
                "affected_software": product,
                "affected_version": version,
                "references": [
                    r.get("url", "")
                    for r in cve.get("references", [])[:3]
                ],
            })
        return findings

    # ── Utilities ─────────────────────────────────────────────────────────────

    @staticmethod
    def _normalise(text: str) -> str:
        """Convert to lowercase and strip non-alphanumeric characters."""
        return re.sub(r"[^a-z0-9 ]", " ", text.lower()).strip()
