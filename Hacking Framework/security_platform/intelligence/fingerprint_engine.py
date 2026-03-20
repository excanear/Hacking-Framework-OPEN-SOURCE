"""
Service Fingerprint Engine (Intelligence Layer)

Maps raw service banners and HTTP headers to structured product/version
records using a compact signature database.  This is the intelligence-layer
counterpart to the network-layer module; it handles richer inputs including
pre-correlated service data from multiple modules.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ─── Signature registry ───────────────────────────────────────────────────────
# Each entry: (regex pattern, product string, version capture group index | None)

_SIGNATURES: List[Tuple[re.Pattern, str, Optional[int]]] = [
    # SSH
    (re.compile(r"OpenSSH[_\s]([\d.]+p?\d*)", re.I), "OpenSSH", 1),
    (re.compile(r"SSH-2\.0-dropbear[_\s]?([\d.]*)", re.I), "Dropbear SSH", 1),
    # HTTP servers
    (re.compile(r"Apache[/\s]([\d.]+)", re.I), "Apache HTTP Server", 1),
    (re.compile(r"nginx[/\s]([\d.]+)", re.I), "nginx", 1),
    (re.compile(r"Microsoft-IIS[/\s]([\d.]+)", re.I), "Microsoft IIS", 1),
    (re.compile(r"LiteSpeed", re.I), "LiteSpeed Web Server", None),
    (re.compile(r"Caddy", re.I), "Caddy", None),
    # Web frameworks & platforms
    (re.compile(r"PHP[/\s]([\d.]+)", re.I), "PHP", 1),
    (re.compile(r"WordPress/([\d.]+)", re.I), "WordPress", 1),
    (re.compile(r"Drupal\s+([\d.]+)", re.I), "Drupal", 1),
    (re.compile(r"Joomla!?\s+([\d.]+)", re.I), "Joomla", 1),
    # FTP
    (re.compile(r"vsftpd\s+([\d.]+)", re.I), "vsftpd", 1),
    (re.compile(r"ProFTPD\s+([\d.]+)", re.I), "ProFTPD", 1),
    (re.compile(r"FileZilla Server\s+([\d.]+)", re.I), "FileZilla Server", 1),
    # Mail
    (re.compile(r"Postfix ESMTP", re.I), "Postfix", None),
    (re.compile(r"Exim\s+([\d.]+)", re.I), "Exim", 1),
    (re.compile(r"Microsoft ESMTP MAIL Service", re.I), "Microsoft Exchange", None),
    (re.compile(r"Sendmail\s+([\d./]+)", re.I), "Sendmail", 1),
    # Databases
    (re.compile(r"MySQL.*?([\d.]+)", re.I), "MySQL", 1),
    (re.compile(r"MariaDB.*?([\d.]+)", re.I), "MariaDB", 1),
    (re.compile(r"PostgreSQL.*?([\d.]+)", re.I), "PostgreSQL", 1),
    (re.compile(r"Microsoft SQL Server.*?([\d.]+)", re.I), "Microsoft SQL Server", 1),
    (re.compile(r"Oracle.*?([\d.]+)", re.I), "Oracle Database", 1),
    (re.compile(r"MongoDB\s+([\d.]+)", re.I), "MongoDB", 1),
    (re.compile(r"Redis\s+([\d.]+)", re.I), "Redis", 1),
    (re.compile(r"CouchDB/([\d.]+)", re.I), "Apache CouchDB", 1),
    (re.compile(r"Elasticsearch\s+version:\s*([\d.]+)", re.I), "Elasticsearch", 1),
    (re.compile(r"Cassandra\s+([\d.]+)", re.I), "Apache Cassandra", 1),
    # Message brokers
    (re.compile(r"RabbitMQ\s+([\d.]+)", re.I), "RabbitMQ", 1),
    (re.compile(r"Kafka\s+([\d.]+)", re.I), "Apache Kafka", 1),
    # VPN / remote access
    (re.compile(r"OpenVPN\s+([\d.]+)", re.I), "OpenVPN", 1),
    (re.compile(r"Cisco ASA", re.I), "Cisco ASA", None),
    (re.compile(r"Fortinet", re.I), "Fortinet VPN", None),
    # Network devices
    (re.compile(r"Cisco IOS\s+([\d.]+)", re.I), "Cisco IOS", 1),
    (re.compile(r"Juniper", re.I), "Juniper", None),
    (re.compile(r"pfSense", re.I), "pfSense", None),
]


class FingerprintEngine:
    """
    Intelligence-layer service fingerprinting engine.

    Accepts raw banner strings, HTTP headers, or pre-structured service dicts
    and returns structured product/version identification.
    """

    def identify(self, banner: str) -> Dict[str, Optional[str]]:
        """
        Match *banner* string against all known signatures.

        Returns:
            dict with keys: product, version  (both Optional[str])
        """
        if not banner:
            return {"product": None, "version": None}
        for pattern, product, version_group in _SIGNATURES:
            m = pattern.search(banner)
            if m:
                version = m.group(version_group) if version_group else None
                return {"product": product, "version": version}
        return {"product": None, "version": None}

    def enrich_services(
        self, services: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Enrich a list of service dicts by fingerprinting any available banner.

        Fills in `product` and `version` when not already populated.

        Args:
            services: List of service dicts (minimally containing `banner`).

        Returns:
            Enriched copy of the service list.
        """
        enriched: List[Dict[str, Any]] = []
        for svc in services:
            svc = dict(svc)  # copy — never mutate input
            banner = svc.get("banner") or ""
            if not svc.get("product") and banner:
                identified = self.identify(banner)
                svc["product"] = identified["product"]
                svc["version"] = identified["version"]
            enriched.append(svc)
        return enriched

    def identify_from_headers(
        self, headers: Dict[str, str]
    ) -> Dict[str, Optional[str]]:
        """
        Extract product/version from HTTP response headers.

        Checks Server, X-Powered-By, and Via headers.
        """
        combined = " ".join(
            headers.get(h, "")
            for h in ("server", "x-powered-by", "via", "x-generator")
        )
        return self.identify(combined)
