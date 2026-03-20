"""
Risk Scoring Engine

Calculates a normalised numerical risk score (0.0–10.0) for a target based on:
  - Vulnerability severity distribution (CVSS scores)
  - Number and type of exposed services
  - Presence of critical misconfigurations
  - Asset exposure level (internet-facing vs. internal)
  - Asset importance weight (configurable)

Scoring model:
  base_score     = weighted_cvss_aggregate
  exposure_mod   = multiplier based on open port count and service types
  config_penalty = deduction for missing security controls (TLS, headers, etc.)
  final_score    = clamp(base_score * exposure_mod - config_penalty, 0, 10)

Output includes a numeric score and a breakdown of contributing factors.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ─── Severity weights ─────────────────────────────────────────────────────────
# Maps severity label → maximum contribution to base score per finding

_SEVERITY_WEIGHTS: Dict[str, float] = {
    "critical": 10.0,
    "high":      7.5,
    "medium":    5.0,
    "low":       2.5,
    "informational": 0.5,
    "info":      0.5,
    "unknown":   1.0,
}

# Services that meaningfully increase exposure risk
_HIGH_RISK_PORTS: Dict[int, str] = {
    21:    "FTP (cleartext)",
    23:    "Telnet (cleartext)",
    135:   "RPC",
    139:   "NetBIOS",
    445:   "SMB",
    1433:  "MSSQL",
    1521:  "Oracle DB",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    5900:  "VNC",
    6379:  "Redis",
    27017: "MongoDB",
}

_MEDIUM_RISK_PORTS: Dict[int, str] = {
    22:   "SSH",
    25:   "SMTP",
    110:  "POP3",
    143:  "IMAP",
    8080: "HTTP alt",
    9200: "Elasticsearch",
}


@dataclass
class RiskFactor:
    """A single contributing factor used in risk score calculation."""
    name: str
    score_delta: float
    description: str


@dataclass
class RiskScoreResult:
    """Full risk scoring output for a target."""
    target: str
    final_score: float            # 0.0–10.0
    risk_level: str               # critical | high | medium | low | minimal
    vulnerability_score: float
    exposure_score: float
    configuration_penalty: float
    factors: List[RiskFactor] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "final_score": round(self.final_score, 2),
            "risk_level": self.risk_level,
            "vulnerability_score": round(self.vulnerability_score, 2),
            "exposure_score": round(self.exposure_score, 2),
            "configuration_penalty": round(self.configuration_penalty, 2),
            "factors": [
                {"name": f.name, "delta": round(f.score_delta, 2), "description": f.description}
                for f in self.factors
            ],
            "recommendations": self.recommendations,
        }


def _risk_level(score: float) -> str:
    """Map a numeric score to a human-readable risk level."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 2.0:
        return "low"
    return "minimal"


class RiskEngine:
    """
    Computes a composite risk score for a target from scan findings.

    Accepts structured data produced by the CVEIntelligenceEngine and
    the various SecurityModules and returns a RiskScoreResult.
    """

    # ── Public interface ──────────────────────────────────────────────────────

    def score(
        self,
        target: str,
        vulnerabilities: List[Dict[str, Any]],
        services: List[Dict[str, Any]],
        web_findings: Optional[List[Dict[str, Any]]] = None,
        asset_importance: float = 1.0,
    ) -> RiskScoreResult:
        """
        Calculate the composite risk score for *target*.

        Args:
            target:           Target value string (for labelling).
            vulnerabilities:  List of vuln dicts from CVEIntelligenceEngine.
            services:         List of service dicts from port/fingerprint modules.
            web_findings:     Optional list of web analyser findings.
            asset_importance: Multiplier (0.5 = low importance, 2.0 = critical asset).

        Returns:
            RiskScoreResult with full breakdown.
        """
        factors: List[RiskFactor] = []
        recommendations: List[str] = []

        # ── 1. Vulnerability sub-score ────────────────────────────────────────
        vuln_score = self._vulnerability_score(vulnerabilities, factors)

        # ── 2. Exposure sub-score ──────────────────────────────────────────────
        exp_score = self._exposure_score(services, factors, recommendations)

        # ── 3. Configuration penalty (web) ────────────────────────────────────
        config_penalty = self._config_penalty(web_findings or [], factors, recommendations)

        # ── 4. Combine ─────────────────────────────────────────────────────────
        raw = (vuln_score * 0.6) + (exp_score * 0.4)
        raw = raw * asset_importance - config_penalty
        final = max(0.0, min(10.0, raw))

        return RiskScoreResult(
            target=target,
            final_score=final,
            risk_level=_risk_level(final),
            vulnerability_score=vuln_score,
            exposure_score=exp_score,
            configuration_penalty=config_penalty,
            factors=factors,
            recommendations=recommendations,
        )

    # ── Sub-scorers ────────────────────────────────────────────────────────────

    def _vulnerability_score(
        self,
        vulns: List[Dict[str, Any]],
        factors: List[RiskFactor],
    ) -> float:
        """Aggregate CVSS scores across all vulnerabilities, capped at 10."""
        if not vulns:
            return 0.0

        total = 0.0
        for vuln in vulns:
            severity = (vuln.get("severity") or "unknown").lower()
            cvss = vuln.get("cvss_score")
            if cvss is not None:
                contribution = float(cvss)
            else:
                contribution = _SEVERITY_WEIGHTS.get(severity, 1.0)

            total += contribution
            factors.append(RiskFactor(
                name=f"vuln:{vuln.get('cve_id', 'unknown')}",
                score_delta=contribution,
                description=f"{vuln.get('cve_id', '?')} ({severity}) — {vuln.get('title', '')[:80]}",
            ))

        # Use logarithmic damping so one CVE-10.0 doesn't dominate unfairly
        damped = 10.0 * (1.0 - math.exp(-total / 15.0))
        return min(10.0, damped)

    def _exposure_score(
        self,
        services: List[Dict[str, Any]],
        factors: List[RiskFactor],
        recommendations: List[str],
    ) -> float:
        """Score based on number and risk classification of open ports."""
        if not services:
            return 0.0

        total = 0.0
        for svc in services:
            port = svc.get("port", 0)
            if not svc.get("is_open", True):
                continue

            if port in _HIGH_RISK_PORTS:
                delta = 3.0
                factors.append(RiskFactor(
                    name=f"port:{port}",
                    score_delta=delta,
                    description=f"High-risk service exposed: {_HIGH_RISK_PORTS[port]} (port {port})",
                ))
                recommendations.append(
                    f"Restrict access to port {port} ({_HIGH_RISK_PORTS[port]}) "
                    "using a firewall or VPN."
                )
                total += delta
            elif port in _MEDIUM_RISK_PORTS:
                delta = 1.5
                factors.append(RiskFactor(
                    name=f"port:{port}",
                    score_delta=delta,
                    description=f"Medium-risk service: {_MEDIUM_RISK_PORTS[port]} (port {port})",
                ))
                total += delta
            else:
                total += 0.5  # anything open is slight exposure

        # Too many open ports also adds risk
        open_count = sum(1 for s in services if s.get("is_open", True))
        if open_count > 20:
            extra = 2.0
            factors.append(RiskFactor(
                name="many_open_ports",
                score_delta=extra,
                description=f"Large attack surface: {open_count} open ports detected.",
            ))
            recommendations.append(
                "Reduce attack surface by closing unnecessary services."
            )
            total += extra

        return min(10.0, total)

    def _config_penalty(
        self,
        web_findings: List[Dict[str, Any]],
        factors: List[RiskFactor],
        recommendations: List[str],
    ) -> float:
        """Subtract score for missing security controls detected in web analysis."""
        penalty = 0.0
        for finding in web_findings:
            missing = finding.get("missing_security_headers", [])
            for header_info in missing:
                header = header_info.get("header", "")
                p = 0.3
                factors.append(RiskFactor(
                    name=f"missing_header:{header}",
                    score_delta=-p,
                    description=f"Missing HTTP security header: {header}",
                ))
                recommendations.append(
                    f"Add '{header}' HTTP response header: {header_info.get('description', '')}"
                )
                penalty += p

            if finding.get("insecure_cookies"):
                p = 0.5
                factors.append(RiskFactor(
                    name="insecure_cookies",
                    score_delta=-p,
                    description="Cookies without Secure/HttpOnly flags detected.",
                ))
                recommendations.append(
                    "Set Secure and HttpOnly flags on all authentication cookies."
                )
                penalty += p

        return penalty
