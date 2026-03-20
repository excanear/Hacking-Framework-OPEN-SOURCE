"""
Report generator — orchestrates data collection, risk analysis, export,
and DB persistence for a completed scan.

Usage::

    generator = ReportGenerator()
    report = await generator.generate(
        scan_result=scan_result,
        target=target,
        report_format=ReportFormat.HTML,
        title="Q3 Infra Assessment",
        db=db_session,
    )
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import (
    Asset,
    Report,
    ReportFormat,
    ScanResult,
    Service,
    Target,
    Vulnerability,
)
from intelligence.risk_engine import RiskEngine
from reports.exporters import HTMLExporter, JSONExporter


# Output directory for generated report files
_REPORTS_DIR = Path("reports_output")


class ReportGenerator:
    """Collects findings for a completed scan and produces a structured report."""

    def __init__(self) -> None:
        self._risk_engine = RiskEngine()

    # ── Public interface ─────────────────────────────────────────────────────

    async def generate(
        self,
        scan_result: ScanResult,
        target: Target,
        report_format: ReportFormat,
        title: str,
        db: AsyncSession,
    ) -> Report:
        """Generate a report for *scan_result* and persist it to the database.

        Returns the newly created :class:`~database.models.Report` ORM object.
        """
        # 1. Load related DB rows
        assets = await self._load_assets(db, target.id)
        services = await self._load_services(db, target.id)
        vulnerabilities = await self._load_vulnerabilities(db, target.id)

        # 2. Compute risk score if not already stored
        vuln_dicts = [
            {"severity": v.severity.value if hasattr(v.severity, "value") else str(v.severity),
             "cvss_score": v.cvss_score, "cve_id": v.cve_id, "title": v.title}
            for v in vulnerabilities
        ]
        svc_dicts = [
            {"port": s.port, "is_open": s.is_open, "service_name": s.service_name,
             "product": s.product, "version": s.version}
            for s in services
        ]
        loop = asyncio.get_event_loop()
        risk_result = await loop.run_in_executor(
            None,
            self._risk_engine.score,
            str(target.value),
            vuln_dicts,
            svc_dicts,
        )

        if not scan_result.risk_score:
            scan_result.risk_score = risk_result.final_score
            db.add(scan_result)

        # 3. Build normalised report payload
        report_data = self._build_report_data(
            title=title,
            target=target,
            assets=assets,
            services=services,
            vulnerabilities=vulnerabilities,
            risk_result=risk_result,
            raw_results=scan_result.results or {},
        )

        # 4. Render to the requested format
        file_path = await self._write_file(
            report_data=report_data,
            report_format=report_format,
            scan_id=str(scan_result.id),
        )

        # 5. Persist the Report record
        fmt_value = (
            report_format.value
            if isinstance(report_format, ReportFormat)
            else report_format
        )
        report = Report(
            id=str(uuid.uuid4()),
            title=title,
            format=report_format,
            scan_result_id=str(scan_result.id),
            target_id=str(target.id),
            file_path=str(file_path),
            risk_score=risk_result.final_score,
            summary={
                "risk_score": risk_result.final_score,
                "risk_level": risk_result.risk_level,
                "assets_count": len(assets),
                "services_count": len(services),
                "vulnerabilities_count": len(vulnerabilities),
            },
        )
        db.add(report)
        await db.commit()
        await db.refresh(report)
        return report

    # ── Private helpers ──────────────────────────────────────────────────────

    async def _load_assets(
        self, db: AsyncSession, target_id: uuid.UUID
    ) -> List[Asset]:
        result = await db.execute(select(Asset).where(Asset.target_id == target_id))
        return list(result.scalars().all())

    async def _load_services(
        self, db: AsyncSession, target_id: uuid.UUID
    ) -> List[Service]:
        result = await db.execute(
            select(Service)
            .join(Asset, Service.asset_id == Asset.id)
            .where(Asset.target_id == str(target_id))
        )
        return list(result.scalars().all())

    async def _load_vulnerabilities(
        self, db: AsyncSession, target_id: uuid.UUID
    ) -> List[Vulnerability]:
        result = await db.execute(
            select(Vulnerability)
            .join(Service, Vulnerability.service_id == Service.id)
            .join(Asset, Service.asset_id == Asset.id)
            .where(Asset.target_id == str(target_id))
        )
        return list(result.scalars().all())

    def _build_report_data(
        self,
        *,
        title: str,
        target: Target,
        assets: List[Asset],
        services: List[Service],
        vulnerabilities: List[Vulnerability],
        risk_result: Any,
        raw_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Return a flat, JSON- and template-ready dict."""

        # Extract OSINT observations embedded in raw module results
        observations: List[str] = []
        for module_name, module_data in raw_results.items():
            if isinstance(module_data, dict):
                obs = module_data.get("observations") or module_data.get("findings", [])
                if isinstance(obs, list):
                    observations.extend(str(o) for o in obs)

        recommendations = self._build_recommendations(
            services=services,
            vulnerabilities=vulnerabilities,
            risk_result=risk_result,
            raw_results=raw_results,
        )

        return {
            "title": title,
            "version": "1.0.0",
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "risk_score": risk_result.final_score,
            "risk_level": risk_result.risk_level,
            "summary": {
                "target": target.value,
                "target_type": target.target_type.value
                if hasattr(target.target_type, "value")
                else target.target_type,
                "total_assets": len(assets),
                "total_services": len(services),
                "total_vulnerabilities": len(vulnerabilities),
                "modules_run": len(raw_results),
            },
            "assets": [self._serialise_asset(a) for a in assets],
            "services": [self._serialise_service(s) for s in services],
            "vulnerabilities": [self._serialise_vuln(v) for v in vulnerabilities],
            "risk_breakdown": {
                "score": risk_result.final_score,
                "risk_level": risk_result.risk_level,
                "factors": [
                    {
                        "name": f.name,
                        "delta": f.score_delta,
                        "description": f.description,
                    }
                    for f in risk_result.factors
                ],
            },
            "osint_observations": observations[:50],  # cap for HTML readability
            "recommendations": recommendations,
            "raw_results": raw_results,
        }

    def _build_recommendations(
        self,
        services: List[Service],
        vulnerabilities: List[Vulnerability],
        risk_result: Any,
        raw_results: Dict[str, Any],
    ) -> List[str]:
        recs: List[str] = []

        # CVE-based
        seen_cves: set[str] = set()
        for v in vulnerabilities:
            if v.cve_id and v.cve_id not in seen_cves:
                seen_cves.add(v.cve_id)
                if v.severity in ("critical", "high"):
                    recs.append(
                        f"Patch {v.cve_id} ({v.severity.upper()}) — {v.title}"
                    )

        # Port exposure
        risky_ports = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 5432, 6379, 27017}
        open_ports = {s.port for s in services}
        exposed = open_ports & risky_ports
        if exposed:
            recs.append(
                f"Review firewall rules — sensitive ports exposed: {sorted(exposed)}"
            )

        # Missing security headers
        web_data = raw_results.get("web_analyzer", {})
        missing = web_data.get("findings", {}).get("missing_headers", [])
        if isinstance(missing, list) and missing:
            recs.append(f"Add missing HTTP security headers: {', '.join(missing)}")

        # DNS OSINT
        dns_data = raw_results.get("dns_osint", {})
        obs = dns_data.get("observations", [])
        for o in obs:
            if isinstance(o, str) and "missing" in o.lower():
                recs.append(o)

        # High overall risk
        if risk_result.final_score >= 7.0:
            recs.append(
                "Overall risk score is HIGH — prioritise remediation and re-scan after changes."
            )

        return recs[:20]  # cap to keep reports readable

    # ── Serialisers ──────────────────────────────────────────────────────────

    @staticmethod
    def _serialise_asset(a: Asset) -> Dict[str, Any]:
        return {
            "id": str(a.id),
            "value": a.value,
            "type": a.asset_type.value if hasattr(a.asset_type, "value") else a.asset_type,
            "ip_address": a.ip_address,
            "is_alive": a.is_alive,
        }

    @staticmethod
    def _serialise_service(s: Service) -> Dict[str, Any]:
        return {
            "id": str(s.id),
            "port": s.port,
            "protocol": s.protocol,
            "service_name": s.service_name,
            "product": s.product,
            "version": s.version,
            "banner": s.banner,
        }

    @staticmethod
    def _serialise_vuln(v: Vulnerability) -> Dict[str, Any]:
        return {
            "id": str(v.id),
            "cve_id": v.cve_id,
            "title": v.title,
            "description": v.description,
            "severity": v.severity.value if hasattr(v.severity, "value") else v.severity,
            "cvss_score": float(v.cvss_score) if v.cvss_score else None,
            "affected_software": v.affected_software,
        }

    # ── File I/O ─────────────────────────────────────────────────────────────

    async def _write_file(
        self,
        report_data: Dict[str, Any],
        report_format: ReportFormat,
        scan_id: str,
    ) -> Path:
        """Write the rendered report to disk and return the absolute path."""
        _REPORTS_DIR.mkdir(parents=True, exist_ok=True)

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        fmt_str = (
            report_format.value
            if isinstance(report_format, ReportFormat)
            else str(report_format)
        )
        filename = f"report_{scan_id[:8]}_{ts}.{fmt_str}"
        file_path = _REPORTS_DIR / filename

        if fmt_str == "html":
            exporter = HTMLExporter()
            content = exporter.export(report_data)
            file_path.write_text(content, encoding="utf-8")
        else:
            exporter = JSONExporter()
            content = exporter.export(report_data)
            file_path.write_text(content, encoding="utf-8")

        return file_path.resolve()
