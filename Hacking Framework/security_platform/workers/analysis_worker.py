"""
Analysis Worker

Celery tasks for post-scan intelligence correlation and risk scoring.

These tasks run after a scan completes and enrich the ScanResult with:
  - CVE correlation for discovered services
  - Risk score calculation
  - Vulnerability records persisted to the database

Task routing: all tasks route to the `analysis` queue.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
from typing import Any, Dict, List, Optional

from celery.exceptions import SoftTimeLimitExceeded

from workers.worker_manager import celery_app

logger = logging.getLogger(__name__)


def _run_async(coro):
    """Run an async coroutine safely regardless of whether an event loop is running."""
    try:
        asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    except RuntimeError:
        return asyncio.run(coro)


@celery_app.task(
    bind=True,
    name="workers.analysis_worker.run_analysis_task",
    queue="analysis",
    max_retries=1,
    soft_time_limit=180,
    time_limit=240,
)
def run_analysis_task(
    self,
    scan_result_id: str,
) -> Dict[str, Any]:
    """
    Run intelligence correlation and risk scoring for a completed scan.

    Reads the scan results from the database, correlates services with CVEs,
    calculates a risk score, and writes findings back.

    Args:
        scan_result_id: ID of the completed ScanResult record.

    Returns:
        Dict containing risk score and vulnerability summary.
    """
    logger.info("[analysis_worker] Starting analysis for scan '%s'.", scan_result_id)

    try:
        result = _run_async(_run_analysis(scan_result_id))
        logger.info(
            "[analysis_worker] Analysis complete for '%s'. Risk score: %.2f",
            scan_result_id, result.get("risk_score", 0.0),
        )
        return result

    except SoftTimeLimitExceeded:
        logger.warning("[analysis_worker] Analysis timed out for '%s'.", scan_result_id)
        raise

    except Exception as exc:
        logger.exception("[analysis_worker] Analysis failed for '%s'.", scan_result_id)
        raise self.retry(exc=exc)


async def _run_analysis(scan_result_id: str) -> Dict[str, Any]:
    """
    Async implementation of the analysis pipeline.

    1. Load the ScanResult and its associated services from the database.
    2. Correlate services with CVEs via CVEIntelligenceEngine.
    3. Score risk via RiskEngine.
    4. Persist all findings and update the ScanResult risk_score.
    """
    from database.database import AsyncSessionLocal
    from database.models import ScanResult, Vulnerability, SeverityLevel
    from intelligence.cve_intelligence import CVEIntelligenceEngine
    from intelligence.risk_engine import RiskEngine
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    cve_engine = CVEIntelligenceEngine(use_nvd_api=False)
    risk_engine = RiskEngine()

    async with AsyncSessionLocal() as session:
        # Load scan result with related target assets and services
        stmt = (
            select(ScanResult)
            .where(ScanResult.id == scan_result_id)
            .options(
                selectinload(ScanResult.target)
            )
        )
        row = await session.execute(stmt)
        scan: Optional[ScanResult] = row.scalar_one_or_none()

        if scan is None:
            raise ValueError(f"ScanResult '{scan_result_id}' not found.")

        results_data: Dict[str, Any] = scan.results or {}

        # Collect all services from the scan results payload
        all_services: List[Dict[str, Any]] = []
        web_findings: List[Dict[str, Any]] = []

        for _module_name, module_result in results_data.get("results", {}).items():
            data = module_result.get("data", {})
            for asset in data.get("assets", []):
                all_services.extend(asset.get("services", []))
            if "web_findings" in data:
                web_findings.extend(data["web_findings"])

        # ── CVE correlation ────────────────────────────────────────────────
        vulnerabilities = await cve_engine.correlate_services(all_services)

        # Persist new vulnerability records
        for vuln_data in vulnerabilities:
            vuln = Vulnerability(
                cve_id=vuln_data.get("cve_id"),
                title=vuln_data.get("title", ""),
                description=vuln_data.get("description"),
                severity=_map_severity(vuln_data.get("severity", "unknown")),
                cvss_score=vuln_data.get("cvss_score"),
                cvss_vector=vuln_data.get("cvss_vector"),
                affected_software=vuln_data.get("affected_software"),
                affected_version=vuln_data.get("affected_version"),
                references={"urls": vuln_data.get("references", [])},
            )
            session.add(vuln)

        # ── Risk scoring ───────────────────────────────────────────────────
        risk_result = risk_engine.score(
            target=scan.target.value if scan.target else scan_result_id,
            vulnerabilities=vulnerabilities,
            services=all_services,
            web_findings=web_findings,
        )

        # Update the ScanResult with the risk score
        scan.risk_score = risk_result.final_score
        if scan.results:
            scan.results["risk_analysis"] = risk_result.to_dict()
            scan.results["vulnerabilities_found"] = vulnerabilities

        await session.commit()

    return {
        "scan_result_id": scan_result_id,
        "risk_score": risk_result.final_score,
        "risk_level": risk_result.risk_level,
        "vulnerabilities_found": len(vulnerabilities),
        "risk_breakdown": risk_result.to_dict(),
    }


def _map_severity(raw: str):
    """Map a raw severity string to a SeverityLevel enum value."""
    from database.models import SeverityLevel
    mapping = {
        "critical": SeverityLevel.CRITICAL,
        "high":     SeverityLevel.HIGH,
        "medium":   SeverityLevel.MEDIUM,
        "low":      SeverityLevel.LOW,
    }
    return mapping.get(raw.lower(), SeverityLevel.INFO)
