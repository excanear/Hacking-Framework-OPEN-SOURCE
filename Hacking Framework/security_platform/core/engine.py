"""
Security Engine — central orchestrator for all platform operations.

The SecurityEngine:
  - Owns the PluginLoader and initialises it on startup
  - Provides high-level methods for running single modules or complete workflows
  - Persists scan results and discovered assets to the database
  - Is designed to be used both by the FastAPI layer and the worker layer

Usage::

    engine = SecurityEngine()
    await engine.startup()

    result = await engine.run_module("subdomain_discovery", target="example.com")
    scan   = await engine.run_full_scan(target_id="...", target="example.com")
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from config.settings import settings
from core.plugin_loader import PluginLoader
from database.database import get_db_session
from database.models import Asset, ScanResult, ScanStatus, Service, Target
from modules.base_module import ModuleResult, ModuleStatus

logger = logging.getLogger(__name__)


class SecurityEngine:
    """
    Central orchestrator for the security research platform.

    This class is intentionally stateless between requests so it can be
    shared safely across async tasks and worker processes.
    """

    def __init__(self) -> None:
        self.plugin_loader = PluginLoader()
        self._initialised = False

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def startup(self) -> None:
        """Initialise the engine: discover plugins and run module setup hooks."""
        if self._initialised:
            return
        self.plugin_loader.discover()
        logger.info(
            "SecurityEngine started. %d modules loaded.", len(self.plugin_loader)
        )
        self._initialised = True

    async def shutdown(self) -> None:
        """Tear down module resources gracefully."""
        logger.info("SecurityEngine shutting down.")

    # ── Single-module execution ───────────────────────────────────────────────

    async def run_module(
        self,
        module_name: str,
        target: str,
        **kwargs: Any,
    ) -> ModuleResult:
        """
        Execute a single module against *target*.

        Args:
            module_name: Registered name of the module to execute.
            target:      Asset value to analyse.
            **kwargs:    Module-specific options.

        Returns:
            ModuleResult containing findings and status.

        Raises:
            ValueError: If the module is not found.
        """
        module = self.plugin_loader.get_instance(module_name)
        if module is None:
            raise ValueError(f"Module '{module_name}' is not registered.")

        valid = await module.validate_target(target)
        if not valid:
            return ModuleResult(
                module_name=module_name,
                target=target,
                status=ModuleStatus.SKIPPED,
                errors=[f"Target validation failed for '{target}'."],
            )

        logger.info("Running module '%s' against target '%s'.", module_name, target)
        try:
            result = await module.run(target, **kwargs)
        except Exception as exc:
            logger.exception("Module '%s' raised an unhandled exception.", module_name)
            result = ModuleResult(
                module_name=module_name,
                target=target,
                status=ModuleStatus.FAILED,
                errors=[str(exc)],
            )

        return result

    # ── Full scan pipeline ────────────────────────────────────────────────────

    async def run_full_scan(
        self,
        target_id: str,
        target_value: str,
        scan_result_id: str,
        module_names: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Execute a complete scan pipeline against a target.

        Discovers assets, analyses network services, and returns aggregated results.
        Persists findings to the database.

        Args:
            target_id:      Database ID of the Target record.
            target_value:   The actual value to scan (domain, IP, …).
            scan_result_id: Database ID of the ScanResult tracking this run.
            module_names:   Explicit list of modules to run; defaults to all.

        Returns:
            Dict summary of all module results.
        """
        if module_names is None:
            module_names = self.plugin_loader.registered_names

        collected: Dict[str, Any] = {}
        errors: List[str] = []

        for name in module_names:
            try:
                result = await self.run_module(name, target_value)
                collected[name] = result.to_dict()
                if result.status == ModuleStatus.SUCCESS:
                    await self._persist_findings(target_id, result)
            except Exception as exc:
                logger.error("Error running module '%s': %s", name, exc)
                errors.append(f"{name}: {exc}")

        summary = {
            "target": target_value,
            "modules_run": module_names,
            "results": collected,
            "errors": errors,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }

        await self._update_scan_result(scan_result_id, summary)
        return summary

    # ── Asset / service persistence ───────────────────────────────────────────

    async def _persist_findings(
        self, target_id: str, result: ModuleResult
    ) -> None:
        """Write discovered assets and services from a ModuleResult to the DB."""
        async with get_db_session() as session:
            # Persist discovered subdomains / IPs as Asset rows
            for asset_data in result.data.get("assets", []):
                asset = Asset(
                    target_id=target_id,
                    value=asset_data.get("value", ""),
                    asset_type=asset_data.get("type", "unknown"),
                    ip_address=asset_data.get("ip_address"),
                    hostname=asset_data.get("hostname"),
                    is_alive=asset_data.get("is_alive"),
                    extra_metadata=asset_data.get("metadata"),
                )
                session.add(asset)
                await session.flush()  # get auto-assigned id

                # Persist services found on this asset
                for svc_data in asset_data.get("services", []):
                    service = Service(
                        asset_id=asset.id,
                        port=svc_data.get("port", 0),
                        protocol=svc_data.get("protocol", "tcp"),
                        service_name=svc_data.get("service_name"),
                        product=svc_data.get("product"),
                        version=svc_data.get("version"),
                        banner=svc_data.get("banner"),
                        is_open=svc_data.get("is_open", True),
                    )
                    session.add(service)

    async def _update_scan_result(
        self, scan_result_id: str, summary: Dict[str, Any]
    ) -> None:
        """Mark a ScanResult as completed and store its summary."""
        async with get_db_session() as session:
            scan: Optional[ScanResult] = await session.get(ScanResult, scan_result_id)
            if scan:
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.now(timezone.utc)
                scan.results = summary

    # ── Introspection ─────────────────────────────────────────────────────────

    def list_modules(self) -> List[Dict[str, str]]:
        """Return metadata for all registered modules."""
        return self.plugin_loader.list_all()

    def get_module_info(self, name: str) -> Optional[Dict[str, str]]:
        """Return metadata for a single module by name."""
        cls = self.plugin_loader.get_module(name)
        if cls is None:
            return None
        return {
            "name": cls.name,
            "category": cls.category,
            "description": cls.description,
            "version": cls.version,
            "requires": cls.requires,
        }


# ─── Module-level singleton (used by API and workers) ─────────────────────────

_engine: Optional[SecurityEngine] = None


def get_engine() -> SecurityEngine:
    """Return the global SecurityEngine singleton, creating it if necessary."""
    global _engine
    if _engine is None:
        _engine = SecurityEngine()
    return _engine
