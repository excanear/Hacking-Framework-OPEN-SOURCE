"""
Scan Worker

Celery tasks responsible for executing security scan pipelines.

Task routing: all tasks in this module route to the `scans` queue.

Usage (from Python code — prefer using core.scheduler.Scheduler):

    from workers.scan_worker import run_full_scan_task
    result = run_full_scan_task.apply_async(kwargs={...}, queue="scans")
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from celery import Task
from celery.exceptions import SoftTimeLimitExceeded

from workers.worker_manager import celery_app

logger = logging.getLogger(__name__)


def _run_async(coro):
    """Run an async coroutine safely regardless of whether an event loop is running."""
    try:
        asyncio.get_running_loop()
        # Already inside an event loop (Celery eager mode in FastAPI) — use a thread
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    except RuntimeError:
        # No running loop — run directly
        return asyncio.run(coro)


# ─── Base task with engine initialisation ─────────────────────────────────────

class EngineTask(Task):
    """
    Celery Task subclass that lazily initialises the SecurityEngine.

    The engine (and its plugin loader) is initialised once per worker process,
    not once per task, for performance.
    """

    _engine = None

    @property
    def engine(self):
        if self._engine is None:
            from core.engine import SecurityEngine
            self._engine = SecurityEngine()
            _run_async(self._engine.startup())
        return self._engine


# ─── Tasks ────────────────────────────────────────────────────────────────────

@celery_app.task(
    bind=True,
    base=EngineTask,
    name="workers.scan_worker.run_full_scan_task",
    queue="scans",
    max_retries=2,
    default_retry_delay=30,
    soft_time_limit=300,
    time_limit=360,
)
def run_full_scan_task(
    self: EngineTask,
    target_id: str,
    target_value: str,
    scan_result_id: str,
    module_names: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Execute a full security scan pipeline for a single target.

    Args:
        target_id:      Target database record ID.
        target_value:   Domain / IP address to scan.
        scan_result_id: ScanResult database record ID to update.
        module_names:   Explicit list of modules to run (None = all registered).

    Returns:
        Dict summary of all module results.
    """
    logger.info(
        "[scan_worker] Starting full scan: target='%s' scan_id='%s'",
        target_value, scan_result_id,
    )

    # Update scan status to RUNNING
    _set_scan_status(scan_result_id, "running")

    try:
        summary = _run_async(
            self.engine.run_full_scan(
                target_id=target_id,
                target_value=target_value,
                scan_result_id=scan_result_id,
                module_names=module_names,
            )
        )
        logger.info(
            "[scan_worker] Scan completed: scan_id='%s'", scan_result_id
        )
        return summary

    except SoftTimeLimitExceeded:
        logger.warning("[scan_worker] Scan timed out: scan_id='%s'", scan_result_id)
        _set_scan_status(scan_result_id, "failed", error="Task soft time limit exceeded.")
        raise

    except Exception as exc:
        logger.exception("[scan_worker] Scan failed: scan_id='%s'", scan_result_id)
        _set_scan_status(scan_result_id, "failed", error=str(exc))
        # Retry on transient errors
        raise self.retry(exc=exc)


@celery_app.task(
    bind=True,
    base=EngineTask,
    name="workers.scan_worker.run_module_task",
    queue="scans",
    max_retries=1,
    soft_time_limit=120,
)
def run_module_task(
    self: EngineTask,
    module_name: str,
    target_value: str,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Execute a single SecurityModule against a target.

    Args:
        module_name:  Registered module name.
        target_value: Target to scan.
        options:      Module-specific options dict.

    Returns:
        Serialised ModuleResult dict.
    """
    options = options or {}
    logger.info(
        "[scan_worker] Running module '%s' against '%s'.", module_name, target_value
    )
    try:
        result = _run_async(
            self.engine.run_module(module_name, target_value, **options)
        )
        return result.to_dict()
    except Exception as exc:
        logger.exception("[scan_worker] Module task failed.")
        raise self.retry(exc=exc)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _set_scan_status(
    scan_result_id: str,
    status: str,
    error: Optional[str] = None,
) -> None:
    """Update ScanResult status synchronously from within a worker task."""
    try:
        from database.database import AsyncSessionLocal
        from database.models import ScanResult, ScanStatus

        async def _update():
            async with AsyncSessionLocal() as session:
                scan: Optional[ScanResult] = await session.get(
                    ScanResult, scan_result_id
                )
                if scan:
                    scan.status = ScanStatus(status)
                    if status == "running":
                        scan.started_at = datetime.now(timezone.utc)
                    if error:
                        scan.error_message = error
                    await session.commit()

        _run_async(_update())
    except Exception as exc:
        logger.error("Failed to update scan status in DB: %s", exc)
