"""
Scheduler — periodic / deferred task scheduling using APScheduler (optional)
and direct Celery delay integration.

The Scheduler wraps Celery task dispatch so the rest of the platform never
imports Celery directly.  It also registers periodic jobs (e.g. nightly CVE
feed refresh) via APScheduler when the `apscheduler` package is available.

Usage::

    scheduler = Scheduler()
    task_id = scheduler.enqueue_scan(target_id="...", target="example.com")
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class Scheduler:
    """
    High-level task dispatcher.

    Delegates actual async execution to Celery workers via the workers package.
    """

    # ── Scan tasks ────────────────────────────────────────────────────────────

    def enqueue_scan(
        self,
        target_id: str,
        target_value: str,
        scan_result_id: str,
        module_names: Optional[List[str]] = None,
        priority: int = 5,
    ) -> str:
        """
        Enqueue a full scan task on the Celery workers queue.

        Args:
            target_id:      Target DB record ID.
            target_value:   Domain / IP to scan.
            scan_result_id: ScanResult DB record ID to update on completion.
            module_names:   Optional explicit module list; defaults to all.
            priority:       Celery task priority (0 = highest, 9 = lowest).

        Returns:
            Celery task ID string.
        """
        from workers.scan_worker import run_full_scan_task  # lazy import

        result = run_full_scan_task.apply_async(
            kwargs={
                "target_id": target_id,
                "target_value": target_value,
                "scan_result_id": scan_result_id,
                "module_names": module_names,
            },
            priority=priority,
        )
        logger.info(
            "Enqueued full scan task %s for target '%s'.", result.id, target_value
        )
        return result.id

    def enqueue_analysis(
        self,
        scan_result_id: str,
        priority: int = 5,
    ) -> str:
        """
        Enqueue a post-scan analysis (risk scoring, intelligence correlation) task.

        Args:
            scan_result_id: Completed ScanResult to analyse.
            priority:       Celery priority.

        Returns:
            Celery task ID string.
        """
        from workers.analysis_worker import run_analysis_task  # lazy import

        result = run_analysis_task.apply_async(
            kwargs={"scan_result_id": scan_result_id},
            priority=priority,
        )
        logger.info(
            "Enqueued analysis task %s for scan '%s'.", result.id, scan_result_id
        )
        return result.id

    # ── Task status ───────────────────────────────────────────────────────────

    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """
        Return the current status of a Celery task.

        Returns a dict with keys: task_id, state, result, traceback.
        """
        from workers.worker_manager import celery_app  # lazy import

        task = celery_app.AsyncResult(task_id)
        return {
            "task_id": task_id,
            "state": task.state,
            "result": task.result if task.ready() else None,
            "traceback": task.traceback,
        }

    def revoke_task(self, task_id: str, terminate: bool = False) -> None:
        """
        Cancel a queued or running task.

        Args:
            task_id:   Celery task ID to cancel.
            terminate: If True, send SIGTERM to the worker executing the task.
        """
        from workers.worker_manager import celery_app  # lazy import

        celery_app.control.revoke(task_id, terminate=terminate)
        logger.info("Revoked task %s (terminate=%s).", task_id, terminate)
