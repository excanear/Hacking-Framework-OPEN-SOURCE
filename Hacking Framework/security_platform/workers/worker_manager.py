"""
Celery application factory and worker management utilities.

The Celery app is the single broker-connection entry point shared by:
  - scan_worker     (scanning tasks)
  - analysis_worker (intelligence / risk scoring tasks)

Workers are started with::

    celery -A workers.worker_manager worker --loglevel=info --concurrency=4 -Q scans,analysis

To monitor tasks via Flower::

    celery -A workers.worker_manager flower --port=5555
"""

from __future__ import annotations

import logging

from celery import Celery
from celery.signals import worker_ready, worker_shutdown

from config.settings import redis_settings, settings

logger = logging.getLogger(__name__)


# ─── Celery application ───────────────────────────────────────────────────────

# In dev mode (CELERY_TASK_ALWAYS_EAGER=true) tasks run in-process without Redis.
_broker = "memory://" if settings.celery_task_always_eager else redis_settings.celery_broker_url
_backend = "cache+memory://" if settings.celery_task_always_eager else redis_settings.celery_broker_url

celery_app = Celery(
    "security_platform",
    broker=_broker,
    backend=_backend,
    include=[
        "workers.scan_worker",
        "workers.analysis_worker",
    ],
)

# ─── Celery configuration ─────────────────────────────────────────────────────

celery_app.conf.update(
    # Serialisation
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    # Time limits (hard limit kills the worker process; soft sends SIGTERM first)
    task_soft_time_limit=settings.scan_timeout_seconds,
    task_time_limit=settings.scan_timeout_seconds + 60,
    # Result expiry
    result_expires=86400,          # 24 h
    # Acknowledgement — ack only after task completes so work is not lost
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    # Priority queues
    task_default_queue="default",
    task_queues={
        "scans":    {"exchange": "scans",    "binding_key": "scans"},
        "analysis": {"exchange": "analysis", "binding_key": "analysis"},
        "default":  {"exchange": "default",  "binding_key": "default"},
    },
    task_default_priority=5,
    broker_transport_options={
        "priority_steps": list(range(10)),
        "sep": ":",
        "queue_order_strategy": "priority",
    },
    # Worker settings
    worker_prefetch_multiplier=1,   # one task at a time per worker slot
    worker_max_tasks_per_child=100, # recycle workers periodically to avoid leaks
    # Beat schedule (optional periodic tasks)
    beat_schedule={},
    # Dev / eager mode: tasks execute synchronously in the calling process
    task_always_eager=settings.celery_task_always_eager,
    task_eager_propagates=settings.celery_task_always_eager,
)


# ─── Worker lifecycle signals ─────────────────────────────────────────────────

@worker_ready.connect
def on_worker_ready(sender, **kwargs):
    logger.info("Celery worker '%s' is ready and accepting tasks.", sender)


@worker_shutdown.connect
def on_worker_shutdown(sender, **kwargs):
    logger.info("Celery worker '%s' is shutting down.", sender)
