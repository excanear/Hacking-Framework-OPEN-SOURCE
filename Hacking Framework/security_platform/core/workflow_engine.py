"""
Workflow Engine — defines and executes configurable security automation pipelines.

A Workflow is an ordered sequence of Steps, each of which maps to one or more
SecurityModules.  Steps can be:
  - mandatory   : pipeline aborts if the step fails
  - optional    : failure is recorded but execution continues
  - conditional : runs only when a previous step produced specific data

The engine emits structured events at each lifecycle boundary so callers can
stream progress over WebSockets or log to the database.

Usage::

    wf = WorkflowEngine()
    workflow = wf.build_default_workflow()
    async for event in wf.execute(workflow, target="example.com", scan_id="..."):
        print(event)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncGenerator, Dict, List, Optional

from core.engine import SecurityEngine, get_engine
from modules.base_module import ModuleStatus

logger = logging.getLogger(__name__)


# ─── Workflow types ───────────────────────────────────────────────────────────


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class WorkflowStep:
    """
    A single step in a workflow pipeline.

    Attributes:
        name:          Human-readable label.
        module_names:  One or more SecurityModule names to run in this step.
        mandatory:     If True, a failure aborts the remaining pipeline.
        condition_key: If set, this step runs only when the previous results
                       dict contains a truthy value at this key.
        options:       Passed as **kwargs to each module.run().
    """

    name: str
    module_names: List[str]
    mandatory: bool = True
    condition_key: Optional[str] = None
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Workflow:
    """
    An ordered collection of WorkflowSteps with metadata.

    Workflows are defined in code (or loaded from a YAML/JSON config in future
    iterations) and passed to WorkflowEngine.execute().
    """

    name: str
    description: str = ""
    steps: List[WorkflowStep] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


@dataclass
class WorkflowEvent:
    """
    Progress event emitted by WorkflowEngine.execute().

    Consumers (API, CLI, WebSocket handler) receive these in real time.
    """

    event_type: str          # "step_start" | "step_done" | "workflow_done" | "error"
    step_name: Optional[str]
    status: StepStatus
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type,
            "step_name": self.step_name,
            "status": self.status.value,
            "data": self.data,
            "timestamp": self.timestamp,
        }


# ─── Engine ───────────────────────────────────────────────────────────────────


class WorkflowEngine:
    """Executes Workflow instances against a target using the SecurityEngine."""

    def __init__(self, engine: Optional[SecurityEngine] = None) -> None:
        self._engine = engine or get_engine()

    # ── Pre-built workflows ───────────────────────────────────────────────────

    def build_default_workflow(self) -> Workflow:
        """
        Return the standard full-pipeline workflow:

        1. Discovery  →  2. Network Analysis  →  3. OSINT
        →  4. Intelligence Correlation  →  5. Risk Scoring
        """
        return Workflow(
            name="full_security_assessment",
            description="Complete security assessment pipeline",
            steps=[
                WorkflowStep(
                    name="asset_discovery",
                    module_names=["subdomain_discovery", "dns_enumeration"],
                    mandatory=True,
                ),
                WorkflowStep(
                    name="network_analysis",
                    module_names=["port_scanner", "service_fingerprint"],
                    mandatory=False,
                ),
                WorkflowStep(
                    name="osint_collection",
                    module_names=["dns_osint"],
                    mandatory=False,
                ),
                WorkflowStep(
                    name="web_analysis",
                    module_names=["web_analyzer"],
                    mandatory=False,
                ),
            ],
            tags=["full", "default"],
        )

    def build_quick_workflow(self) -> Workflow:
        """Lightweight discovery-only workflow for fast initial recon."""
        return Workflow(
            name="quick_discovery",
            description="Fast subdomain and DNS discovery only",
            steps=[
                WorkflowStep(
                    name="asset_discovery",
                    module_names=["subdomain_discovery", "dns_enumeration"],
                    mandatory=True,
                ),
            ],
            tags=["quick"],
        )

    # ── Execution ─────────────────────────────────────────────────────────────

    async def execute(
        self,
        workflow: Workflow,
        target: str,
        scan_id: Optional[str] = None,
        **global_options: Any,
    ) -> AsyncGenerator[WorkflowEvent, None]:
        """
        Execute *workflow* against *target*, yielding WorkflowEvent objects.

        The caller can iterate over events to stream progress::

            async for event in engine.execute(workflow, "example.com"):
                await websocket.send_json(event.to_dict())

        Args:
            workflow:        The Workflow to execute.
            target:          Asset value to scan.
            scan_id:         Optional scan record ID for DB updates.
            **global_options: Additional kwargs forwarded to every module.

        Yields:
            WorkflowEvent for each step start/completion and the final summary.
        """
        accumulated: Dict[str, Any] = {}
        pipeline_failed = False

        logger.info(
            "Starting workflow '%s' against target '%s'.", workflow.name, target
        )

        for step in workflow.steps:
            # ── Conditional check ──────────────────────────────────────────
            if step.condition_key and not accumulated.get(step.condition_key):
                logger.info("Skipping step '%s': condition not met.", step.name)
                yield WorkflowEvent(
                    event_type="step_start",
                    step_name=step.name,
                    status=StepStatus.SKIPPED,
                )
                continue

            # ── Emit step start ────────────────────────────────────────────
            yield WorkflowEvent(
                event_type="step_start",
                step_name=step.name,
                status=StepStatus.RUNNING,
                data={"modules": step.module_names},
            )

            step_results: Dict[str, Any] = {}
            step_failed = False

            for module_name in step.module_names:
                options = {**global_options, **step.options}
                try:
                    result = await self._engine.run_module(
                        module_name, target, **options
                    )
                    step_results[module_name] = result.to_dict()
                    if result.status == ModuleStatus.FAILED:
                        step_failed = True
                except Exception as exc:
                    logger.error(
                        "Unhandled error in module '%s': %s", module_name, exc
                    )
                    step_results[module_name] = {"status": "error", "error": str(exc)}
                    step_failed = True

            accumulated[step.name] = step_results

            # ── Emit step completion ───────────────────────────────────────
            final_status = StepStatus.FAILED if step_failed else StepStatus.SUCCESS
            yield WorkflowEvent(
                event_type="step_done",
                step_name=step.name,
                status=final_status,
                data=step_results,
            )

            if step_failed and step.mandatory:
                pipeline_failed = True
                logger.warning(
                    "Mandatory step '%s' failed — aborting pipeline.", step.name
                )
                break

        # ── Final summary event ────────────────────────────────────────────
        overall = StepStatus.FAILED if pipeline_failed else StepStatus.SUCCESS
        yield WorkflowEvent(
            event_type="workflow_done",
            step_name=None,
            status=overall,
            data={
                "workflow": workflow.name,
                "target": target,
                "scan_id": scan_id,
                "results": accumulated,
            },
        )

        logger.info(
            "Workflow '%s' finished with status: %s.", workflow.name, overall.value
        )
