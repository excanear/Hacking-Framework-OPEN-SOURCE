"""
Base module contract for all Security Research Platform modules.

Every module must:
  - Inherit from SecurityModule
  - Declare class-level `name` and `category` attributes
  - Implement async `run(target: str, **kwargs) -> ModuleResult`

The plugin loader discovers and registers concrete SecurityModule subclasses
automatically; no manual registration is required.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


logger = logging.getLogger(__name__)


# ─── Result types ─────────────────────────────────────────────────────────────


class ModuleStatus(str, Enum):
    """Terminal state of a module execution."""

    SUCCESS = "success"
    PARTIAL = "partial"   # completed with warnings / incomplete data
    FAILED = "failed"
    SKIPPED = "skipped"   # prerequisites not met; execution not attempted


@dataclass
class ModuleResult:
    """
    Structured output returned by every module run.

    Attributes:
        module_name: Name of the module that produced this result.
        target:      The target value that was analysed.
        status:      Final execution status.
        data:        Arbitrary dict of findings (schema defined by each module).
        errors:      List of non-fatal error messages encountered during the run.
        metadata:    Optional extra context (timing, version info, etc.).
    """

    module_name: str
    target: str
    status: ModuleStatus
    data: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the result to a plain dict (JSON-compatible)."""
        return {
            "module_name": self.module_name,
            "target": self.target,
            "status": self.status.value,
            "data": self.data,
            "errors": self.errors,
            "metadata": self.metadata,
        }


# ─── Abstract base class ──────────────────────────────────────────────────────


class SecurityModule(ABC):
    """
    Abstract base for all platform modules.

    Class attributes (required on every concrete subclass):
        name     : Unique machine-readable identifier  (e.g. "subdomain_discovery")
        category : Logical grouping                    (e.g. "discovery", "network", "osint")

    Optional class attributes:
        description : Human-readable purpose summary.
        version     : Module version string.
        requires    : List of prerequisite module names that must run first.
    """

    name: str = "unnamed_module"
    category: str = "generic"
    description: str = ""
    version: str = "1.0.0"
    requires: List[str] = []

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if not getattr(cls, "__abstractmethods__", None):
            # Warn if a concrete module forgot to set name/category
            if cls.name == "unnamed_module":
                logger.warning(
                    "Module %s does not define a 'name' class attribute.", cls.__name__
                )

    # ── Public interface ──────────────────────────────────────────────────────

    @abstractmethod
    async def run(self, target: str, **kwargs: Any) -> ModuleResult:
        """
        Execute the module against *target*.

        Args:
            target:   The asset to analyse (domain, IP, CIDR, URL …).
            **kwargs: Module-specific options passed from the workflow engine.

        Returns:
            ModuleResult describing what was found.
        """

    async def validate_target(self, target: str) -> bool:
        """
        Pre-flight check on the target string.

        Override in subclasses to add module-specific validation.
        Default implementation accepts any non-empty string.
        """
        return bool(target and target.strip())

    async def setup(self) -> None:
        """Optional async setup hook called once before the first run."""

    async def teardown(self) -> None:
        """Optional async teardown hook called after the last run."""

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _make_result(
        self,
        target: str,
        status: ModuleStatus = ModuleStatus.SUCCESS,
        data: Optional[Dict[str, Any]] = None,
        errors: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ModuleResult:
        """Convenience factory for building a ModuleResult."""
        return ModuleResult(
            module_name=self.name,
            target=target,
            status=status,
            data=data or {},
            errors=errors or [],
            metadata=metadata or {},
        )

    def __repr__(self) -> str:
        return f"<SecurityModule name={self.name!r} category={self.category!r}>"
