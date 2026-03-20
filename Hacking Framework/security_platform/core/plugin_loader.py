"""
Plugin loader — automatically discovers and registers SecurityModule subclasses.

The loader recursively imports every Python file found under the configured
modules directory.  Any class that:
  - inherits from SecurityModule
  - is concrete (not abstract)
  - defines a unique `name` attribute

…is registered and retrievable by name or category.

Usage::

    loader = PluginLoader()
    loader.discover()

    # Retrieve by name
    module = loader.get_module("subdomain_discovery")

    # Retrieve all discovery modules
    modules = loader.get_by_category("discovery")
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import logging
import pkgutil
from pathlib import Path
from typing import Dict, List, Optional, Type

from modules.base_module import SecurityModule

logger = logging.getLogger(__name__)


class PluginLoader:
    """
    Discovers and manages SecurityModule plugins.

    Attributes:
        modules_dir: Root directory to scan for modules.
        _registry:   name → class mapping for all loaded modules.
    """

    def __init__(self, modules_dir: Optional[Path] = None) -> None:
        self.modules_dir: Path = modules_dir or Path(__file__).parent.parent / "modules"
        self._registry: Dict[str, Type[SecurityModule]] = {}

    # ── Discovery ─────────────────────────────────────────────────────────────

    def discover(self) -> None:
        """
        Walk `modules_dir` and import every .py file.

        After import, inspect each module's namespace for concrete
        SecurityModule subclasses and register them.
        """
        logger.info("Discovering plugins in: %s", self.modules_dir)
        self._walk_and_import(self.modules_dir)
        logger.info(
            "Plugin discovery complete. Registered modules: %s",
            list(self._registry.keys()),
        )

    def _walk_and_import(self, directory: Path) -> None:
        """Recursively import all Python packages and modules under *directory*."""
        if not directory.is_dir():
            logger.warning("Modules directory does not exist: %s", directory)
            return

        # Convert filesystem path to Python dotted package path
        project_root = directory.parent
        for path in sorted(directory.rglob("*.py")):
            if path.name.startswith("_"):
                continue  # skip __init__.py, __pycache__, etc.

            # Build dotted module path relative to project root
            relative = path.relative_to(project_root)
            dotted = ".".join(relative.with_suffix("").parts)

            try:
                module = importlib.import_module(dotted)
            except Exception as exc:
                logger.error("Failed to import plugin module %s: %s", dotted, exc)
                continue

            self._register_from_module(module)

    def _register_from_module(self, module: object) -> None:
        """Scan *module* namespace and register SecurityModule subclasses."""
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            if (
                issubclass(obj, SecurityModule)
                and obj is not SecurityModule
                and not inspect.isabstract(obj)
            ):
                plugin_name = obj.name
                if plugin_name == "unnamed_module":
                    logger.warning(
                        "Skipping module class %s: no 'name' defined.", obj.__name__
                    )
                    continue
                if plugin_name in self._registry:
                    logger.debug(
                        "Module '%s' already registered; skipping duplicate.", plugin_name
                    )
                    continue
                self._registry[plugin_name] = obj
                logger.debug("Registered module: %s (category=%s)", plugin_name, obj.category)

    # ── Registry access ───────────────────────────────────────────────────────

    def get_module(self, name: str) -> Optional[Type[SecurityModule]]:
        """Return the module class registered under *name*, or None."""
        return self._registry.get(name)

    def get_instance(self, name: str) -> Optional[SecurityModule]:
        """Return a fresh instance of the module registered under *name*, or None."""
        cls = self.get_module(name)
        return cls() if cls is not None else None

    def get_by_category(self, category: str) -> List[Type[SecurityModule]]:
        """Return all module classes belonging to *category*."""
        return [cls for cls in self._registry.values() if cls.category == category]

    def list_all(self) -> List[Dict[str, str]]:
        """Return a serialisable summary of every registered module."""
        return [
            {
                "name": cls.name,
                "category": cls.category,
                "description": cls.description,
                "version": cls.version,
            }
            for cls in self._registry.values()
        ]

    @property
    def registered_names(self) -> List[str]:
        """Sorted list of all registered module names."""
        return sorted(self._registry.keys())

    def __len__(self) -> int:
        return len(self._registry)

    def __repr__(self) -> str:
        return f"<PluginLoader modules={len(self)} dir={self.modules_dir}>"
