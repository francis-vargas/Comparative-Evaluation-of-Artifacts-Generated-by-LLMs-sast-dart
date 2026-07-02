"""Central registry of detection rules.

Rules self-register via the ``@register_rule`` decorator at import time.
The ``load_all_rules()`` function imports every module in
``dart_sast.rules`` so that decoration side-effects populate the registry.
This indirection is what makes the rule-set extensible (SeloS): contributors
add a file, decorate the class, and it is picked up automatically without
touching a central "god file" that lists every rule by hand.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Dict, List, Type

from dart_sast.engine.rule import Rule

_REGISTRY: Dict[str, Type[Rule]] = {}


def register_rule(cls: Type[Rule]) -> Type[Rule]:
    """Class decorator that registers a Rule subclass by its rule_id."""

    if not cls.rule_id:
        raise ValueError(f"Rule {cls.__name__} must define a non-empty rule_id")
    if cls.rule_id in _REGISTRY:
        raise ValueError(f"Duplicate rule_id detected: {cls.rule_id}")
    _REGISTRY[cls.rule_id] = cls
    return cls


def load_all_rules() -> None:
    """Import every submodule of dart_sast.rules to trigger registration."""

    import dart_sast.rules as rules_pkg

    for module_info in pkgutil.iter_modules(rules_pkg.__path__):
        importlib.import_module(f"{rules_pkg.__name__}.{module_info.name}")


def get_all_rules() -> List[Type[Rule]]:
    if not _REGISTRY:
        load_all_rules()
    return list(_REGISTRY.values())


def get_rule_by_id(rule_id: str) -> Type[Rule] | None:
    if not _REGISTRY:
        load_all_rules()
    return _REGISTRY.get(rule_id)


def clear_registry_for_testing() -> None:  # pragma: no cover - test helper
    _REGISTRY.clear()
