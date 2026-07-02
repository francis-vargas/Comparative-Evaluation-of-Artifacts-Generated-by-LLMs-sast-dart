"""Core data models used by dart_sast."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class Finding:
    """A single security finding produced by a rule."""

    rule_id: str
    cwe: str
    title: str
    severity: str
    message: str
    file: str
    line: int
    column: int
    evidence: str
    recommendation: str
    confidence: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SourceFile:
    """Represents a Dart or project metadata file to be scanned."""

    path: Path
    relative_path: str
    content: str

    @property
    def lines(self) -> List[str]:
        return self.content.splitlines()
