"""Data model for a single security finding."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Ordered severity levels used to rank and filter findings."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self)

    def __lt__(self, other: "Severity") -> bool:  # pragma: no cover - trivial
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


@dataclass(frozen=True)
class Finding:
    """A single occurrence of a rule violation in a scanned file."""

    rule_id: str
    cwe: str
    title: str
    description: str
    severity: Severity
    file_path: str
    line: int
    column: int = 1
    snippet: str = ""
    recommendation: str = ""
    references: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "file": self.file_path,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "recommendation": self.recommendation,
            "references": list(self.references),
        }
