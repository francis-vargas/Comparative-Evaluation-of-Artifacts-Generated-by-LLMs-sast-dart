"""Base classes and helper functions for rules."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, List, Pattern

from dart_sast.models import Finding, SourceFile


@dataclass(frozen=True)
class RuleMetadata:
    """Descriptive metadata for one SAST rule."""

    rule_id: str
    cwe: str
    title: str
    severity: str
    recommendation: str
    confidence: str = "medium"


class Rule:
    """Base class for all rules.

    Rules receive a SourceFile and return zero or more findings. This small
    contract makes rule development simple and avoids coupling rules to CLI,
    reporting, or filesystem concerns.
    """

    metadata: RuleMetadata
    file_kinds = ("dart",)

    def scan(self, source: SourceFile) -> List[Finding]:
        raise NotImplementedError

    def finding(self, source: SourceFile, line_no: int, column: int, evidence: str, message: str) -> Finding:
        return Finding(
            rule_id=self.metadata.rule_id,
            cwe=self.metadata.cwe,
            title=self.metadata.title,
            severity=self.metadata.severity,
            message=message,
            file=source.relative_path,
            line=line_no,
            column=column,
            evidence=evidence.strip()[:240],
            recommendation=self.metadata.recommendation,
            confidence=self.metadata.confidence,
        )


def line_matches(source: SourceFile, pattern: Pattern[str]) -> Iterable[tuple[int, int, str, re.Match[str]]]:
    """Yield line number, column, line text and match for regex matches."""
    for idx, line in enumerate(source.lines, start=1):
        for match in pattern.finditer(line):
            yield idx, match.start() + 1, line, match


def is_comment_only(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("//") or stripped.startswith("*")
