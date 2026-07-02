"""Base classes that concrete detection rules build on.

Design rationale (SeloS - Sustentabilidade)
--------------------------------------------
Each rule is an independent, self-contained class living in its own module
under ``dart_sast/rules/``. This keeps the codebase modular: adding a new
check means dropping a new file in that package and registering it with the
``@register_rule`` decorator (see ``registry.py``) -- no other file needs to
change. Two convenience base classes cover the overwhelming majority of
static-analysis patterns needed for a regex/heuristic-based SAST tool:

* ``RegexRule``     -- flags every source line matching one or more regular
                        expressions (used for almost all CWEs in this tool).
* ``PubspecRule``   -- inspects the parsed ``pubspec.yaml`` dependency map
                        (used for CWE-1104, unmaintained third-party
                        components).

Both inherit from the abstract ``Rule`` class, so power users can still
implement fully custom analysis (e.g. multi-line, AST-like heuristics) by
subclassing ``Rule`` directly and overriding ``analyze``.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Iterable, Pattern, Sequence

from dart_sast.engine.finding import Finding, Severity


@dataclass(frozen=True)
class FileContext:
    """Everything a rule needs to analyze a single Dart source file."""

    path: str
    text: str
    lines: Sequence[str]
    relative_path: str


@dataclass(frozen=True)
class PubspecContext:
    """Parsed pubspec.yaml information handed to pubspec-aware rules."""

    path: str
    relative_path: str
    raw_text: str
    data: dict


@dataclass(frozen=True)
class ManifestContext:
    """AndroidManifest.xml text handed to manifest-aware rules."""

    path: str
    relative_path: str
    text: str
    lines: Sequence[str]


class Rule(ABC):
    """Abstract base class every detection rule must implement."""

    #: Short, stable, unique identifier, e.g. "DART-SAST-CWE798".
    rule_id: str = ""
    #: CWE identifier this rule detects, e.g. "CWE-798".
    cwe: str = ""
    title: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    recommendation: str = ""
    references: tuple[str, ...] = ()
    #: If True, the rule is evaluated against pubspec.yaml instead of .dart files.
    targets_pubspec: bool = False
    #: If True, the rule is evaluated against AndroidManifest.xml instead of .dart files.
    targets_manifest: bool = False

    def analyze_file(self, context: FileContext) -> Iterable[Finding]:
        """Analyze a Dart source file. Override for .dart-based rules."""

        return ()

    def analyze_pubspec(self, context: PubspecContext) -> Iterable[Finding]:
        """Analyze pubspec.yaml. Override for dependency-based rules."""

        return ()

    def analyze_manifest(self, context: "ManifestContext") -> Iterable[Finding]:
        """Analyze AndroidManifest.xml. Override for manifest-based rules."""

        return ()

    def _make_finding(self, file_path: str, line: int, column: int, snippet: str) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            cwe=self.cwe,
            title=self.title,
            description=self.description,
            severity=self.severity,
            file_path=file_path,
            line=line,
            column=column,
            snippet=snippet.strip(),
            recommendation=self.recommendation,
            references=self.references,
        )


# Lines that are comments-only; used to reduce false positives across rules.
_LINE_COMMENT_RE = re.compile(r"^\s*//")
_BLOCK_COMMENT_START_RE = re.compile(r"^\s*/\*")


class RegexRule(Rule):
    """Rule implementation driven by one or more compiled regular expressions.

    Subclasses only need to set ``patterns`` (a sequence of compiled regex
    objects). Every line of every scanned ``.dart`` file is tested against
    each pattern; a match produces one ``Finding``. Lines that are entirely
    single-line comments are skipped by default to cut down on noise, but
    this can be disabled per-rule via ``skip_comment_lines = False`` for
    rules where a match inside a comment is still meaningful (rare).
    """

    patterns: Sequence[Pattern[str]] = ()
    skip_comment_lines: bool = True

    def analyze_file(self, context: FileContext) -> Iterable[Finding]:
        findings = []
        in_block_comment = False
        for idx, line in enumerate(context.lines, start=1):
            stripped = line.strip()

            # Very small block-comment tracker (best-effort; not a full parser).
            if in_block_comment:
                if "*/" in stripped:
                    in_block_comment = False
                continue
            if _BLOCK_COMMENT_START_RE.match(stripped) and "*/" not in stripped:
                in_block_comment = True
                continue

            if self.skip_comment_lines and _LINE_COMMENT_RE.match(stripped):
                continue

            for pattern in self.patterns:
                match = pattern.search(line)
                if match:
                    findings.append(
                        self._make_finding(
                            file_path=context.relative_path,
                            line=idx,
                            column=match.start() + 1,
                            snippet=line,
                        )
                    )
                    break  # avoid duplicate findings for the same line/rule
        return findings


class PubspecRule(Rule):
    """Rule implementation that inspects the parsed pubspec.yaml document."""

    targets_pubspec = True

    def analyze_pubspec(self, context: PubspecContext) -> Iterable[Finding]:  # pragma: no cover
        raise NotImplementedError


class ManifestRule(Rule):
    """Rule implementation that inspects AndroidManifest.xml."""

    targets_manifest = True

    def analyze_manifest(self, context: "ManifestContext") -> Iterable[Finding]:  # pragma: no cover
        raise NotImplementedError
