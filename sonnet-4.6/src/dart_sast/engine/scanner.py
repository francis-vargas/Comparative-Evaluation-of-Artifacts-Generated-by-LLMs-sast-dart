"""File-system walking and rule execution orchestration."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from typing import Iterable, List, Sequence, Type

from dart_sast.engine.finding import Finding
from dart_sast.engine.pubspec import parse_pubspec
from dart_sast.engine.rule import FileContext, ManifestContext, PubspecContext, Rule

DEFAULT_EXCLUDES = (
    ".git/*",
    ".dart_tool/*",
    "build/*",
    ".pub-cache/*",
    "*.g.dart",
    "*.freezed.dart",
    "*.mocks.dart",
)


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    scanned_files: int = 0
    scanned_dart_files: int = 0
    pubspec_files: int = 0
    errors: List[str] = field(default_factory=list)


def _is_excluded(relative_path: str, exclude_patterns: Sequence[str]) -> bool:
    normalized = relative_path.replace(os.sep, "/")
    for pattern in exclude_patterns:
        if fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch(
            normalized, f"*/{pattern}"
        ):
            return True
    return False


def _iter_target_files(root: str, exclude_patterns: Sequence[str]) -> Iterable[str]:
    if os.path.isfile(root):
        yield root
        return

    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        # Prune excluded directories in-place for efficiency.
        dirnames[:] = [
            d
            for d in dirnames
            if not _is_excluded(
                os.path.join(rel_dir, d) if rel_dir != "." else d, exclude_patterns
            )
        ]
        for filename in filenames:
            if not (
                filename.endswith(".dart")
                or filename == "pubspec.yaml"
                or filename == "AndroidManifest.xml"
            ):
                continue
            rel_path = os.path.join(rel_dir, filename) if rel_dir != "." else filename
            if _is_excluded(rel_path, exclude_patterns):
                continue
            yield os.path.join(dirpath, filename)


class Scanner:
    """Runs a set of rules against a file or directory tree."""

    def __init__(
        self,
        rules: Sequence[Type[Rule]],
        exclude_patterns: Sequence[str] = (),
        base_path: str | None = None,
    ) -> None:
        self.rule_instances: List[Rule] = [rule_cls() for rule_cls in rules]
        self.exclude_patterns = tuple(DEFAULT_EXCLUDES) + tuple(exclude_patterns)
        self.base_path = base_path

    def scan(self, target: str) -> ScanResult:
        result = ScanResult()
        root_for_relpath = self.base_path or (
            target if os.path.isdir(target) else os.path.dirname(target) or "."
        )

        dart_rules = [
            r for r in self.rule_instances if not r.targets_pubspec and not r.targets_manifest
        ]
        pubspec_rules = [r for r in self.rule_instances if r.targets_pubspec]
        manifest_rules = [r for r in self.rule_instances if r.targets_manifest]

        for file_path in _iter_target_files(target, self.exclude_patterns):
            relative_path = os.path.relpath(file_path, root_for_relpath)
            result.scanned_files += 1
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError as exc:  # pragma: no cover - defensive
                result.errors.append(f"Could not read {file_path}: {exc}")
                continue

            if os.path.basename(file_path) == "pubspec.yaml":
                result.pubspec_files += 1
                try:
                    data = parse_pubspec(text)
                except Exception as exc:  # noqa: BLE001 - parser is best-effort
                    result.errors.append(f"Could not parse {file_path}: {exc}")
                    data = {}
                ctx = PubspecContext(
                    path=file_path, relative_path=relative_path, raw_text=text, data=data
                )
                for rule in pubspec_rules:
                    result.findings.extend(rule.analyze_pubspec(ctx))
                continue

            if os.path.basename(file_path) == "AndroidManifest.xml":
                manifest_ctx = ManifestContext(
                    path=file_path,
                    relative_path=relative_path,
                    text=text,
                    lines=text.splitlines(),
                )
                for rule in manifest_rules:
                    result.findings.extend(rule.analyze_manifest(manifest_ctx))
                continue

            result.scanned_dart_files += 1
            lines = text.splitlines()
            ctx = FileContext(
                path=file_path, text=text, lines=lines, relative_path=relative_path
            )
            for rule in dart_rules:
                result.findings.extend(rule.analyze_file(ctx))

        result.findings.sort(key=lambda f: (f.file_path, f.line, f.rule_id))
        return result
