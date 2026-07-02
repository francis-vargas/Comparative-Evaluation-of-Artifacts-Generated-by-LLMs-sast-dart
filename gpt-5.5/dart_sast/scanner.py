"""Filesystem discovery and scan orchestration."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Sequence

from dart_sast.models import Finding, SourceFile
from dart_sast.rules import ALL_RULES
from dart_sast.rules.base import Rule

SUPPORTED_NAMES = {"pubspec.yaml": "pubspec", "AndroidManifest.xml": "manifest"}


def classify(path: Path) -> str | None:
    if path.suffix == ".dart":
        return "dart"
    return SUPPORTED_NAMES.get(path.name)


def discover(target: Path) -> List[Path]:
    """Return supported files under a file or directory target."""
    if target.is_file():
        return [target] if classify(target) else []
    if not target.exists():
        raise FileNotFoundError(f"Target not found: {target}")
    ignored = {".dart_tool", "build", ".git", ".idea"}
    files: List[Path] = []
    for path in target.rglob("*"):
        if any(part in ignored for part in path.parts):
            continue
        if path.is_file() and classify(path):
            files.append(path)
    return sorted(files)


def load_source(path: Path, root: Path) -> SourceFile:
    content = path.read_text(encoding="utf-8", errors="replace")
    rel = str(path.relative_to(root)) if root.is_dir() else path.name
    return SourceFile(path=path, relative_path=rel, content=content)


def scan_target(target: Path, rules: Sequence[Rule] = ALL_RULES, exclude_rule_ids: Iterable[str] = ()) -> List[Finding]:
    """Scan a Dart file/project and return findings."""
    target = target.resolve()
    root = target if target.is_dir() else target.parent
    excluded = set(exclude_rule_ids)
    findings: List[Finding] = []
    for path in discover(target):
        kind = classify(path)
        if not kind:
            continue
        source = load_source(path, root)
        for rule in rules:
            if rule.metadata.rule_id in excluded or kind not in rule.file_kinds:
                continue
            findings.extend(rule.scan(source))
    return sorted(findings, key=lambda f: (f.file, f.line, f.rule_id))
