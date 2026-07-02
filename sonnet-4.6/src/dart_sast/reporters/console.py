"""Human-readable console output."""

from __future__ import annotations

from dart_sast.engine.finding import Severity
from dart_sast.engine.scanner import ScanResult

_SEVERITY_COLOR = {
    Severity.CRITICAL: "\033[1;41m",  # white on red
    Severity.HIGH: "\033[1;31m",  # bold red
    Severity.MEDIUM: "\033[1;33m",  # bold yellow
    Severity.LOW: "\033[0;36m",  # cyan
    Severity.INFO: "\033[0;37m",  # grey
}
_RESET = "\033[0m"


def render(result: ScanResult, use_color: bool = True) -> str:
    lines: list[str] = []

    def colorize(text: str, severity: Severity) -> str:
        if not use_color:
            return text
        return f"{_SEVERITY_COLOR.get(severity, '')}{text}{_RESET}"

    lines.append("=" * 78)
    lines.append("dart_sast - Static Application Security Testing for Dart/Flutter")
    lines.append("=" * 78)

    if not result.findings:
        lines.append("")
        lines.append("No issues found. \u2705")
    else:
        by_file: dict[str, list] = {}
        for finding in result.findings:
            by_file.setdefault(finding.file_path, []).append(finding)

        for file_path, findings in by_file.items():
            lines.append("")
            lines.append(f"{file_path}")
            lines.append("-" * len(file_path))
            for f in findings:
                header = f"[{f.severity.value}] {f.rule_id} ({f.cwe}) - {f.title}"
                lines.append(f"  {colorize(header, f.severity)}")
                lines.append(f"    line {f.line}, col {f.column}: {f.snippet}")
                lines.append(f"    {f.description}")
                lines.append(f"    -> {f.recommendation}")
                lines.append("")

    lines.append("=" * 78)
    lines.append("Summary")
    lines.append("=" * 78)
    counts = {s: 0 for s in Severity}
    for f in result.findings:
        counts[f.severity] += 1
    for severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        if counts[severity]:
            lines.append(colorize(f"  {severity.value}: {counts[severity]}", severity))
    lines.append(f"  TOTAL findings: {len(result.findings)}")
    lines.append(
        f"  Files scanned: {result.scanned_files} "
        f"(.dart: {result.scanned_dart_files}, pubspec.yaml: {result.pubspec_files})"
    )
    if result.errors:
        lines.append("")
        lines.append("Errors:")
        for err in result.errors:
            lines.append(f"  - {err}")

    return "\n".join(lines)
