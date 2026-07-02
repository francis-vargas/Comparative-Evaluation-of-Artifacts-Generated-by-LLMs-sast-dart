"""Command-line interface for dart_sast.

Design rationale (CI/CD-friendly flags)
----------------------------------------
The flag set below was chosen specifically to make dart_sast easy to drop
into a CI/CD pipeline:

* --format / --output   let a pipeline request machine-readable output
                          (json/sarif) written straight to a file that a
                          later step (e.g. `github/codeql-action/upload-sarif`
                          or a DefectDojo import step) can consume.
* --fail-on              controls the process exit code independently of
                          "were there findings at all", so a team can start
                          by only failing builds on CRITICAL/HIGH issues and
                          ratchet the bar down over time.
* --rules / --exclude-rules / --exclude
                          let a team temporarily silence a noisy rule or
                          skip generated/vendored paths without editing
                          source code.
* --list-rules           self-documents the tool for the SeloF ("execução
                          com exemplo mínimo de uso") criterion, and is
                          useful to sanity-check a --rules/--exclude-rules
                          filter before running a full scan.
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from dart_sast import __version__
from dart_sast.engine.finding import Severity
from dart_sast.engine.registry import get_all_rules
from dart_sast.engine.scanner import Scanner
from dart_sast.reporters import console, json_reporter, sarif

_SEVERITY_ORDER = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dart_sast",
        description="Static Application Security Testing (SAST) for Dart/Flutter code.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="File or directory to scan (default: current directory).",
    )
    parser.add_argument(
        "--format",
        choices=["console", "json", "sarif", "all"],
        default="console",
        help="Output format (default: console).",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help=(
            "Write output to FILE instead of stdout. When --format=all, "
            "FILE is treated as a prefix and '.json'/'.sarif' are appended "
            "(console output still goes to stdout)."
        ),
    )
    parser.add_argument(
        "--min-severity",
        choices=[s.value for s in _SEVERITY_ORDER],
        default="INFO",
        help="Only report findings at or above this severity (default: INFO).",
    )
    parser.add_argument(
        "--fail-on",
        choices=["never", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="HIGH",
        help=(
            "Exit with status 1 if a finding at or above this severity is "
            "present. Use 'never' to always exit 0 (default: HIGH)."
        ),
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="Glob pattern (relative path) to exclude; can be repeated.",
    )
    parser.add_argument(
        "--rules",
        metavar="RULE_ID[,RULE_ID...]",
        help="Only run these rule IDs (comma-separated).",
    )
    parser.add_argument(
        "--exclude-rules",
        metavar="RULE_ID[,RULE_ID...]",
        help="Skip these rule IDs (comma-separated).",
    )
    parser.add_argument(
        "--list-rules",
        action="store_true",
        help="Print all available rules and exit.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors in console output.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"dart_sast {__version__}",
    )
    return parser


def _print_rule_list() -> None:
    for rule_cls in sorted(get_all_rules(), key=lambda r: r.rule_id):
        print(f"{rule_cls.rule_id:22} {rule_cls.cwe:10} {rule_cls.title}")


def _select_rules(args: argparse.Namespace):
    all_rules = get_all_rules()
    include = set(args.rules.split(",")) if args.rules else None
    exclude = set(args.exclude_rules.split(",")) if args.exclude_rules else set()

    selected = []
    for rule_cls in all_rules:
        if include is not None and rule_cls.rule_id not in include:
            continue
        if rule_cls.rule_id in exclude:
            continue
        selected.append(rule_cls)
    return selected


def _write(content: str, path: str | None) -> None:
    if path is None:
        print(content)
    else:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.write("\n")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        _print_rule_list()
        return 0

    rules = _select_rules(args)
    if not rules:
        print("error: no rules selected (check --rules/--exclude-rules)", file=sys.stderr)
        return 2

    scanner = Scanner(rules=rules, exclude_patterns=args.exclude)
    result = scanner.scan(args.path)

    min_severity = Severity(args.min_severity)
    result.findings = [f for f in result.findings if f.severity.rank >= min_severity.rank]

    if args.format in ("console", "all"):
        text = console.render(result, use_color=not args.no_color)
        if args.format == "all":
            print(text)
        else:
            _write(text, args.output)

    if args.format in ("json", "all"):
        text = json_reporter.render(result, target=args.path)
        out_path = f"{args.output}.json" if (args.format == "all" and args.output) else (
            args.output if args.format == "json" else None
        )
        _write(text, out_path)

    if args.format in ("sarif", "all"):
        text = sarif.render(result)
        out_path = f"{args.output}.sarif" if (args.format == "all" and args.output) else (
            args.output if args.format == "sarif" else None
        )
        _write(text, out_path)

    if args.fail_on == "never":
        return 0

    threshold = Severity(args.fail_on)
    if any(f.severity.rank >= threshold.rank for f in result.findings):
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
