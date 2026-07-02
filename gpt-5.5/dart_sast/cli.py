"""Command-line interface for dart_sast."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dart_sast.reporters import as_console, as_json, as_sarif
from dart_sast.scanner import scan_target

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SAST scanner for Dart/Flutter projects.")
    parser.add_argument("target", help="Dart file or project directory to scan")
    parser.add_argument("--format", choices=["console", "json", "sarif"], default="console", help="Output format")
    parser.add_argument("--output", "-o", help="Write output to file instead of stdout")
    parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], default=None, help="Exit with code 1 when a finding at or above this severity exists")
    parser.add_argument("--exclude-rule", action="append", default=[], help="Rule id to disable. Can be used multiple times")
    parser.add_argument("--list-rules", action="store_true", help="List available rules and exit")
    return parser


def render(findings, fmt: str) -> str:
    if fmt == "json":
        return as_json(findings)
    if fmt == "sarif":
        return as_sarif(findings)
    return as_console(findings)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.list_rules:
        from dart_sast.rules import ALL_RULES
        for rule in ALL_RULES:
            meta = rule.metadata
            print(f"{meta.rule_id}\t{meta.cwe}\t{meta.severity}\t{meta.title}")
        return 0
    findings = scan_target(Path(args.target), exclude_rule_ids=args.exclude_rule)
    output = render(findings, args.format)
    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
    else:
        print(output)
    if args.fail_on:
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
