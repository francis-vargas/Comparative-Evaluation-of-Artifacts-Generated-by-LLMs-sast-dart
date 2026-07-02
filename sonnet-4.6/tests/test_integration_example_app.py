"""Part 5.3 of the assignment: teste de integração usando o app de exemplo."""

from __future__ import annotations

import os

from dart_sast.engine.registry import get_all_rules
from dart_sast.engine.scanner import Scanner

EXAMPLE_APP = os.path.join(
    os.path.dirname(__file__), "..", "examples", "vulnerable_app"
)


def test_example_app_triggers_every_rule():
    scanner = Scanner(rules=get_all_rules())
    result = scanner.scan(EXAMPLE_APP)

    triggered = {f.rule_id for f in result.findings}
    all_ids = {r.rule_id for r in get_all_rules()}
    missing = all_ids - triggered
    assert not missing, f"These rules did not trigger on the example app: {missing}"


def test_example_app_scans_dart_pubspec_and_manifest():
    scanner = Scanner(rules=get_all_rules())
    result = scanner.scan(EXAMPLE_APP)

    assert result.scanned_dart_files >= 1
    assert result.pubspec_files == 1
    assert not result.errors
