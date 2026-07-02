"""Part 5.2 of the assignment: não detecção em código limpo (falsos positivos)."""

from __future__ import annotations

from dart_sast.engine.registry import get_all_rules
from dart_sast.engine.scanner import Scanner

from conftest import CLEAN_FIXTURE


def test_no_findings_on_clean_fixture():
    scanner = Scanner(rules=get_all_rules())
    result = scanner.scan(CLEAN_FIXTURE)
    assert result.findings == [], (
        "Expected zero findings on the clean fixture, got: "
        + ", ".join(f"{f.rule_id}:{f.line}" for f in result.findings)
    )
