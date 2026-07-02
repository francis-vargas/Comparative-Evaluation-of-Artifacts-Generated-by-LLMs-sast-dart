"""Part 5.1 of the assignment: detecção positiva para cada regra implementada.

For every registered rule, run the scanner over the vulnerable fixture with
*only* that rule enabled and assert it produced at least one finding.
"""

from __future__ import annotations

import pytest

from dart_sast.engine.registry import get_all_rules, get_rule_by_id
from dart_sast.engine.scanner import Scanner

from conftest import VULNERABLE_FIXTURE


@pytest.mark.parametrize("rule_cls", get_all_rules(), ids=lambda r: r.rule_id)
def test_rule_detects_vulnerable_fixture(rule_cls):
    scanner = Scanner(rules=[rule_cls])
    result = scanner.scan(VULNERABLE_FIXTURE)
    assert result.findings, (
        f"Rule {rule_cls.rule_id} ({rule_cls.cwe}) produced no findings on "
        f"the vulnerable fixture; expected at least one."
    )
    for finding in result.findings:
        assert finding.rule_id == rule_cls.rule_id
        assert finding.cwe == rule_cls.cwe
        assert finding.line >= 1


def test_registry_has_twenty_rules():
    assert len(get_all_rules()) == 20


@pytest.mark.parametrize(
    "rule_id",
    [
        "DART-SAST-CWE798",
        "DART-SAST-CWE319",
        "DART-SAST-CWE327",
        "DART-SAST-CWE338",
        "DART-SAST-CWE89",
        "DART-SAST-CWE532",
        "DART-SAST-CWE215",
        "DART-SAST-CWE312",
        "DART-SAST-CWE295",
        "DART-SAST-CWE22",
        "DART-SAST-CWE926",
        "DART-SAST-CWE1104",
        "DART-SAST-CWE78",
        "DART-SAST-CWE918",
        "DART-SAST-CWE347",
        "DART-SAST-CWE942",
        "DART-SAST-CWE598",
        "DART-SAST-CWE287",
        "DART-SAST-CWE209",
        "DART-SAST-CWE521",
    ],
)
def test_every_required_cwe_is_registered(rule_id):
    assert get_rule_by_id(rule_id) is not None
