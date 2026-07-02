from __future__ import annotations

from dart_sast.engine.registry import get_all_rules
from dart_sast.engine.scanner import Scanner
from dart_sast.reporters import console

from conftest import VULNERABLE_FIXTURE, CLEAN_FIXTURE


def test_console_render_lists_findings():
    scanner = Scanner(rules=get_all_rules())
    result = scanner.scan(VULNERABLE_FIXTURE)
    text = console.render(result, use_color=False)
    assert "DART-SAST-CWE798" in text
    assert "TOTAL findings:" in text
    assert "\033[" not in text  # no ANSI codes when use_color=False


def test_console_render_no_issues_message():
    scanner = Scanner(rules=get_all_rules())
    result = scanner.scan(CLEAN_FIXTURE)
    text = console.render(result, use_color=False)
    assert "No issues found" in text


def test_console_render_with_color_includes_ansi_codes():
    scanner = Scanner(rules=get_all_rules())
    result = scanner.scan(VULNERABLE_FIXTURE)
    text = console.render(result, use_color=True)
    assert "\033[" in text
