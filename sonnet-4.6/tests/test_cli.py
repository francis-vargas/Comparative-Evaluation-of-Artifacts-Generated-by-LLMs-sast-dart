from __future__ import annotations

import json
import os
import tempfile

import pytest

from dart_sast.cli import main

from conftest import VULNERABLE_FIXTURE, CLEAN_FIXTURE


def test_list_rules(capsys):
    exit_code = main(["--list-rules"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "DART-SAST-CWE798" in captured.out
    assert captured.out.count("DART-SAST-CWE") == 20


def test_json_output_is_valid_json(capsys):
    exit_code = main([VULNERABLE_FIXTURE, "--format", "json", "--fail-on", "never"])
    captured = capsys.readouterr()
    assert exit_code == 0
    data = json.loads(captured.out)
    assert data["summary"]["total_findings"] > 0
    assert data["findings"]


def test_sarif_output_has_expected_shape(capsys):
    exit_code = main([VULNERABLE_FIXTURE, "--format", "sarif", "--fail-on", "never"])
    captured = capsys.readouterr()
    assert exit_code == 0
    data = json.loads(captured.out)
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"]


def test_fail_on_never_always_exits_zero():
    exit_code = main([VULNERABLE_FIXTURE, "--format", "json", "--fail-on", "never"])
    assert exit_code == 0


def test_fail_on_critical_exits_nonzero_on_vulnerable_fixture():
    exit_code = main([VULNERABLE_FIXTURE, "--format", "json", "--fail-on", "CRITICAL"])
    assert exit_code == 1


def test_clean_fixture_exits_zero_even_with_strict_fail_on():
    exit_code = main([CLEAN_FIXTURE, "--format", "json", "--fail-on", "INFO"])
    assert exit_code == 0


def test_rules_filter_restricts_output(capsys):
    exit_code = main(
        [
            VULNERABLE_FIXTURE,
            "--format",
            "json",
            "--rules",
            "DART-SAST-CWE798",
            "--fail-on",
            "never",
        ]
    )
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    rule_ids = {f["rule_id"] for f in data["findings"]}
    assert rule_ids == {"DART-SAST-CWE798"}


def test_exclude_rules_filter(capsys):
    exit_code = main(
        [
            VULNERABLE_FIXTURE,
            "--format",
            "json",
            "--exclude-rules",
            "DART-SAST-CWE798",
            "--fail-on",
            "never",
        ]
    )
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    rule_ids = {f["rule_id"] for f in data["findings"]}
    assert "DART-SAST-CWE798" not in rule_ids


def test_output_to_file():
    with tempfile.TemporaryDirectory() as tmp:
        out_path = os.path.join(tmp, "report.json")
        exit_code = main(
            [VULNERABLE_FIXTURE, "--format", "json", "--output", out_path, "--fail-on", "never"]
        )
        assert exit_code == 0
        assert os.path.exists(out_path)
        with open(out_path) as fh:
            data = json.load(fh)
        assert data["summary"]["total_findings"] > 0


def test_min_severity_filters_low_severity_findings(capsys):
    exit_code = main(
        [
            VULNERABLE_FIXTURE,
            "--format",
            "json",
            "--min-severity",
            "CRITICAL",
            "--fail-on",
            "never",
        ]
    )
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    severities = {f["severity"] for f in data["findings"]}
    assert severities <= {"CRITICAL"}
