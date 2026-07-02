from pathlib import Path

from dart_sast.scanner import scan_target

ROOT = Path(__file__).parent / "fixtures"


def test_vulnerable_fixture_detects_all_expected_cwes():
    findings = scan_target(ROOT / "vulnerable_app")
    cwes = {f.cwe for f in findings}
    expected = {
        "CWE-798", "CWE-319", "CWE-327", "CWE-338", "CWE-89",
        "CWE-532", "CWE-215", "CWE-312", "CWE-295", "CWE-22",
        "CWE-926", "CWE-1104", "CWE-78", "CWE-918", "CWE-347",
        "CWE-942", "CWE-598", "CWE-287", "CWE-209", "CWE-521",
        "CWE-749",
    }
    missing = expected - cwes
    assert not missing, f"Missing CWE detections: {sorted(missing)}"


def test_clean_fixture_has_no_findings():
    findings = scan_target(ROOT / "clean_app")
    assert findings == []


def test_exclude_rule():
    findings = scan_target(ROOT / "vulnerable_app", exclude_rule_ids=["DART-SAST-001"])
    assert all(f.rule_id != "DART-SAST-001" for f in findings)
