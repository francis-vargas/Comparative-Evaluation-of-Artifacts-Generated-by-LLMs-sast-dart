import json
from pathlib import Path

from dart_sast.cli import main

ROOT = Path(__file__).parent / "fixtures"


def test_cli_json_output_file(tmp_path):
    output = tmp_path / "findings.json"
    code = main([str(ROOT / "vulnerable_app"), "--format", "json", "--output", str(output)])
    assert code == 0
    data = json.loads(output.read_text())
    assert data["count"] > 0
    assert data["tool"] == "dart_sast"


def test_cli_fail_on_high():
    code = main([str(ROOT / "vulnerable_app"), "--fail-on", "high"])
    assert code == 1


def test_cli_clean_fail_on_high():
    code = main([str(ROOT / "clean_app"), "--fail-on", "high"])
    assert code == 0
