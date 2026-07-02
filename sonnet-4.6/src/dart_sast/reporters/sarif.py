"""SARIF 2.1.0 output.

SARIF (Static Analysis Results Interchange Format) is consumed natively by
GitHub Code Scanning, Azure DevOps, and can be imported into most security
dashboards (DefectDojo, etc.), which is why it is offered as a first-class
output format alongside plain JSON.
"""

from __future__ import annotations

import json

from dart_sast import __version__
from dart_sast.engine.finding import Severity
from dart_sast.engine.scanner import ScanResult

_SEVERITY_TO_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render(result: ScanResult) -> str:
    rules_seen: dict[str, dict] = {}
    results = []

    for f in result.findings:
        if f.rule_id not in rules_seen:
            rules_seen[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title.replace(" ", ""),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "help": {"text": f.recommendation},
                "properties": {"cwe": f.cwe, "tags": [f.cwe, "security"]},
            }
        results.append(
            {
                "ruleId": f.rule_id,
                "level": _SEVERITY_TO_SARIF_LEVEL.get(f.severity, "warning"),
                "message": {"text": f"{f.description} ({f.cwe})"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path.replace("\\", "/")},
                            "region": {
                                "startLine": max(f.line, 1),
                                "startColumn": max(f.column, 1),
                                "snippet": {"text": f.snippet},
                            },
                        }
                    }
                ],
            }
        )

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dart_sast",
                        "informationUri": "https://github.com/example/dart_sast",
                        "version": __version__,
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)
