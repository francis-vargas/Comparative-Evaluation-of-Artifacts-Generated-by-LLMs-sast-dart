"""Output formatters for console, JSON and SARIF."""
from __future__ import annotations

import json
from collections import Counter
from typing import Iterable, List

from dart_sast.models import Finding
from dart_sast.rules import ALL_RULES


def as_json(findings: Iterable[Finding]) -> str:
    data = [f.to_dict() for f in findings]
    return json.dumps({"tool": "dart_sast", "version": "0.1.0", "findings": data, "count": len(data)}, indent=2, ensure_ascii=False)


def as_console(findings: List[Finding]) -> str:
    if not findings:
        return "dart_sast: no findings."
    counts = Counter(f.severity for f in findings)
    lines = [f"dart_sast: {len(findings)} finding(s) | " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))]
    for f in findings:
        lines.append(f"[{f.severity.upper()}] {f.rule_id} {f.cwe} {f.file}:{f.line}:{f.column} - {f.title}: {f.message}")
        lines.append(f"  evidence: {f.evidence}")
        lines.append(f"  fix: {f.recommendation}")
    return "\n".join(lines)


def as_sarif(findings: List[Finding]) -> str:
    rule_meta = {r.metadata.rule_id: r.metadata for r in ALL_RULES}
    rules = []
    for rule_id, meta in sorted(rule_meta.items()):
        rules.append({
            "id": rule_id,
            "name": meta.title,
            "shortDescription": {"text": meta.title},
            "fullDescription": {"text": f"{meta.cwe}: {meta.title}"},
            "help": {"text": meta.recommendation},
            "properties": {"tags": [meta.cwe], "security-severity": meta.severity},
        })
    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule_id,
            "level": "error" if f.severity in {"critical", "high"} else "warning",
            "message": {"text": f.message},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file}, "region": {"startLine": f.line, "startColumn": f.column}}}],
            "properties": {"cwe": f.cwe, "severity": f.severity, "confidence": f.confidence, "evidence": f.evidence},
        })
    return json.dumps({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": {"name": "dart_sast", "version": "0.1.0", "rules": rules}}, "results": results}],
    }, indent=2)
