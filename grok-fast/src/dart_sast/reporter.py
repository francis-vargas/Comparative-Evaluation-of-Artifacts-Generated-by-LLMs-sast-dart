"""Reporting for findings."""

import json
from typing import List, Dict
from .rules.base import Finding

def to_console(findings: List[Finding], summary: bool = False):
    """Print findings to console."""
    if not findings:
        print("✅ No vulnerabilities found!")
        return
    
    print(f"🔍 Found {len(findings)} potential vulnerabilities:\n")
    for f in findings:
        print(f"[{f.severity}] {f.rule_id} ({f.cwe})")
        print(f"   File: {f.file_path}:{f.line}")
        print(f"   {f.message}")
        print(f"   Snippet: {f.snippet[:100]}...\n")
    
    if summary:
        from collections import Counter
        severity_count = Counter(f.severity for f in findings)
        print("Summary:")
        for sev, count in severity_count.items():
            print(f"  {sev}: {count}")

def to_json(findings: List[Finding]) -> str:
    """Convert findings to JSON."""
    data = {
        "tool": "dart_sast",
        "version": "0.1.0",
        "findings": [
            {
                "rule_id": f.rule_id,
                "cwe": f.cwe,
                "severity": f.severity,
                "message": f.message,
                "file": f.file_path,
                "line": f.line,
                "snippet": f.snippet
            } for f in findings
        ]
    }
    return json.dumps(data, indent=2)