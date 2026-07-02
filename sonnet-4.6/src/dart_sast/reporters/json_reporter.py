"""JSON output, suitable for machine consumption / CI pipelines."""

from __future__ import annotations

import json

from dart_sast import __version__
from dart_sast.engine.scanner import ScanResult


def render(result: ScanResult, target: str) -> str:
    payload = {
        "tool": "dart_sast",
        "version": __version__,
        "target": target,
        "summary": {
            "files_scanned": result.scanned_files,
            "dart_files_scanned": result.scanned_dart_files,
            "pubspec_files_scanned": result.pubspec_files,
            "total_findings": len(result.findings),
            "errors": result.errors,
        },
        "findings": [f.to_dict() for f in result.findings],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
