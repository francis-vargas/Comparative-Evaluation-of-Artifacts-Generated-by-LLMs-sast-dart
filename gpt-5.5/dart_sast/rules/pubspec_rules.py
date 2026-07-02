"""Rules that inspect pubspec.yaml dependencies."""
from __future__ import annotations

import re
from typing import List

from dart_sast.models import Finding, SourceFile
from dart_sast.rules.base import Rule, RuleMetadata


class UnmaintainedDependencyRule(Rule):
    """Flags Dart/Flutter packages known to be discontinued, obsolete, or risky.

    The list is intentionally small and documented. It can be extended without
    changing the scanner core.
    """

    metadata = RuleMetadata(
        "DART-SAST-021",
        "CWE-1104",
        "Use of unmaintained third-party component",
        "medium",
        "Replace discontinued packages and periodically review dependency health.",
    )
    file_kinds = ("pubspec",)
    packages = {
        "flutter_webview_plugin": "discontinued; prefer webview_flutter or an actively maintained alternative",
        "package_info": "superseded by package_info_plus",
        "connectivity": "superseded by connectivity_plus",
        "device_info": "superseded by device_info_plus",
    }

    def scan(self, source: SourceFile) -> List[Finding]:
        findings: List[Finding] = []
        for line_no, line in enumerate(source.lines, start=1):
            for package, reason in self.packages.items():
                if re.match(rf"\s*{re.escape(package)}\s*:", line):
                    findings.append(self.finding(source, line_no, line.find(package) + 1, line, f"Dependency '{package}' is potentially unmaintained or obsolete: {reason}."))
        return findings
