import os
import re
from typing import Dict, List, Any
from dart_sast.rules_definitions import RULES

class SASTEngine:
    """
    Static Application Security Testing (SAST) engine for Dart/Flutter projects.
    Fulfills SBRC 2026 SeloS (Sustentabilidade) via clean OOP structure, modular rules, and clear logging.
    """
    
    def __init__(self, rules: List[Dict[str, Any]] = None):
        self.rules = rules if rules is not None else RULES
        # Precompile regex patterns for efficiency
        for rule in self.rules:
            rule["compiled_patterns"] = [
                re.compile(pattern) for pattern in rule["patterns"]
            ]

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Scans a single file against all defined security rules.
        """
        findings = []
        filename = os.path.basename(file_path)
        ext = os.path.splitext(filename)[1].lower()
        
        # We scan .dart, .yaml (for pubspec), and .xml (for AndroidManifest)
        if ext not in [".dart", ".yaml", ".xml"]:
            return findings

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception as e:
            # Skip unreadable files gracefully
            return findings

        for line_num, line in enumerate(lines, 1):
            # Strip whitespace to help with formatting
            stripped_line = line.strip()
            
            # Skip purely blank lines or full comments (except if they could contain keys, but usually skip general lines)
            if not stripped_line or (stripped_line.startswith("//") and not any(k in stripped_line.lower() for k in ["api_key", "secret", "password"])):
                continue

            for rule in self.rules:
                # Some rules only target certain files (e.g. CWE-926 for manifest XML, CWE-1104 for pubspec yaml)
                cwe = rule["cwe"]
                if cwe == "CWE-926" and ext != ".xml":
                    continue
                if cwe == "CWE-1104" and ext != ".yaml":
                    continue
                if cwe not in ["CWE-926", "CWE-1104"] and ext != ".dart":
                    continue

                for pattern in rule["compiled_patterns"]:
                    match = pattern.search(line)
                    if match:
                        findings.append({
                            "rule_id": rule["id"],
                            "cwe": rule["cwe"],
                            "name": rule["name"],
                            "severity": rule["severity"],
                            "file": file_path,
                            "line": line_num,
                            "code": stripped_line,
                            "match": match.group(0),
                            "description": rule["description"],
                            "recommendation": rule["recommendation"]
                        })
                        # Avoid duplicate findings for the same rule on the same line
                        break
        
        return findings

    def scan_directory(self, dir_path: str) -> List[Dict[str, Any]]:
        """
        Recursively scans a directory for vulnerable files.
        """
        all_findings = []
        for root, _, files in os.walk(dir_path):
            # Skip hidden folders and build artifacts
            if any(part.startswith(".") or part in ["build", "ios", "macos", "windows", "linux", "web"] for part in root.split(os.sep)):
                continue
            for file in files:
                full_path = os.path.join(root, file)
                # Keep paths relative and clean
                relative_path = os.path.relpath(full_path, dir_path)
                findings = self.scan_file(full_path)
                for f in findings:
                    f["file"] = relative_path
                all_findings.extend(findings)
        
        return all_findings
