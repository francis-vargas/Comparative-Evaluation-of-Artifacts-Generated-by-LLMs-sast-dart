"""Main scanner for dart_sast."""

import os
from pathlib import Path
from typing import List

from .rules.base import Finding
from .rules.hardcoded_credentials import HardcodedCredentialsRule
from .rules.sql_injection import SqlInjectionRule
from .rules.command_injection import CommandInjectionRule
from .rules.path_traversal import PathTraversalRule

class DartSASTScanner:
    """Scanner for Dart/Flutter code."""
    
    def __init__(self):
        self.rules = [
            HardcodedCredentialsRule(),
            SqlInjectionRule(),
            CommandInjectionRule(),
            PathTraversalRule(),
            # Add more rules here
        ]
    
    def scan_file(self, file_path: str) -> List[Finding]:
        """Scan a single file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            findings = []
            for rule in self.rules:
                findings.extend(rule.check(content, file_path))
            return findings
        except Exception:
            return []
    
    def scan_directory(self, dir_path: str) -> List[Finding]:
        """Scan a directory recursively for .dart files."""
        findings = []
        for root, _, files in os.walk(dir_path):
            for file in files:
                if file.endswith('.dart'):
                    file_path = os.path.join(root, file)
                    findings.extend(self.scan_file(file_path))
        return findings