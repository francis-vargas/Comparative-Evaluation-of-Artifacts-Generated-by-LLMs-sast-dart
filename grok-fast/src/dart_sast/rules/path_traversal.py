"""Rule for CWE-22: Path Traversal."""

from .base import BaseRule

class PathTraversalRule(BaseRule):
    """Detects path traversal vulnerabilities."""
    
    def __init__(self):
        super().__init__()
        self.rule_id = "DART-004"
        self.cwe = "CWE-22"
        self.severity = "HIGH"
        self.description = "Potential path traversal. Sanitize file paths."
        self.patterns = [
            r'(?i)(File|Directory)\s*\(\s*[^)]*\+\s*',
            r'(?i)\.\./|\.\.\\',
        ]
        self.compile_patterns()