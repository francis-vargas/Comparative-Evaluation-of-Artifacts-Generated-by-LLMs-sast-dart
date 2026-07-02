"""Rule for CWE-89: SQL Injection."""

from .base import BaseRule

class SqlInjectionRule(BaseRule):
    """Detects potential SQL injection."""
    
    def __init__(self):
        super().__init__()
        self.rule_id = "DART-002"
        self.cwe = "CWE-89"
        self.severity = "CRITICAL"
        self.description = "Potential SQL injection via string concatenation. Use parameterized queries."
        self.patterns = [
            r'(?i)\b(select|insert|update|delete)\b.*\+\s*["\']',
            r'(?i)sql\s*\.\s*execute.*\+\s*',
        ]
        self.compile_patterns()