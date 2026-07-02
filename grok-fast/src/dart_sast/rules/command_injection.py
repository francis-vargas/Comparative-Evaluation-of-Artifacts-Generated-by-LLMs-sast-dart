"""Rule for CWE-78: OS Command Injection."""

from .base import BaseRule

class CommandInjectionRule(BaseRule):
    """Detects OS command injection."""
    
    def __init__(self):
        super().__init__()
        self.rule_id = "DART-003"
        self.cwe = "CWE-78"
        self.severity = "CRITICAL"
        self.description = "Potential OS command injection. Avoid executing user-controlled input."
        self.patterns = [
            r'(?i)(Process\.run|Process\.start|dart:io.*exec).*\+',
            r'(?i)\b(exec|system|shell)\s*\(\s*[^)]*\$',
        ]
        self.compile_patterns()