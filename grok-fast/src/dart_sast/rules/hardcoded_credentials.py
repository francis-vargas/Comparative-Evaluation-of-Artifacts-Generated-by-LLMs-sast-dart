"""Rule for CWE-798: Hardcoded credentials."""

from .base import BaseRule

class HardcodedCredentialsRule(BaseRule):
    """Detects hardcoded credentials."""
    
    def __init__(self):
        super().__init__()
        self.rule_id = "DART-001"
        self.cwe = "CWE-798"
        self.severity = "HIGH"
        self.description = "Hardcoded credentials detected. Use environment variables or secure secret management."
        self.patterns = [
            r'(?i)(api_key|password|secret|token|key)\s*[:=]\s*["\'][^"\']{8,}["\']',
            r'(?i)(Bearer|Basic)\s+[\w-]+',
        ]
        self.compile_patterns()