"""Base class for security rules."""

import re
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

@dataclass
class Finding:
    rule_id: str
    cwe: str
    severity: str
    message: str
    file_path: str
    line: int
    snippet: str

class BaseRule:
    """Base class for all security rules."""
    
    def __init__(self):
        self.rule_id: str = ""
        self.cwe: str = ""
        self.severity: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
        self.description: str = ""
        self.patterns: List[str] = []
        self.compiled_patterns: List[re.Pattern] = []
    
    def compile_patterns(self):
        """Compile regex patterns for efficiency."""
        self.compiled_patterns = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in self.patterns]
    
    def check(self, content: str, file_path: str) -> List[Finding]:
        """Check content for vulnerabilities."""
        findings = []
        lines = content.splitlines()
        for pattern in self.compiled_patterns:
            for match in pattern.finditer(content):
                line_num = content.count('\n', 0, match.start()) + 1
                snippet = lines[line_num-1] if line_num <= len(lines) else match.group(0)
                findings.append(Finding(
                    rule_id=self.rule_id,
                    cwe=self.cwe,
                    severity=self.severity,
                    message=self.description,
                    file_path=file_path,
                    line=line_num,
                    snippet=snippet.strip()
                ))
        return findings