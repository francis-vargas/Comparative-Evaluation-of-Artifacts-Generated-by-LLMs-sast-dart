import re

from dart_sast.engine.finding import Severity
from dart_sast.engine.registry import register_rule
from dart_sast.engine.rule import RegexRule

_KEYWORDS = r"(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|" \
            r"private[_-]?key|client[_-]?secret|auth[_-]?token|token)"


@register_rule
class HardcodedCredentialsRule(RegexRule):
    rule_id = "DART-SAST-CWE798"
    cwe = "CWE-798"
    title = "Use of Hard-coded Credentials"
    description = (
        "A string literal that looks like a credential (password, API key, "
        "secret or token) is assigned directly in source code. Hard-coded "
        "credentials are trivially recoverable by anyone with access to the "
        "source, the compiled APK/IPA, or the public repository history."
    )
    severity = Severity.CRITICAL
    recommendation = (
        "Load secrets at runtime from a secure source (environment variables "
        "injected at build time, a secrets manager, or --dart-define) and "
        "never commit them to version control. Add the file to .gitignore "
        "if it must exist locally."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://owasp.org/www-project-mobile-top-10/2023-risks/m1-improper-credential-usage",
    )
    patterns = (
        re.compile(rf"(?i)\b{_KEYWORDS}\b\s*[:=]\s*['\"](?!\$)[^'\"$]{{3,}}['\"]"),
        re.compile(r"(?i)Authorization['\"]?\s*[:=]\s*['\"]Bearer\s+[A-Za-z0-9._-]{8,}['\"]"),
    )
