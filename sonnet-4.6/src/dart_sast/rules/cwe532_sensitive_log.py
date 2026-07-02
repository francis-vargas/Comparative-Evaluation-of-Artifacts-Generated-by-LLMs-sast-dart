import re

from dart_sast.engine.finding import Severity
from dart_sast.engine.registry import register_rule
from dart_sast.engine.rule import RegexRule

_SENSITIVE = r"(?:password|passwd|pwd|secret|token|api[_-]?key|cpf|cvv|cardnumber|ssn)"
_LOG_SINKS = r"(?:print|debugPrint|log|logger\.\w+|Logger\(\)\.\w+)"


@register_rule
class SensitiveInformationInLogRule(RegexRule):
    rule_id = "DART-SAST-CWE532"
    cwe = "CWE-532"
    title = "Insertion of Sensitive Information into Log File"
    description = (
        "A logging call (print/debugPrint/log/Logger) appears to output a "
        "variable whose name suggests it holds a credential or sensitive "
        "personal data. Log files and log-aggregation services are often "
        "less protected than the primary datastore, and mobile crash/log "
        "SDKs may upload logs off-device."
    )
    severity = Severity.MEDIUM
    recommendation = (
        "Remove sensitive values from log statements, or mask/redact them "
        "(e.g. show only the last 4 digits) before logging. Ensure logging "
        "is disabled or filtered in release builds."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/532.html",
        "https://owasp.org/www-project-mobile-top-10/2023-risks/m10-insufficient-cryptography",
    )
    patterns = (
        re.compile(rf"(?i)\b{_LOG_SINKS}\s*\([^)]*\b{_SENSITIVE}\w*\b"),
    )
