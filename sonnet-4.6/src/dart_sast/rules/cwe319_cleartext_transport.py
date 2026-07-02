import re

from dart_sast.engine.finding import Severity
from dart_sast.engine.registry import register_rule
from dart_sast.engine.rule import RegexRule


@register_rule
class CleartextTransportRule(RegexRule):
    rule_id = "DART-SAST-CWE319"
    cwe = "CWE-319"
    title = "Cleartext Transmission of Sensitive Information"
    description = (
        "An explicit http:// URL (or Uri.http(...) constructor) is used to "
        "reach a network endpoint. Traffic sent over plain HTTP can be read "
        "or tampered with by anyone on the network path (Wi-Fi, proxies, "
        "carrier infrastructure)."
    )
    severity = Severity.HIGH
    recommendation = (
        "Use https:// (or Uri.https(...)) for every endpoint that is not "
        "localhost/loopback. If HTTP is unavoidable for local development, "
        "gate it behind a debug-only flag so release builds never use it."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/319.html",
        "https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication",
    )
    patterns = (
        re.compile(r"""(?i)['"]http://(?!localhost|127\.0\.0\.1|10\.0\.2\.2|\[::1\])[^'"]+['"]"""),
        re.compile(r"(?i)\bUri\.http\s*\("),
    )
