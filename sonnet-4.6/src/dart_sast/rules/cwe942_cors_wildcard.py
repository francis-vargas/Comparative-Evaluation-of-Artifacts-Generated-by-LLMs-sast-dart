import re

from dart_sast.engine.finding import Severity
from dart_sast.engine.registry import register_rule
from dart_sast.engine.rule import RegexRule


@register_rule
class OverlyPermissiveCorsRule(RegexRule):
    rule_id = "DART-SAST-CWE942"
    cwe = "CWE-942"
    title = "Permissive Cross-domain Policy (CORS)"
    description = (
        "A server-side Dart handler (shelf, shelf_cors_headers, "
        "dart_frog, etc.) sets Access-Control-Allow-Origin to '*' "
        "(optionally together with credentials), allowing any website to "
        "make cross-origin requests to this API and read the response."
    )
    severity = Severity.MEDIUM
    recommendation = (
        "Return an explicit allow-list of trusted origins instead of '*', "
        "and never combine a wildcard origin with "
        "Access-Control-Allow-Credentials: true."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/942.html",
        "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
    )
    patterns = (
        re.compile(r"(?i)Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*['\"]"),
        re.compile(r"(?i)\borigin\s*:\s*['\"]\*['\"]"),
    )
