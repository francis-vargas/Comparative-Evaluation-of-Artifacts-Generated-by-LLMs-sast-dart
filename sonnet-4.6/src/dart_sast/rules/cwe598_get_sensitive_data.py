import re

from dart_sast.engine.finding import Severity
from dart_sast.engine.registry import register_rule
from dart_sast.engine.rule import RegexRule

_SENSITIVE = r"(?:password|passwd|pwd|token|secret|apikey|api_key|ssn|cpf|cardnumber)"


@register_rule
class SensitiveDataInGetRequestRule(RegexRule):
    rule_id = "DART-SAST-CWE598"
    cwe = "CWE-598"
    title = "Use of GET Request Method With Sensitive Query Strings"
    description = (
        "A credential-like value is placed directly in a URL's query "
        "string used with an HTTP GET request. Query strings are commonly "
        "logged by web servers, proxies, browser history, and the Referer "
        "header, exposing the sensitive value well beyond the original "
        "request."
    )
    severity = Severity.MEDIUM
    recommendation = (
        "Send sensitive values in the request body (POST) or in headers "
        "(e.g. Authorization) instead of the URL query string, and use "
        "HTTPS so the body/headers are encrypted in transit."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/598.html",
        "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url",
    )
    patterns = (
        re.compile(rf"(?i)http\.get\s*\([^)]*\?[^)]*\b{_SENSITIVE}\w*\s*="),
        re.compile(rf"(?i)Uri\.parse\s*\(\s*['\"][^'\"]*\?[^'\"]*\b{_SENSITIVE}\w*\s*="),
    )
