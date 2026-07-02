import re

from dart_sast.engine.finding import Severity
from dart_sast.engine.registry import register_rule
from dart_sast.engine.rule import RegexRule

_HTTP_SINKS = r"(?:http\.get|http\.post|http\.put|http\.delete|\.get|\.post|\.put|\.delete)"
_UNTRUSTED = r"(?:request|req|params|query|args|input|userInput|url|targetUrl|callbackUrl)"


@register_rule
class ServerSideRequestForgeryRule(RegexRule):
    rule_id = "DART-SAST-CWE918"
    cwe = "CWE-918"
    title = "Server-Side Request Forgery (SSRF)"
    description = (
        "An HTTP client call (http/dio) fetches a URL that is built from a "
        "variable whose name suggests it comes from user/request input "
        "(url, targetUrl, callbackUrl, query parameters, ...), without an "
        "allow-list check. In server-side Dart code (shelf, dart_frog, "
        "functions) this lets an attacker force the backend to issue "
        "requests to internal/cloud-metadata endpoints."
    )
    severity = Severity.HIGH
    recommendation = (
        "Validate the target URL against an explicit allow-list of hosts/"
        "schemes before making the request. Never forward a raw "
        "user-supplied URL directly into an outbound HTTP call, and block "
        "requests to link-local/metadata addresses (169.254.0.0/16, "
        "127.0.0.0/8, etc.)."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/918.html",
        "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
    )
    patterns = (
        re.compile(
            rf"(?i)\b{_HTTP_SINKS}\s*\(\s*Uri\.parse\(\s*{_UNTRUSTED}\w*\s*\)"
        ),
        re.compile(rf"(?i)\b{_HTTP_SINKS}\s*\(\s*{_UNTRUSTED}\w*\s*\)"),
    )
