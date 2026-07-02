import re

from dart_sast.engine.finding import Severity
from dart_sast.engine.registry import register_rule
from dart_sast.engine.rule import RegexRule


@register_rule
class ImproperAuthenticationRule(RegexRule):
    rule_id = "DART-SAST-CWE287"
    cwe = "CWE-287"
    title = "Improper Authentication"
    description = (
        "A password/token is compared using the plain equality operator "
        "(==) instead of a constant-time comparison, or an authentication "
        "check contains an obvious hard-coded bypass (e.g. comparing "
        "against a fixed 'admin'/'backdoor' literal, or a "
        "TODO/FIXME/skip-auth marker). Naive '==' comparisons on secrets "
        "are vulnerable to timing attacks, and hard-coded bypasses defeat "
        "authentication entirely."
    )
    severity = Severity.HIGH
    recommendation = (
        "Compare secrets with a constant-time function (e.g. "
        "crypto.constantTimeEquals equivalent) rather than ==, and remove "
        "any hard-coded bypass branches before shipping to production."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/287.html",
        "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication",
    )
    patterns = (
        re.compile(r"(?i)\b(?:password|pwd|passwd|token)\s*==\s*(?:request|input|user)?\w*\.?\w*"),
        re.compile(r"(?i)//\s*(?:TODO|FIXME).*(?:skip|bypass|disable).*auth"),
        re.compile(r"""(?i)username\s*==\s*['"]admin['"]\s*&&\s*password\s*=="""),
    )
