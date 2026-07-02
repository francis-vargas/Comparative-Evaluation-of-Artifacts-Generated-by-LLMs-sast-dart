import re

from dart_sast.engine.finding import Severity
from dart_sast.engine.registry import register_rule
from dart_sast.engine.rule import RegexRule


@register_rule
class WeakPasswordRequirementsRule(RegexRule):
    rule_id = "DART-SAST-CWE521"
    cwe = "CWE-521"
    title = "Weak Password Requirements"
    description = (
        "A password-related length/strength check accepts passwords "
        "shorter than 8 characters (e.g. 'password.length < 6' used as the "
        "*valid* condition, or a minLength/minimumLength configured below "
        "8). Short passwords are far more susceptible to brute-force and "
        "dictionary attacks."
    )
    severity = Severity.LOW
    recommendation = (
        "Require a minimum length of at least 8 characters (NIST SP "
        "800-63B recommends allowing up to 64 and not mandating arbitrary "
        "composition rules), and check the password against a breached-"
        "password list where feasible."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/521.html",
        "https://pages.nist.gov/800-63-3/sp800-63b.html",
    )
    patterns = (
        re.compile(r"(?i)password\w*\.length\s*(?:>=|>)\s*[1-7]\b"),
        re.compile(r"(?i)password\w*\.length\s*<\s*[1-8]\b"),
        re.compile(r"(?i)min(?:imum)?[_]?length\s*[:=]\s*[1-7]\b"),
    )
