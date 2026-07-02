import re

from dart_sast.engine.finding import Severity
from dart_sast.engine.registry import register_rule
from dart_sast.engine.rule import RegexRule


@register_rule
class ImproperSignatureVerificationRule(RegexRule):
    rule_id = "DART-SAST-CWE347"
    cwe = "CWE-347"
    title = "Improper Verification of Cryptographic Signature"
    description = (
        "A JWT (or other signed payload) is decoded/verified with signature "
        "checking explicitly disabled, or the algorithm is not pinned "
        "(allowing an attacker to switch to 'none' or a weaker algorithm). "
        "Skipping signature verification lets an attacker forge tokens and "
        "claims."
    )
    severity = Severity.CRITICAL
    recommendation = (
        "Always verify the signature (verify: true, or use a library "
        "default that verifies) and explicitly pin the accepted algorithm "
        "(e.g. only accept HS256/RS256, never 'none'). Reject the token if "
        "verification fails instead of catching and ignoring the error."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/347.html",
        "https://owasp.org/www-community/vulnerabilities/JWT_Signature_Bypass",
    )
    patterns = (
        re.compile(r"(?i)\bverify['\"]?\s*:\s*false\b"),
        re.compile(r"(?i)\.verify\s*:\s*false"),
        re.compile(r"(?i)alg(?:orithm)?['\"]?\s*:\s*['\"]?none['\"]?"),
        re.compile(r"(?i)JWT\.decode\s*\([^)]*\)\s*;(?!.*verify)"),
    )
