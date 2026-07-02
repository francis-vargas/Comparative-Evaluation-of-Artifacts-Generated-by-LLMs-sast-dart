import re

from dart_sast.engine.finding import Severity
from dart_sast.engine.registry import register_rule
from dart_sast.engine.rule import RegexRule

_SECURITY_CONTEXT = (
    r"(?:token|otp|nonce|salt|iv|session|password|pin|key|reset|verification|"
    r"code|challenge|secret)"
)


@register_rule
class WeakRandomForSecurityRule(RegexRule):
    rule_id = "DART-SAST-CWE338"
    cwe = "CWE-338"
    title = "Use of Cryptographically Weak Pseudo-Random Number Generator"
    description = (
        "dart:math's Random() is a statistically-seeded, non-cryptographic "
        "generator. When used to build tokens, OTPs, nonces, session "
        "identifiers, salts or password-reset codes, its output can be "
        "predicted or brute-forced by an attacker."
    )
    severity = Severity.HIGH
    recommendation = (
        "Use Random.secure() (backed by the OS CSPRNG) for anything with a "
        "security purpose. Plain Random() remains fine for non-security "
        "randomness such as UI animations or game logic."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/338.html",
        "https://api.dart.dev/stable/dart-math/Random/Random.secure.html",
    )
    patterns = (
        re.compile(
            rf"(?i){_SECURITY_CONTEXT}[A-Za-z0-9_]*\s*=[^=].{{0,80}}\bRandom\(\)(?!\.secure)"
        ),
        re.compile(rf"(?i)\bRandom\(\)\.nextInt\(.{{0,10}}\).{{0,20}}{_SECURITY_CONTEXT}"),
    )
