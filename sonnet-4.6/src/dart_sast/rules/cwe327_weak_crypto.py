import re

from dart_sast.engine.finding import Severity
from dart_sast.engine.registry import register_rule
from dart_sast.engine.rule import RegexRule


@register_rule
class WeakCryptoAlgorithmRule(RegexRule):
    rule_id = "DART-SAST-CWE327"
    cwe = "CWE-327"
    title = "Use of a Broken or Risky Cryptographic Algorithm"
    description = (
        "A cryptographically broken or deprecated primitive (MD5, SHA-1, "
        "DES/3DES, RC4, or AES in ECB mode) is used. These algorithms have "
        "known collision or key-recovery attacks and should not protect "
        "sensitive data or authenticate content."
    )
    severity = Severity.HIGH
    recommendation = (
        "Use SHA-256/SHA-3 (or BLAKE2) for hashing, and AES-GCM (or "
        "ChaCha20-Poly1305) with a random IV/nonce for symmetric encryption. "
        "For password storage use a dedicated slow hash such as Argon2 or "
        "bcrypt/PBKDF2, never a general-purpose hash function."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/327.html",
        "https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration",
    )
    patterns = (
        re.compile(r"(?i)\bmd5\b\s*(?:\(|\.)"),
        re.compile(r"(?i)\bsha1\b\s*(?:\(|\.)"),
        re.compile(r"\bDES\s*\(|\b3DES\b|\bDESede\b"),
        re.compile(r"\bRC4\b"),
        re.compile(r"(?i)AESMode\.ecb|mode\s*:\s*['\"]?ECB['\"]?"),
    )
