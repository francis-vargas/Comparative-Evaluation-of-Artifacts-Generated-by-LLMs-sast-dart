import re

from dart_sast.engine.finding import Severity
from dart_sast.engine.registry import register_rule
from dart_sast.engine.rule import RegexRule

_SENSITIVE = r"(?:password|passwd|pwd|secret|token|api[_-]?key|creditcard|cardnumber|ssn|cpf)"


@register_rule
class CleartextStorageRule(RegexRule):
    rule_id = "DART-SAST-CWE312"
    cwe = "CWE-312"
    title = "Cleartext Storage of Sensitive Information"
    description = (
        "Sensitive data (password, token, API key, card number, etc.) is "
        "written to SharedPreferences, a plain file, or a local database "
        "field without encryption. SharedPreferences on Android and "
        "NSUserDefaults on iOS are not encrypted by default and can be "
        "read by anyone with device/backup access."
    )
    severity = Severity.HIGH
    recommendation = (
        "Store secrets with flutter_secure_storage (Keychain/Keystore-"
        "backed) instead of SharedPreferences or plain files. If a local "
        "database must hold sensitive fields, encrypt them at the "
        "application layer before persisting."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/312.html",
        "https://pub.dev/packages/flutter_secure_storage",
    )
    patterns = (
        re.compile(
            rf"(?i)\.(?:setString|setInt|setBool|setStringList)\s*\(\s*['\"][^'\"]*{_SENSITIVE}\w*[^'\"]*['\"]"
        ),
        re.compile(rf"(?i)File\([^)]*\)\.writeAsString(?:Sync)?\([^)]*\b{_SENSITIVE}\w*\b"),
    )
