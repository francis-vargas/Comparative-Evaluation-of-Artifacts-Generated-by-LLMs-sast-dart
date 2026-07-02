import re

from dart_sast.engine.finding import Severity
from dart_sast.engine.registry import register_rule
from dart_sast.engine.rule import RegexRule

_SENSITIVE = r"(?:password|passwd|pwd|secret|token|api[_-]?key|privateKey)"


@register_rule
class SensitiveInfoInDebugCodeRule(RegexRule):
    rule_id = "DART-SAST-CWE215"
    cwe = "CWE-215"
    title = "Insertion of Sensitive Information Into Debugging Code"
    description = (
        "An assert()/kDebugMode block, or a class toString() override, "
        "exposes a credential-like field. assert() statements are stripped "
        "in release mode but remain visible in profile/debug builds and in "
        "source control; a leaked toString() can end up in crash reports "
        "or UI widgets that render arbitrary objects."
    )
    severity = Severity.MEDIUM
    recommendation = (
        "Never reference secret fields inside assert()/toString(). Exclude "
        "sensitive fields explicitly when building a debug representation, "
        "e.g. return 'User(id: $id)' without the password/token field."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/215.html",
        "https://dart.dev/language/class-modifiers#assert",
    )
    patterns = (
        re.compile(rf"(?i)\bassert\s*\([^)]*\b{_SENSITIVE}\w*\b"),
        re.compile(rf"(?i)String\s+toString\(\).{{0,200}}\b{_SENSITIVE}\w*\b"),
        re.compile(rf"(?i)if\s*\(\s*kDebugMode\s*\)\s*\{{?[^}}]{{0,120}}\b{_SENSITIVE}\w*\b"),
    )
