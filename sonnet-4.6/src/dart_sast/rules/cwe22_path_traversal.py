import re

from dart_sast.engine.finding import Severity
from dart_sast.engine.registry import register_rule
from dart_sast.engine.rule import RegexRule

_UNTRUSTED = r"(?:request|req|params|query|args|input|userInput|fileName|filename|path)"


@register_rule
class PathTraversalRule(RegexRule):
    rule_id = "DART-SAST-CWE22"
    cwe = "CWE-22"
    title = "Path Traversal"
    description = (
        "A File/Directory is constructed by concatenating or interpolating "
        "a value that appears to originate from a request, query "
        "parameter, or other external input, without prior sanitization. "
        "An attacker could supply '../' sequences to read or write files "
        "outside the intended directory."
    )
    severity = Severity.HIGH
    recommendation = (
        "Reject path segments containing '..', resolve the final path with "
        "path.normalize()/File(...).absolute and verify it stays within the "
        "intended base directory before use (e.g. p.isWithin(baseDir, "
        "resolvedPath))."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/22.html",
        "https://owasp.org/www-community/attacks/Path_Traversal",
    )
    patterns = (
        re.compile(rf"(?i)\bFile\s*\(\s*['\"][^'\"]*\$\{{?\b{_UNTRUSTED}\w*\b"),
        re.compile(rf"(?i)\bDirectory\s*\(\s*['\"][^'\"]*\$\{{?\b{_UNTRUSTED}\w*\b"),
        re.compile(rf"(?i)\bFile\s*\(\s*{_UNTRUSTED}\w*(?:\[[^\]]*\]|\.\w+)*\s*\)"),
    )
