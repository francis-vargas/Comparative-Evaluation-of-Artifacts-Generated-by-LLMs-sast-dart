import re

from dart_sast.engine.finding import Severity
from dart_sast.engine.registry import register_rule
from dart_sast.engine.rule import RegexRule


@register_rule
class SensitiveErrorMessageRule(RegexRule):
    rule_id = "DART-SAST-CWE209"
    cwe = "CWE-209"
    title = "Generation of Error Message Containing Sensitive Information"
    description = (
        "The raw exception/stack trace (e.toString(), e.runtimeType, "
        "stackTrace) is rendered directly to the user interface (a Text/"
        "SnackBar widget) or returned in an HTTP response body. Internal "
        "exception details can reveal file paths, library versions, query "
        "text, or other internals useful to an attacker."
    )
    severity = Severity.LOW
    recommendation = (
        "Show a generic, user-friendly error message in the UI/response, "
        "and log the full exception/stack trace only to a server-side or "
        "developer-only sink."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/209.html",
        "https://owasp.org/www-community/Improper_Error_Handling",
    )
    patterns = (
        re.compile(r"(?i)\bText\s*\(\s*e(?:rror)?\.toString\(\)"),
        re.compile(r"(?i)\bText\s*\(\s*['\"]\$\{?\s*e(?:rror)?\b"),
        re.compile(r"(?i)SnackBar\([^)]*\be(?:rror)?\.toString\(\)"),
        re.compile(r"(?i)response\.(?:body|write)\s*\([^)]*\bstack[Tt]race\b"),
    )
