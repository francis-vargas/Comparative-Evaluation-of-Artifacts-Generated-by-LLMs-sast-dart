import re

from dart_sast.engine.finding import Severity
from dart_sast.engine.registry import register_rule
from dart_sast.engine.rule import RegexRule

_PROC_SINKS = r"(?:Process\.run|Process\.runSync|Process\.start)"


@register_rule
class OsCommandInjectionRule(RegexRule):
    rule_id = "DART-SAST-CWE78"
    cwe = "CWE-78"
    title = "OS Command Injection"
    description = (
        "Process.run/runSync/start is invoked with a command or argument "
        "string built via concatenation or interpolation from a variable, "
        "instead of passing a fixed executable with a separate argument "
        "list. If any part of that string is influenced by external input, "
        "an attacker can inject additional shell commands."
    )
    severity = Severity.CRITICAL
    recommendation = (
        "Pass the executable and each argument as separate list elements "
        "(Process.run('git', ['clone', url])) instead of building a single "
        "shell command string, and avoid runInShell: true with untrusted "
        "input."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/78.html",
        "https://owasp.org/www-community/attacks/Command_Injection",
    )
    patterns = (
        re.compile(rf"(?i){_PROC_SINKS}\s*\(\s*['\"][^'\"]*\$\{{?\w"),
        re.compile(rf"(?i){_PROC_SINKS}\s*\(\s*['\"][^'\"]*['\"]\s*\+\s*\w"),
        re.compile(r"(?i)runInShell\s*:\s*true"),
    )
