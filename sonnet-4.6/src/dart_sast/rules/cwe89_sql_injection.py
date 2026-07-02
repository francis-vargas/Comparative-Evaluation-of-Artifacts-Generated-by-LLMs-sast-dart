import re

from dart_sast.engine.finding import Severity
from dart_sast.engine.registry import register_rule
from dart_sast.engine.rule import RegexRule

_SQL_SINKS = r"(?:rawQuery|rawInsert|rawUpdate|rawDelete|execute|query)"


@register_rule
class SqlInjectionRule(RegexRule):
    rule_id = "DART-SAST-CWE89"
    cwe = "CWE-89"
    title = "SQL Injection"
    description = (
        "A SQL statement passed to a sqflite/moor/postgres raw-query API is "
        "built via string concatenation ('+') or string interpolation "
        "('${...}') instead of parameter binding. An attacker who controls "
        "any part of the interpolated value can alter the query's meaning."
    )
    severity = Severity.CRITICAL
    recommendation = (
        "Use parameterized queries: pass placeholders ('?') in the SQL "
        "string and supply the actual values through the whereArgs/"
        "arguments parameter instead of interpolating them into the SQL "
        "text directly."
    )
    references = (
        "https://cwe.mitre.org/data/definitions/89.html",
        "https://owasp.org/www-community/attacks/SQL_Injection",
    )
    patterns = (
        re.compile(rf"""(?i)\.{_SQL_SINKS}\s*\(\s*(['"])(?:(?!\1).)*\$\{{?\w"""),
        re.compile(rf"""(?i)\.{_SQL_SINKS}\s*\(\s*(['"])(?:(?!\1).)*\1\s*\+\s*\w"""),
        re.compile(r"(?i)\bSELECT\b.{0,120}\$\{?\w.{0,40}\bFROM\b"),
    )
