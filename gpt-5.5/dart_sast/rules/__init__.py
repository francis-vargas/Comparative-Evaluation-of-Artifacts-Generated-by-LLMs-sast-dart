"""Rule registry."""
from dart_sast.rules.pubspec_rules import UnmaintainedDependencyRule
from dart_sast.rules.regex_rules import ALL_REGEX_RULES

ALL_RULES = [*ALL_REGEX_RULES, UnmaintainedDependencyRule()]
