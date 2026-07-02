# Architecture

`dart_sast` is organized around four stable extension points:

1. **Scanner** (`dart_sast/scanner.py`): discovers supported project files and dispatches them to rules.
2. **Rules** (`dart_sast/rules/`): each rule implements the `Rule.scan(SourceFile)` contract and returns findings.
3. **Models** (`dart_sast/models.py`): typed dataclasses for findings and source files.
4. **Reporters** (`dart_sast/reporters.py`): convert findings to console, JSON, or SARIF.

This architecture was chosen to satisfy sustainability and reproducibility goals: rules do not know about the CLI, output formats, or filesystem traversal. Adding a rule requires creating a small class and registering it in `dart_sast/rules/__init__.py`.

## Adding a new rule

1. Create a class that extends `RegexRule` or `Rule`.
2. Define `RuleMetadata` with rule id, CWE, severity, title, and recommendation.
3. Add tests with vulnerable and clean snippets.
4. Register the rule in `ALL_RULES`.

## Scope and limitations

The current version is intentionally lightweight and dependency-free at runtime. It uses transparent pattern-based detection rather than full semantic analysis. Findings should be reviewed by humans before being treated as confirmed vulnerabilities.
