# dart_sast

`dart_sast` is a lightweight SAST (Static Application Security Testing) CLI for Dart/Flutter projects. It scans `.dart`, `pubspec.yaml`, and Android manifest files for security patterns mapped to CWE identifiers, producing console, JSON, and SARIF outputs for local use and CI/CD pipelines.

## 1. Problem and motivation

Dart/Flutter applications commonly include mobile, web, API, storage, cryptography, and dependency decisions in the same codebase. Small implementation mistakes can expose secrets, bypass TLS validation, leak sensitive data in logs, store tokens in cleartext, or introduce injection risks.

This artifact was designed for scientific artifact evaluation and practical DevSecOps use. It targets the SBRC 2026 artifact quality dimensions: availability, functionality, sustainability, and reproducibility. The SBRC artifact instructions describe the expected four seals as Available/SeloD, Functional/SeloF, Sustainable/SeloS, and Reproducible/SeloR, with README, dependencies, execution instructions, code organization, and reproducibility guidance as important evaluation elements.

## 2. Architecture and design decisions

`dart_sast` uses a modular rule registry:

- `scanner.py` discovers supported files and dispatches them to rules.
- `rules/` contains independent rule classes.
- `models.py` defines typed finding/source models.
- `reporters.py` implements output formats.
- `cli.py` exposes the command-line interface.

The design favors sustainability over hidden complexity. Rules are independent from CLI and output logic, making it simple to add new CWEs, tune patterns, or add new reporters. Runtime dependencies are intentionally avoided to keep installation reproducible and CI-friendly.

Current analysis is pattern-based, not a full Dart AST/data-flow engine. This makes the tool transparent and portable, but results should be reviewed before being treated as confirmed vulnerabilities.

## 3. Implemented rules

| Rule ID | CWE | Detection |
|---|---:|---|
| DART-SAST-001 | CWE-798 | Hardcoded credentials |
| DART-SAST-002 | CWE-319 | Plain HTTP endpoints |
| DART-SAST-003 | CWE-327 | Weak crypto such as MD5, SHA-1, DES, RC4 |
| DART-SAST-004 | CWE-338 | `Random()` for security-sensitive randomness |
| DART-SAST-005 | CWE-89 | SQL string interpolation/concatenation |
| DART-SAST-006 | CWE-532 | Sensitive values in logs |
| DART-SAST-007 | CWE-215 | Sensitive values in debug/assert code |
| DART-SAST-008 | CWE-312 | Sensitive data stored in cleartext sinks |
| DART-SAST-009 | CWE-295 | Certificate validation bypass |
| DART-SAST-010 | CWE-22 | Path traversal-prone file paths |
| DART-SAST-011 | CWE-78 | OS command injection-prone process calls |
| DART-SAST-012 | CWE-918 | Dynamic outbound URLs / SSRF risk |
| DART-SAST-013 | CWE-347 | Signature/token verification bypass |
| DART-SAST-014 | CWE-942 | Wildcard CORS |
| DART-SAST-015 | CWE-598 | Sensitive data in GET URL |
| DART-SAST-016 | CWE-287 | Authentication bypass patterns |
| DART-SAST-017 | CWE-209 | Verbose error details exposed |
| DART-SAST-018 | CWE-521 | Weak password length policy |
| DART-SAST-019 | CWE-749 | Dangerous WebView JavaScript capability |
| DART-SAST-020 | CWE-926 | Exported Android component |
| DART-SAST-021 | CWE-1104 | Obsolete/unmaintained Dart dependencies |

## 4. Dependencies and versions

Runtime:

- Python `>=3.9`
- No third-party runtime dependencies

Development/test:

- `pytest==8.2.2`
- `setuptools>=68`
- `wheel`

Tested environment:

- Python 3.9, 3.10, 3.11+
- Linux/macOS/Windows with standard Python tooling

## 5. Installation

From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
pip install -e .
```

For development:

```bash
pip install -e .[dev]
```

## 6. Usage examples

Scan a Dart/Flutter project and print console output:

```bash
dart_sast path/to/flutter_project
```

Scan one Dart file:

```bash
dart_sast lib/main.dart
```

Generate JSON:

```bash
dart_sast path/to/project --format json --output findings.json
```

Generate SARIF for GitHub code scanning or other security platforms:

```bash
dart_sast path/to/project --format sarif --output dart_sast.sarif
```

Fail a CI pipeline when high or critical findings exist:

```bash
dart_sast path/to/project --fail-on high
```

Disable a specific rule:

```bash
dart_sast path/to/project --exclude-rule DART-SAST-001
```

List rules:

```bash
dart_sast . --list-rules
```

## 7. Reproducing the artifact results

The repository includes two fixtures:

- `tests/fixtures/vulnerable_app`: intentionally vulnerable Dart/Flutter-like project.
- `tests/fixtures/clean_app`: clean project used to check false positives.

Reproduce the expected vulnerable scan:

```bash
dart_sast tests/fixtures/vulnerable_app --format json --output findings.json
python -m json.tool findings.json
```

Expected result: findings are produced for the implemented CWE set.

Reproduce the clean scan:

```bash
dart_sast tests/fixtures/clean_app --format json
```

Expected result: `count` is `0`.

## 8. Running tests

```bash
pip install -e .[dev]
pytest -q
```

The automated tests cover:

1. Positive detection for each implemented rule family.
2. No detection in the clean fixture.
3. CLI JSON output and CI failure threshold behavior.

## 9. Docker

Build:

```bash
docker build -t dart_sast:0.1.0 .
```

Run against the current directory:

```bash
docker run --rm -v "$PWD:/src" dart_sast:0.1.0 /src --format sarif --output /src/dart_sast.sarif
```

## 10. GitHub Action

This repository includes `action.yml`, allowing use as a local/composite action:

```yaml
name: dart_sast
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - uses: ./
        with:
          target: .
          format: sarif
          output: dart_sast.sarif
          fail-on: high
```

## 11. Repository structure

```text
dart_sast/
├── dart_sast/
│   ├── __init__.py
│   ├── cli.py
│   ├── models.py
│   ├── reporters.py
│   ├── scanner.py
│   └── rules/
│       ├── __init__.py
│       ├── base.py
│       ├── pubspec_rules.py
│       └── regex_rules.py
├── docs/
│   └── ARCHITECTURE.md
├── tests/
│   ├── fixtures/
│   │   ├── clean_app/
│   │   └── vulnerable_app/
│   ├── test_cli.py
│   └── test_scanner.py
├── .github/workflows/ci.yml
├── action.yml
├── Dockerfile
├── LICENSE
├── README.md
├── pyproject.toml
└── requirements-dev.txt
```

## 12. Scientific artifact checklist

| Seal | Evidence in this artifact |
|---|---|
| SeloD / Availability | MIT license, public-repository-ready structure, README, stable source layout |
| SeloF / Functionality | Installable package, executable CLI, dependency list, examples, Docker, Action |
| SeloS / Sustainability | Modular scanner/rules/reporters, architecture documentation, tests |
| SeloR / Reproducibility | Versioned dev dependencies, fixtures, deterministic tests, exact reproduction commands |

## 13. References

- CWE List, MITRE: https://cwe.mitre.org/
- OWASP Mobile Application Security: https://owasp.org/www-project-mobile-app-security/
- OWASP MASVS: https://mas.owasp.org/MASVS/
- SARIF 2.1.0: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
- SBRC 2026 artifact guidance: https://doc-artefatos.github.io/sbrc2026/
