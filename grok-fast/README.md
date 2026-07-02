# dart_sast

Static Application Security Testing (SAST) tool for Dart and Flutter applications.

## Problem and Motivation

Dart/Flutter apps often handle sensitive data, network calls, and file operations. Manual security reviews are error-prone. dart_sast provides automated detection of common vulnerabilities based on OWASP and CWE for the Dart ecosystem.

## Features

- Detects multiple CWEs relevant to Dart/Flutter
- CLI with JSON output for CI/CD integration
- Modular rule system
- Supports single files and directories
- GitHub Actions ready

## Dependencies

- Python 3.9+
- No external dependencies beyond standard library

## Installation

```bash
# Clone the repo
git clone https://github.com/yourusername/dart_sast.git
cd dart_sast

# Install as package
pip install -e .

# Or use directly
python -m dart_sast.cli <target>
```

## Usage Examples

```bash
# Scan a file
dart-sast path/to/app.dart

# Scan directory
dart-sast ./lib

# JSON output
dart-sast ./lib --format json --output results.json

# In CI/CD
dart-sast ./ --format json || echo "Vulnerabilities found"
```

## Running Tests

```bash
python -m pytest tests/ -v
```

## Repository Structure

```
dart_sast/
├── src/dart_sast/          # Source code
│   ├── __init__.py
│   ├── cli.py
│   ├── scanner.py
│   ├── reporter.py
│   └── rules/              # Security rules (modular)
├── tests/                  # Automated tests
├── examples/               # Demo files
├── .github/workflows/      # CI/CD
├── README.md
├── LICENSE
├── pyproject.toml
└── ...
```

## References

- OWASP Mobile Top 10
- CWE Top 25
- Dart Security Best Practices

For more rules and contributions, see CONTRIBUTING.md (to be added).