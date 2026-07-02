from __future__ import annotations

from dart_sast.engine.pubspec import parse_pubspec

SAMPLE = """
name: my_app
version: 1.0.0+1

environment:
  sdk: ">=3.0.0 <4.0.0"

dependencies:
  flutter:
    sdk: flutter
  http: ^1.1.0
  loose_pkg: any
  git_pkg:
    git:
      url: https://github.com/example/git_pkg.git
      ref: abc1234
  git_pkg_no_ref:
    git: https://github.com/example/other.git
  local_pkg:
    path: ../local_pkg

dev_dependencies:
  test: ^1.24.0
"""


def test_parses_simple_keys():
    data = parse_pubspec(SAMPLE)
    assert data["name"] == "my_app"
    assert data["version"] == "1.0.0+1"


def test_parses_nested_environment():
    data = parse_pubspec(SAMPLE)
    assert data["environment"]["sdk"] == ">=3.0.0 <4.0.0"


def test_parses_dependencies_versions():
    data = parse_pubspec(SAMPLE)
    deps = data["dependencies"]
    assert deps["http"] == "^1.1.0"
    assert deps["loose_pkg"] == "any"


def test_parses_git_dependency_with_ref():
    data = parse_pubspec(SAMPLE)
    git_pkg = data["dependencies"]["git_pkg"]
    assert git_pkg["git"]["ref"] == "abc1234"
    assert git_pkg["git"]["url"] == "https://github.com/example/git_pkg.git"


def test_parses_path_dependency():
    data = parse_pubspec(SAMPLE)
    assert data["dependencies"]["local_pkg"]["path"] == "../local_pkg"


def test_parses_dev_dependencies():
    data = parse_pubspec(SAMPLE)
    assert data["dev_dependencies"]["test"] == "^1.24.0"


def test_ignores_comments_and_blank_lines():
    text = "name: x # a comment\n# full line comment\n\nversion: 1.0.0\n"
    data = parse_pubspec(text)
    assert data["name"] == "x"
    assert data["version"] == "1.0.0"
