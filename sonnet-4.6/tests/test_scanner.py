from __future__ import annotations

import os
import tempfile

from dart_sast.engine.registry import get_all_rules
from dart_sast.engine.scanner import Scanner


def _write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


def test_scanner_excludes_dart_tool_and_build_by_default():
    with tempfile.TemporaryDirectory() as tmp:
        _write(os.path.join(tmp, "lib", "main.dart"), 'const password = "abc12345";\n')
        _write(
            os.path.join(tmp, ".dart_tool", "generated.dart"),
            'const password = "abc12345";\n',
        )
        _write(
            os.path.join(tmp, "build", "ignored.dart"),
            'const password = "abc12345";\n',
        )

        scanner = Scanner(rules=get_all_rules())
        result = scanner.scan(tmp)

        scanned = {f.file_path for f in result.findings}
        assert any("lib" in p for p in scanned)
        assert not any(".dart_tool" in p for p in scanned)
        assert not any(p.startswith("build") for p in scanned)


def test_scanner_honors_custom_exclude_pattern():
    with tempfile.TemporaryDirectory() as tmp:
        _write(os.path.join(tmp, "lib", "main.dart"), 'const password = "abc12345";\n')
        _write(
            os.path.join(tmp, "lib", "legacy", "old.dart"),
            'const password = "abc12345";\n',
        )

        scanner = Scanner(rules=get_all_rules(), exclude_patterns=["lib/legacy/*"])
        result = scanner.scan(tmp)

        scanned = {f.file_path.replace(os.sep, "/") for f in result.findings}
        assert any(p == "lib/main.dart" for p in scanned)
        assert not any("legacy" in p for p in scanned)


def test_scanner_reports_file_counts():
    with tempfile.TemporaryDirectory() as tmp:
        _write(os.path.join(tmp, "lib", "main.dart"), "void main() {}\n")
        _write(os.path.join(tmp, "pubspec.yaml"), "name: x\ndependencies:\n  http: any\n")

        scanner = Scanner(rules=get_all_rules())
        result = scanner.scan(tmp)

        assert result.scanned_dart_files == 1
        assert result.pubspec_files == 1
        assert result.scanned_files == 2
