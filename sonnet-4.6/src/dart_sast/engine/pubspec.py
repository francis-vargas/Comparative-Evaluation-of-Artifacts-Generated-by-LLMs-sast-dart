"""A minimal, dependency-free parser for the subset of YAML used by pubspec.yaml.

Design rationale (OBSERVAÇÕES FINAIS: "Não use dependências externas
desnecessárias")
------------------------------------------------------------------------
`pubspec.yaml` files use a small, predictable subset of YAML: nested block
mappings, block lists ("- item"), and occasionally an inline flow map for
git/path dependencies (``pkg: {git: {url: ..., ref: ...}}``). Rather than
pull in PyYAML as a hard dependency for this narrow need, we implement a
small indentation-based parser here. It is intentionally not a general
YAML parser -- it only needs to be correct for pubspec.yaml files.
"""

from __future__ import annotations

import re
from typing import Any


class PubspecParseError(ValueError):
    pass


def _strip_comment(line: str) -> str:
    # Remove trailing comments, but do not touch '#' inside quotes.
    result = []
    in_single = False
    in_double = False
    for ch in line:
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            break
        result.append(ch)
    return "".join(result)


def _parse_scalar(raw: str) -> Any:
    raw = raw.strip()
    if raw == "" or raw == "~" or raw.lower() == "null":
        return None
    if raw.lower() == "true":
        return True
    if raw.lower() == "false":
        return False
    if (raw.startswith('"') and raw.endswith('"')) or (
        raw.startswith("'") and raw.endswith("'")
    ):
        return raw[1:-1]
    if re.fullmatch(r"-?\d+", raw):
        return int(raw)
    if re.fullmatch(r"-?\d+\.\d+", raw):
        return float(raw)
    if raw.startswith("{") and raw.endswith("}"):
        return _parse_flow_map(raw)
    return raw


def _parse_flow_map(raw: str) -> dict:
    """Very small parser for one-line flow maps like ``{git: {url: x}}``."""

    inner = raw.strip()[1:-1].strip()
    result: dict = {}
    if not inner:
        return result
    depth = 0
    current = []
    parts = []
    for ch in inner:
        if ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    if current:
        parts.append("".join(current))

    for part in parts:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        key = key.strip().strip('"').strip("'")
        result[key] = _parse_scalar(value.strip())
    return result


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def parse_pubspec(text: str) -> dict:
    """Parse pubspec.yaml text into a nested dict/list structure."""

    raw_lines = text.splitlines()
    lines = []
    for line in raw_lines:
        stripped = _strip_comment(line).rstrip()
        if stripped.strip() == "":
            continue
        if stripped.strip() == "---":
            continue
        lines.append(stripped)

    pos = 0

    def parse_block(indent: int) -> Any:
        nonlocal pos
        mapping: dict = {}
        seq: list = []
        is_seq: bool | None = None

        while pos < len(lines):
            line = lines[pos]
            cur_indent = _indent_of(line)
            if cur_indent < indent:
                break
            if cur_indent > indent:
                # Unexpected extra indentation; treat as part of previous scalar.
                pos += 1
                continue

            content = line[indent:]

            if content.startswith("- "):
                if is_seq is None:
                    is_seq = True
                item_content = content[2:]
                pos += 1
                if ":" in item_content and not item_content.strip().startswith(("{", "[")):
                    # Sequence item is itself a small mapping starting inline.
                    key, _, value = item_content.partition(":")
                    sub: dict = {}
                    key = key.strip().strip('"').strip("'")
                    value = value.strip()
                    if value:
                        sub[key] = _parse_scalar(value)
                    else:
                        sub[key] = parse_block(indent + 2)
                    seq.append(sub)
                else:
                    seq.append(_parse_scalar(item_content))
                continue

            if is_seq:
                break

            is_seq = False
            if ":" not in content:
                pos += 1
                continue
            key, _, value = content.partition(":")
            key = key.strip().strip('"').strip("'")
            value = value.strip()
            pos += 1
            if value == "":
                # Look ahead: nested block or empty value.
                if pos < len(lines) and _indent_of(lines[pos]) > indent:
                    mapping[key] = parse_block(_indent_of(lines[pos]))
                else:
                    mapping[key] = None
            else:
                mapping[key] = _parse_scalar(value)

        return seq if is_seq else mapping

    return parse_block(0)
