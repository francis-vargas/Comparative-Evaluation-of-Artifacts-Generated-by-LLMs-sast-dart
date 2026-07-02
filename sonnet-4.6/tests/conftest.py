from __future__ import annotations

import os

import pytest

from dart_sast.engine.registry import get_all_rules

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
CLEAN_FIXTURE = os.path.join(FIXTURES_DIR, "clean")
VULNERABLE_FIXTURE = os.path.join(FIXTURES_DIR, "vulnerable")


@pytest.fixture(scope="session")
def all_rule_ids():
    return sorted(r.rule_id for r in get_all_rules())
