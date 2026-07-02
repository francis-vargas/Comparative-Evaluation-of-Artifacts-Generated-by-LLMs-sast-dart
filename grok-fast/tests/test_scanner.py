"""Tests for dart_sast."""

import os
import pytest
from src.dart_sast.scanner import DartSASTScanner

def test_vulnerable_detection():
    scanner = DartSASTScanner()
    findings = scanner.scan_file("examples/vulnerable.dart")
    assert len(findings) > 0
    rule_ids = [f.rule_id for f in findings]
    assert "DART-001" in rule_ids  # hardcoded
    assert "DART-002" in rule_ids  # sql

def test_clean_code():
    scanner = DartSASTScanner()
    findings = scanner.scan_file("examples/clean.dart")
    assert len(findings) == 0

def test_directory_scan():
    scanner = DartSASTScanner()
    findings = scanner.scan_directory("examples")
    assert len(findings) > 0