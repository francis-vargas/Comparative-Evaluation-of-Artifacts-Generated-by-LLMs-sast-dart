import unittest
import os
import sys

# Ensure dart_sast can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dart_sast.engine import SASTEngine

class TestSASTRules(unittest.TestCase):
    """
    Automated test suite verifying the scanner behavior on both vulnerable and clean files.
    Fulfills SBRC 2026 SeloR (Reprodutibilidade) & Part 5 of design instructions.
    """

    @classmethod
    def setUpClass(cls):
        cls.engine = SASTEngine()
        cls.test_dir = os.path.dirname(os.path.abspath(__file__))
        cls.vulnerable_dart = os.path.join(cls.test_dir, "vulnerable_example.dart")
        cls.clean_dart = os.path.join(cls.test_dir, "clean_example.dart")
        cls.vulnerable_manifest = os.path.join(cls.test_dir, "AndroidManifest.xml")
        cls.vulnerable_pubspec = os.path.join(cls.test_dir, "pubspec.yaml")

    def test_vulnerable_file_detections(self):
        """Test that the engine identifies security vulnerabilities on the vulnerable Dart file."""
        findings = self.engine.scan_file(self.vulnerable_dart)
        cwes_found = {f["cwe"] for f in findings}
        
        # Verify that multiple targeted CWEs are successfully detected
        self.assertIn("CWE-798", cwes_found, "Failed to detect Hardcoded Credentials (CWE-798)")
        self.assertIn("CWE-312", cwes_found, "Failed to detect Cleartext Storage (CWE-312)")
        self.assertIn("CWE-319", cwes_found, "Failed to detect Unencrypted HTTP (CWE-319)")
        self.assertIn("CWE-327", cwes_found, "Failed to detect Weak Crypto Algorithm (CWE-327)")
        self.assertIn("CWE-338", cwes_found, "Failed to detect Weak PRNG (CWE-338)")
        self.assertIn("CWE-89", cwes_found, "Failed to detect SQL Injection (CWE-89)")
        self.assertIn("CWE-532", cwes_found, "Failed to detect Sensitive Leak in Logs (CWE-532)")
        self.assertIn("CWE-215", cwes_found, "Failed to detect Debug Assert Leak (CWE-215)")
        self.assertIn("CWE-295", cwes_found, "Failed to detect Bad SSL Override (CWE-295)")
        self.assertIn("CWE-22", cwes_found, "Failed to detect Path Traversal (CWE-22)")
        self.assertIn("CWE-78", cwes_found, "Failed to detect OS Command Injection (CWE-78)")
        self.assertIn("CWE-918", cwes_found, "Failed to detect SSRF (CWE-918)")
        self.assertIn("CWE-347", cwes_found, "Failed to detect Bypass JWT Signature (CWE-347)")
        self.assertIn("CWE-598", cwes_found, "Failed to detect Secret GET Param (CWE-598)")
        self.assertIn("CWE-287", cwes_found, "Failed to detect Insecure Auth Bypass (CWE-287)")
        self.assertIn("CWE-209", cwes_found, "Failed to detect Exposed Stack in Catch (CWE-209)")
        self.assertIn("CWE-521", cwes_found, "Failed to detect Weak Password Rule (CWE-521)")

    def test_clean_file_no_detections(self):
        """Test that the engine reports ZERO findings on the cleanly-patched secure file."""
        findings = self.engine.scan_file(self.clean_dart)
        self.assertEqual(len(findings), 0, f"False positives detected on clean file: {[f['name'] for f in findings]}")

    def test_manifest_detections(self):
        """Test that Android manifest exports are successfully flagged."""
        findings = self.engine.scan_file(self.vulnerable_manifest)
        cwes_found = {f["cwe"] for f in findings}
        self.assertIn("CWE-926", cwes_found, "Failed to detect Exported Android Component (CWE-926)")

    def test_pubspec_detections(self):
        """Test that unmaintained package references are successfully flagged."""
        findings = self.engine.scan_file(self.vulnerable_pubspec)
        cwes_found = {f["cwe"] for f in findings}
        self.assertIn("CWE-1104", cwes_found, "Failed to detect Unmaintained Dependency (CWE-1104)")

if __name__ == "__main__":
    unittest.main()
