"""Regex-based Dart/Flutter security rules.

The scanner intentionally uses transparent heuristics instead of a full Dart AST
so the artifact remains lightweight, easy to review, and reproducible in CI.
Rules are conservative and focused on patterns commonly found in Flutter apps.
"""
from __future__ import annotations

import re
from typing import List

from dart_sast.models import Finding, SourceFile
from dart_sast.rules.base import Rule, RuleMetadata, is_comment_only, line_matches


class RegexRule(Rule):
    """A reusable line-oriented rule driven by one or more regular expressions."""

    patterns: list[re.Pattern[str]] = []
    message = "Potential security issue detected."

    def scan(self, source: SourceFile) -> List[Finding]:
        findings: List[Finding] = []
        for pattern in self.patterns:
            for line_no, column, line, _ in line_matches(source, pattern):
                if not is_comment_only(line):
                    findings.append(self.finding(source, line_no, column, line, self.message))
        return findings


class HardcodedSecretRule(RegexRule):
    metadata = RuleMetadata("DART-SAST-001", "CWE-798", "Hardcoded credential", "high", "Move secrets to a secure vault or runtime environment variables.")
    patterns = [re.compile(r"(?i)\b(api[_-]?key|secret|token|password|passwd|client[_-]?secret)\b\s*[:=]\s*['\"][^'\"]{6,}['\"]")]
    message = "Credential-like value appears to be hardcoded."


class InsecureHttpRule(RegexRule):
    metadata = RuleMetadata("DART-SAST-002", "CWE-319", "Unencrypted communication", "high", "Use HTTPS and reject plaintext endpoints in production.")
    patterns = [re.compile(r"['\"]http://[^'\"]+['\"]")]
    message = "Plain HTTP endpoint found."


class WeakCryptoRule(RegexRule):
    metadata = RuleMetadata("DART-SAST-003", "CWE-327", "Weak or broken cryptography", "high", "Use modern cryptographic primitives such as AES-GCM, SHA-256/512, or platform security APIs.")
    patterns = [re.compile(r"(?i)\b(md5|sha1|des|rc4)\b")]
    message = "Weak or broken cryptographic algorithm referenced."


class InsecureRandomRule(RegexRule):
    metadata = RuleMetadata("DART-SAST-004", "CWE-338", "Insecure pseudo-random number generation", "medium", "Use Random.secure() for security-sensitive randomness.")
    patterns = [re.compile(r"\bRandom\s*\(\s*\)")]
    message = "Random() is not suitable for tokens, secrets, or security-sensitive values."


class SqlInjectionRule(RegexRule):
    metadata = RuleMetadata("DART-SAST-005", "CWE-89", "Potential SQL injection", "critical", "Use parameterized queries or prepared statements.")
    patterns = [re.compile(r"(?i)\b(rawQuery|execute|query)\s*\([^\n]*(\$\{|\+)")]
    message = "SQL statement appears to include string interpolation or concatenation."


class SensitiveLogRule(RegexRule):
    metadata = RuleMetadata("DART-SAST-006", "CWE-532", "Sensitive information in logs", "medium", "Remove sensitive values from logs or mask them before logging.")
    patterns = [re.compile(r"(?i)\b(print|debugPrint|log)\s*\([^\n]*(password|token|secret|authorization|cookie)")]
    message = "Sensitive data may be written to logs."


class DebugSensitiveRule(RegexRule):
    metadata = RuleMetadata("DART-SAST-007", "CWE-215", "Sensitive information in debug code", "medium", "Avoid exposing sensitive values in debug-only messages or assertions.")
    patterns = [re.compile(r"(?i)\b(assert|debugPrint)\s*\([^\n]*(password|token|secret|key)")]
    message = "Debug code may expose sensitive information."


class CleartextStorageRule(RegexRule):
    metadata = RuleMetadata("DART-SAST-008", "CWE-312", "Cleartext storage of sensitive information", "high", "Store sensitive data with flutter_secure_storage, Keychain, or Android Keystore.")
    patterns = [re.compile(r"(?i)\b(SharedPreferences|File\s*\(|writeAsString|Hive\.box)\b[^\n]*(password|token|secret|jwt)")]
    message = "Sensitive data may be stored in cleartext."


class BadCertificateValidationRule(RegexRule):
    metadata = RuleMetadata("DART-SAST-009", "CWE-295", "Improper certificate validation", "critical", "Do not bypass certificate validation; implement pinning carefully if needed.")
    patterns = [re.compile(r"badCertificateCallback\s*=\s*\([^\)]*\)\s*=>\s*true"), re.compile(r"onBadCertificate\s*:\s*\([^\)]*\)\s*=>\s*true")]
    message = "Certificate validation appears to be bypassed."


class PathTraversalRule(RegexRule):
    metadata = RuleMetadata("DART-SAST-010", "CWE-22", "Potential path traversal", "high", "Normalize paths and enforce an allowlisted base directory.")
    patterns = [re.compile(r"\bFile\s*\([^\n]*(\$\{|\$\w+|\+|\.\.)"), re.compile(r"\bDirectory\s*\([^\n]*(\$\{|\$\w+|\+|\.\.)")]
    message = "File path is built from dynamic input or traversal sequence."


class OsCommandInjectionRule(RegexRule):
    metadata = RuleMetadata("DART-SAST-011", "CWE-78", "Potential OS command injection", "critical", "Avoid shell execution; pass fixed executable and validated arguments.")
    patterns = [re.compile(r"\bProcess\.(run|start)\s*\([^\n]*(\$\{|\+)")]
    message = "OS command appears to be built dynamically."


class SsrfRule(RegexRule):
    metadata = RuleMetadata("DART-SAST-012", "CWE-918", "Potential SSRF", "high", "Validate and allowlist outbound URLs before making requests.")
    patterns = [re.compile(r"\b(http|client)\.(get|post|put|delete)\s*\([^\n]*(Uri\.parse\s*\([^\n]*(\$\{|\+|request|url))", re.I)]
    message = "Outbound request URL appears to be influenced by dynamic input."


class SignatureVerificationRule(RegexRule):
    metadata = RuleMetadata("DART-SAST-013", "CWE-347", "Improper signature verification", "high", "Verify cryptographic signatures and reject invalid tokens or payloads.")
    patterns = [re.compile(r"(?i)(verify\s*:\s*false|ignoreSignature|validateSignature\s*:\s*false|JwtDecoder\.decode\s*\()")]
    message = "Token or signature may be decoded without verification."


class CorsWildcardRule(RegexRule):
    metadata = RuleMetadata("DART-SAST-014", "CWE-942", "Overly permissive CORS", "medium", "Restrict CORS origins to trusted domains.")
    patterns = [re.compile(r"(?i)(Access-Control-Allow-Origin[^\n]*['\"]\*['\"]|cors\s*\([^\n]*origin\s*:\s*['\"]\*)")]
    message = "Wildcard CORS origin found."


class SensitiveGetRule(RegexRule):
    metadata = RuleMetadata("DART-SAST-015", "CWE-598", "Sensitive data in GET request", "medium", "Use POST body or headers for sensitive data and avoid query-string secrets.")
    patterns = [re.compile(r"(?i)\bget\s*\([^\n]*(password|token|secret|apikey|api_key)=")]
    message = "GET request URL appears to include sensitive data."


class ImproperAuthRule(RegexRule):
    metadata = RuleMetadata("DART-SAST-016", "CWE-287", "Improper authentication", "high", "Do not hardcode authentication bypasses; enforce server-side authorization.")
    patterns = [re.compile(r"(?i)(isAuthenticated\s*=\s*true|authBypass\s*=\s*true|skipAuth\s*[:=]\s*true)")]
    message = "Authentication bypass or forced authenticated state found."


class VerboseErrorRule(RegexRule):
    metadata = RuleMetadata("DART-SAST-017", "CWE-209", "Verbose error message", "medium", "Return generic errors to users and keep sensitive details in protected logs.")
    patterns = [re.compile(r"(?i)(catch\s*\([^\)]*e[^\)]*\)\s*\{[^\n]*(return|throw|print).*\be\b|e\.stackTrace|StackTrace\.current)")]
    message = "Error details or stack traces may be exposed."


class WeakPasswordRule(RegexRule):
    metadata = RuleMetadata("DART-SAST-018", "CWE-521", "Weak password requirements", "medium", "Require adequate password length and complexity or use established identity providers.")
    patterns = [re.compile(r"(?i)(password\.length\s*<\s*[1-7]\b|minLength\s*[:=]\s*[1-7]\b)")]
    message = "Password policy appears too weak."


class InsecureWebViewRule(RegexRule):
    metadata = RuleMetadata("DART-SAST-019", "CWE-749", "Dangerous WebView capability", "medium", "Disable JavaScript unless strictly required and restrict loaded origins.")
    patterns = [re.compile(r"JavaScriptMode\.unrestricted|javascriptMode\s*:\s*JavascriptMode\.unrestricted")]
    message = "WebView JavaScript is unrestricted."


class AndroidExportedRule(RegexRule):
    metadata = RuleMetadata("DART-SAST-020", "CWE-926", "Improper export of Android component", "high", "Avoid exported Android components unless protected by permissions.")
    file_kinds = ("manifest",)
    patterns = [re.compile(r"android:exported\s*=\s*['\"]true['\"]")]
    message = "Android component is exported. Confirm it is protected by a permission."


ALL_REGEX_RULES = [
    HardcodedSecretRule(), InsecureHttpRule(), WeakCryptoRule(), InsecureRandomRule(),
    SqlInjectionRule(), SensitiveLogRule(), DebugSensitiveRule(), CleartextStorageRule(),
    BadCertificateValidationRule(), PathTraversalRule(), OsCommandInjectionRule(), SsrfRule(),
    SignatureVerificationRule(), CorsWildcardRule(), SensitiveGetRule(), ImproperAuthRule(),
    VerboseErrorRule(), WeakPasswordRule(), InsecureWebViewRule(), AndroidExportedRule(),
]
