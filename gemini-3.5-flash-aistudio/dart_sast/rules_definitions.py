import re

RULES = [
    {
        "id": "DS-001",
        "cwe": "CWE-798",
        "name": "Hardcoded Credentials",
        "severity": "HIGH",
        "description": "Detection of potentially hardcoded secrets, api keys, or passwords in Dart code.",
        "patterns": [
            r"(?i)(api_key|apikey|secret|password|private_key|token|oauth_token)\s*=\s*['\"][a-zA-Z0-9_\-\.\=\+\/]{16,}['\"]",
            r"(?i)const\s+(api_key|apikey|secret|password|private_key|token)\s*=\s*['\"][^'\"]+['\"]"
        ],
        "recommendation": "Use environment variables (String.fromEnvironment) or secure storage vaults (Flutter Secure Storage) to manage credentials. Never commit secrets to version control."
    },
    {
        "id": "DS-002",
        "cwe": "CWE-319",
        "name": "Unencrypted Communication",
        "severity": "HIGH",
        "description": "Use of unencrypted HTTP protocols instead of HTTPS for network requests.",
        "patterns": [
            r"['\"]http:\/\/[a-zA-Z0-9\-\.\/\?&\=]+['\"]",
            r"HttpClient\(\)\s*\.\.\s*connectionTimeout"
        ],
        "recommendation": "Enforce HTTPS for all network communication to prevent eavesdropping and man-in-the-middle attacks."
    },
    {
        "id": "DS-003",
        "cwe": "CWE-327",
        "name": "Weak Cryptographic Algorithm",
        "severity": "HIGH",
        "description": "Use of weak, broken, or deprecated cryptographic hash functions like MD5 or SHA1.",
        "patterns": [
            r"\bmd5\b",
            r"\bsha1\b",
            r"CryptoUtils\.encryptDES",
            r"\bDES\b"
        ],
        "recommendation": "Use strong cryptographic hash functions like SHA-256 or SHA-512. For encryption, use AES-GCM 256."
    },
    {
        "id": "DS-004",
        "cwe": "CWE-338",
        "name": "Insecure Pseudo-Random Number Generation",
        "severity": "MEDIUM",
        "description": "Using non-cryptographic Random() for security-sensitive operations like token or session generation.",
        "patterns": [
            r"\bRandom\(\)",
            r"math\.Random\(\)"
        ],
        "recommendation": "Use Random.secure() from 'dart:math' to generate cryptographically secure random numbers for tokens, salts, or passwords."
    },
    {
        "id": "DS-005",
        "cwe": "CWE-89",
        "name": "SQL Injection",
        "severity": "HIGH",
        "description": "Constructing SQL queries dynamically using string interpolation or concatenation, risking injection.",
        "patterns": [
            r"execute\(\s*['\"].*?\$[a-zA-Z0-9_].*?['\"]\s*\)",
            r"rawQuery\(\s*['\"].*?\$[a-zA-Z0-9_].*?['\"]\s*\)",
            r"rawInsert\(\s*['\"].*?\$[a-zA-Z0-9_].*?['\"]\s*\)"
        ],
        "recommendation": "Use parameterized queries or prepared statements instead of directly interpolating variables into SQL strings."
    },
    {
        "id": "DS-006",
        "cwe": "CWE-532",
        "name": "Sensitive Information Leak in Logs",
        "severity": "MEDIUM",
        "description": "Logging of potentially sensitive data (passwords, tokens, keys) in console or logger outputs.",
        "patterns": [
            r"\bprint\(\s*['\"].*?(password|token|secret|key|auth).*?['\"]\s*\)",
            r"log\(\s*.*?['\"].*?(password|token|secret|key|auth).*?['\"]\s*\)",
            r"logger\.(d|i|w|e|v|log)\(.*?password.*?\)"
        ],
        "recommendation": "Mask or strip sensitive values from log parameters, and disable debug logging in production environments."
    },
    {
        "id": "DS-007",
        "cwe": "CWE-215",
        "name": "Sensitive Info in Debug Code",
        "severity": "LOW",
        "description": "Assertions or developer logs that expose private internal states or sensitive information.",
        "patterns": [
            r"\bassert\(\s*.*?(password|token|secret|key|auth).*?\)",
            r"developer\.log\(\s*.*?(password|token|secret|key|auth).*?\)"
        ],
        "recommendation": "Remove debug assertions and developer logging statements that output credentials or personal data before publishing."
    },
    {
        "id": "DS-008",
        "cwe": "CWE-312",
        "name": "Cleartext Storage of Sensitive Information",
        "severity": "HIGH",
        "description": "Storing sensitive information in plaintext (e.g., raw SharedPreferences, Hive or Sqflite without encryption).",
        "patterns": [
            r"SharedPreferences\.getInstance\(\)",
            r"Hive\.openBox\(",
            r"FlutterSecureStorage\(\)\s*.*\s*write.*?value:\s*['\"][^'\"]+['\"]"
        ],
        "recommendation": "Use flutter_secure_storage for standard credentials, or encrypted databases (like SQLCipher or encrypted Hive boxes) for large data structures."
    },
    {
        "id": "DS-009",
        "cwe": "CWE-295",
        "name": "Improper Certificate Validation",
        "severity": "HIGH",
        "description": "Accepting self-signed certificates or bypassing SSL certificate validation checks entirely.",
        "patterns": [
            r"badCertificateCallback\s*=\s*.*?=>\s*true",
            r"onBadCertificate\s*=\s*.*?=>\s*true"
        ],
        "recommendation": "Do not bypass certificate validation in production. Implement proper SSL pinning or trust valid CA chains."
    },
    {
        "id": "DS-010",
        "cwe": "CWE-22",
        "name": "Path Traversal",
        "severity": "MEDIUM",
        "description": "Using unvalidated file paths in file input/output operations, enabling directory traversal via '..'.",
        "patterns": [
            r"File\(\s*.*?['\"].*?\$[a-zA-Z0-9_].*?['\"]\s*\)",
            r"Directory\(\s*.*?['\"].*?\$[a-zA-Z0-9_].*?['\"]\s*\)"
        ],
        "recommendation": "Sanitize and validate input paths using path.canonicalize, and restrict access to dedicated app storage directories."
    },
    {
        "id": "DS-011",
        "cwe": "CWE-926",
        "name": "Improper Android Component Export",
        "severity": "MEDIUM",
        "description": "Android component (Activity, Service, Receiver) exported without restrictions in AndroidManifest.xml.",
        "patterns": [
            r"android:exported\s*=\s*['\"]true['\"]"
        ],
        "recommendation": "Set android:exported='false' for components that do not need to be called by external applications. If exported, secure with permissions."
    },
    {
        "id": "DS-012",
        "cwe": "CWE-1104",
        "name": "Unmaintained or Vulnerable Dependency",
        "severity": "MEDIUM",
        "description": "Use of deprecated, non-null-safe, or unmaintained libraries in pubspec.yaml.",
        "patterns": [
            r"\b(http_multi_server|uuid_enhanced|flutter_local_auth_device)\s*:\s*"
        ],
        "recommendation": "Regularly audit dependencies in pubspec.yaml. Upgrade to modern, fully maintained Flutter plugins."
    },
    {
        "id": "DS-013",
        "cwe": "CWE-78",
        "name": "OS Command Injection",
        "severity": "HIGH",
        "description": "Passing unvalidated user inputs directly into OS shell commands via Process.run or Process.start.",
        "patterns": [
            r"Process\.run\(\s*.*?\$[a-zA-Z0-9_]",
            r"Process\.runWithShell\(\s*.*?\$[a-zA-Z0-9_]",
            r"Process\.start\(\s*.*?\$[a-zA-Z0-9_]"
        ],
        "recommendation": "Avoid shell execution. If necessary, pass arguments as a structured List of strings instead of dynamic shell command interpolation."
    },
    {
        "id": "DS-014",
        "cwe": "CWE-918",
        "name": "Server-Side Request Forgery (SSRF)",
        "severity": "HIGH",
        "description": "Allowing arbitrary user inputs to specify HTTP request destinations, leading to internal resource exploitation.",
        "patterns": [
            r"http\.get\(\s*Uri\.parse\(\s*.*?\$[a-zA-Z0-9_]",
            r"Dio\(\)\.get\(\s*.*?\$[a-zA-Z0-9_]"
        ],
        "recommendation": "Restrict outgoing connection domains to a strict whitelist. Never request raw, unvalidated client-controlled URLs."
    },
    {
        "id": "DS-015",
        "cwe": "CWE-347",
        "name": "Improper Verification of Cryptographic Signature",
        "severity": "HIGH",
        "description": "Verifying JSON Web Tokens (JWT) or cryptographic keys without fully validating their signatures.",
        "patterns": [
            r"verifyJWT\(\s*.*?,.*?verify:\s*false",
            r"checkSignature\s*=\s*false"
        ],
        "recommendation": "Always enforce cryptographic signature verification on JWTs and check the integrity of incoming assets."
    },
    {
        "id": "DS-016",
        "cwe": "CWE-942",
        "name": "Permissive CORS Configuration",
        "severity": "MEDIUM",
        "description": "Configuring excessively loose Access-Control-Allow-Origin headers in backend shelf/HTTP server routers.",
        "patterns": [
            r"Access-Control-Allow-Origin\s*.*?\*",
            r"cors\(\s*origin:\s*['\"]\*['\"]"
        ],
        "recommendation": "Define precise origin whitelists instead of wildcard '*' settings, especially on APIs processing session cookies or tokens."
    },
    {
        "id": "DS-017",
        "cwe": "CWE-598",
        "name": "Sensitive Data exposed in GET Requests",
        "severity": "HIGH",
        "description": "Passing user credentials or tokens via GET request query parameters, exposing them in routing logs and history.",
        "patterns": [
            r"http\.get\(\s*Uri\.parse\(['\"].*?(password|token|secret)=\$",
            r"Dio\(\)\.get\(['\"].*?(password|token|secret)=\$"
        ],
        "recommendation": "Transmit sensitive credentials or tokens inside secure request body payloads (POST, PUT) or Authorization request headers."
    },
    {
        "id": "DS-018",
        "cwe": "CWE-287",
        "name": "Improper Authentication",
        "severity": "HIGH",
        "description": "Flawed authentication controls, such as bypassable local biometric checks or incomplete validation flows.",
        "patterns": [
            r"^\s*authenticateWithBiometrics\(\)\s*;",
            r"localAuth\.authenticate\(\s*.*?\)\s*;\s*\/\/\s*ignore"
        ],
        "recommendation": "Properly handle authentication response booleans and exceptions, and require a secondary check on critical business steps."
    },
    {
        "id": "DS-019",
        "cwe": "CWE-209",
        "name": "Sensitive Information in Error Messages",
        "severity": "LOW",
        "description": "Catching exceptions and displaying full stack traces or raw database errors directly to client screens or public files.",
        "patterns": [
            r"\bprint\((e|err|ex|exception)\)",
            r"showDialog\(.*?content:\s*Text\((e|err|ex)\.toString\(\)\)"
        ],
        "recommendation": "Provide user-friendly, high-level generic error alerts in UI screens, and write complete detailed exceptions strictly to secure, internal log files."
    },
    {
        "id": "DS-020",
        "cwe": "CWE-521",
        "name": "Weak Password Requirements",
        "severity": "MEDIUM",
        "description": "Password validation checking only minimal length without complexity checks.",
        "patterns": [
            r"password\.length\s*>\s*[0-6]",
            r"password\.isNotEmpty"
        ],
        "recommendation": "Enforce robust password validation rules: minimum length of 8+ characters, symbols, uppercase and lowercase letters, and digits."
    }
]
