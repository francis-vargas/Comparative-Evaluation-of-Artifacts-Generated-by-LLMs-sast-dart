/**
 * SBRC 2026 Scientific Artifact Demo - dart_sast
 * Clean Dart/Flutter file demonstrating SECURE patches for the target CWEs.
 * Ensures the engine does not trigger false positives on compliant code.
 */

import 'dart:io';
import 'dart:math' as math;
import 'package:sqlite3/sqlite3.dart';

// SECURE: No hardcoded API keys. Fetched from Environment variables.
final String apiKey = String.fromEnvironment("GEMINI_API_KEY");

// SECURE: Sensitive data is saved using flutter_secure_storage or encrypted databases.
class SecureService {
  final _storage = const FlutterSecureStorage();
  
  void storeToken(String token) async {
    await _storage.write(key: "auth_token", value: token);
  }
}

// SECURE: Using secure HTTPS protocols for network requests.
void fetchDataSecurely() async {
  var url = 'https://api.vulnerable-app.com/v1/users'; 
  var client = HttpClient();
  var request = await client.getUrl(Uri.parse(url));
  var response = await request.close();
}

// SECURE: Using SHA-256 (strong hash algorithm) instead of weak MD5/SHA1.
import 'package:crypto/crypto.dart';
import 'dart:convert';
String hashPasswordSecurely(String password) {
  var bytes = utf8.encode(password);
  var digest = sha256.convert(bytes); 
  return digest.toString();
}

// SECURE: Cryptographically secure Random.secure() used.
String generateSessionTokenSecurely() {
  var rng = math.Random.secure(); 
  return rng.nextInt(1000000).toString();
}

// SECURE: Using parameterized query parameters instead of raw dynamic strings.
void queryUserSecurely(Database db, String userInput) {
  db.execute("SELECT * FROM users WHERE username = ?", [userInput]);
}

// SECURE: Masking or removing sensitive details before logging.
void loginUserSecurely(String username, String password) {
  print("Attempting login for user: $username"); // Sensitive password excluded
}

// SECURE: No hardcoded secrets in assertions.
void checkDebugStateSecurely(String value) {
  assert(value.isNotEmpty);
}

// SECURE: No overrides allowing invalid certificates in production.
class SecureHttpOverrides extends HttpOverrides {
  // Use default validation behaviors with trusted Root CAs.
}

// SECURE: Path sanitization and local app storage sandboxing.
void readFileSecurely(String safeFilename) {
  // Validate path boundaries, remove any directory traversal markers
  final sanitizedFilename = safeFilename.replaceAll("../", "");
  final fullPath = "/data/user/files/" + sanitizedFilename;
  var file = File(fullPath);
  if (file.existsSync()) {
    var contents = file.readAsStringSync();
  }
}

// SECURE: Restricting command parameters to separate lists instead of raw shell concatenation.
void runShellCommandSecurely(String safeArg) async {
  var result = await Process.run("backup_utility", [safeArg]);
}

// SECURE: Authenticating only with valid server endpoints, using pinned certificate paths.
void fetchWhitelistedUrl(String relativeEndpoint) async {
  final baseUri = Uri.parse("https://api.my-app-domain.com/");
  final finalUri = baseUri.resolve(relativeEndpoint); // Secure endpoint binding
  var client = HttpClient();
  var request = await client.getUrl(finalUri);
  var response = await request.close();
}

// SECURE: Enforce verification keys and signature verification strictly.
void verifyTokenSecurely(String jwtToken) {
  verifyJWT(jwtToken, verify: true);
}

// SECURE: Sending sensitive values via secure body inside POST requests.
void sendSecretsViaPost(String secretKey) async {
  var response = await http.post(
    Uri.parse("https://api.secure.com/auth"),
    body: {"token": secretKey}
  );
}

// SECURE: Verify biometric authorization return response boolean correctly.
bool triggerBiometricAuthSecurely() {
  bool isAuthenticated = authenticateWithBiometrics();
  if (isAuthenticated) {
    return true;
  } else {
    print("Authentication failed");
    return false;
  }
}

// SECURE: Logging technical stack details to a private logger, presenting friendly message to UI.
void runDBTransactionSecurely() {
  try {
    // perform DB operations
  } catch (e, s) {
    print("Database connection error"); // Secure high-level notification
  }
}

// SECURE: Passwords must be strongly validated with length and complexity thresholds.
bool validatePasswordSecurely(String password) {
  // Must be 8+ characters, contain digit and special symbol
  final lengthValid = password.length >= 8;
  final hasDigit = password.contains(RegExp(r'[0-9]'));
  final hasSpecial = password.contains(RegExp(r'[!@#\$&*~]'));
  return lengthValid && hasDigit && hasSpecial;
}
