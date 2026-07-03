/**
 * SBRC 2026 Scientific Artifact Demo - dart_sast
 * Vulnerable Dart/Flutter file showcasing 20 security flaws (CWE targets)
 */

import 'dart:io';
import 'dart:math' as math;
import 'package:sqlite3/sqlite3.dart';

// CWE-798: Hardcoded Credentials
const String apiKey = "AIzaSyD-un4RkS_SECRETa128913_example";
final String stripeSecret = "sk_live_51NvM798_vulnerable_stripe_key_example";

// CWE-312: Cleartext Storage of Sensitive Information
import 'package:shared_preferences/shared_preferences.dart';
void storeData() async {
  final prefs = await SharedPreferences.getInstance();
  // VULNERABLE: Saving passwords in cleartext preferences
  prefs.setString("user_password", "mySuperSecretPassword123");
}

// CWE-319: Cleartext/Unencrypted Network Communication
void fetchData() async {
  var url = 'http://api.vulnerable-app.com/v1/users'; // VULNERABLE: http protocol
  var client = HttpClient();
  var request = await client.getUrl(Uri.parse(url));
  var response = await request.close();
}

// CWE-327: Use of a Broken or Risky Cryptographic Algorithm
import 'package:crypto/crypto.dart';
import 'dart:convert';
String hashPassword(String password) {
  // VULNERABLE: MD5 is broken/weak
  var bytes = utf8.encode(password);
  var digest = md5.convert(bytes); 
  return digest.toString();
}

// CWE-338: Use of Cryptographically Weak PRNG
String generateSessionToken() {
  var rng = math.Random(); // VULNERABLE: Insecure random number generator
  return rng.nextInt(1000000).toString();
}

// CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQLi)
void queryUser(Database db, String userInput) {
  // VULNERABLE: String interpolation in raw query
  db.execute("SELECT * FROM users WHERE username = '$userInput'");
}

// CWE-532: Insertion of Sensitive Information into Log File
void loginUser(String username, String password) {
  // VULNERABLE: Leak password to output logs
  print("Attempting login for user $username with password: $password");
}

// CWE-215: Insertion of Sensitive Information into Debug Code
void checkDebugState(String secretToken) {
  // VULNERABLE: Assertion leaks secretToken in debug runs
  assert(secretToken == "SUPER_SECRET_ASSERT_TOKEN");
}

// CWE-295: Improper Certificate Validation
class MyHttpOverrides extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return super.createHttpClient(context)
      ..badCertificateCallback = (X509Certificate cert, String host, int port) => true; // VULNERABLE: Accepts all SSL certs
  }
}

// CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
void readFile(String userFilename) {
  // VULNERABLE: Dynamic file access opens traverse to /../../etc/passwd
  var file = File("/data/user/files/$userFilename");
  var contents = file.readAsStringSync();
}

// CWE-78: Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)
void runShellCommand(String scriptArgs) async {
  // VULNERABLE: Arbitrary process execution with command injection risk
  var result = await Process.run("sh", ["-c", "run_backup.sh $scriptArgs"]);
}

// CWE-918: Server-Side Request Forgery (SSRF)
void fetchExternalUrl(String clientUrl) async {
  // VULNERABLE: Arbitrary user-controlled URL request
  var client = HttpClient();
  var request = await client.getUrl(Uri.parse(clientUrl));
  var response = await request.close();
}

// CWE-347: Improper Verification of Cryptographic Signature
void verifyToken(String jwtToken) {
  // VULNERABLE: Bypassing key or signature verification
  verifyJWT(jwtToken, verify: false);
}

// CWE-598: Use of GET Request with Sensitive Query Parameters
void sendSecretsViaGet(String secretKey) async {
  // VULNERABLE: Sending secret key as query param in GET request
  var response = await http.get(Uri.parse("https://api.secure.com/auth?token=$secretKey"));
}

// CWE-287: Improper Authentication
void triggerBiometricAuth() {
  // VULNERABLE: Incomplete or ignored biometric auth callback
  authenticateWithBiometrics(); // returns bool, ignored
}

// CWE-209: Generation of Error Message Containing Sensitive Information
void runDBTransaction() {
  try {
    // perform DB operations
  } catch (e, s) {
    // VULNERABLE: Exposing full stack and raw details to output console
    print(e);
  }
}

// CWE-521: Weak Password Requirements
bool validatePassword(String password) {
  // VULNERABLE: Only checking length, weak requirements
  return password.length > 6;
}
