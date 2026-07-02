// vulnerable_app/lib/main.dart
//
// INTENTIONALLY VULNERABLE demo file used by dart_sast's test suite and
// documentation examples. Every block below is annotated with the CWE it
// is meant to trigger. Do NOT use any of this code as a reference for real
// applications.

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

// --- CWE-798: Use of Hard-coded Credentials ---------------------------------
const String apiKey = "sk_live_51Hqz2m9d8f7g6h5j4k3l2";
const String password = "SuperSecret123";

class AuthService {
  // --- CWE-319: Cleartext Transmission of Sensitive Information -----------
  final String loginUrl = "http://api.example.com/login";

  Future<void> login(String user, String password) async {
    // --- CWE-89: SQL Injection --------------------------------------------
    final db = FakeDb();
    db.rawQuery("SELECT * FROM users WHERE name = '$user'");

    // --- CWE-532: Insertion of Sensitive Information into Log File -------
    print("Attempting login with password: $password");

    // --- CWE-215: Insertion of Sensitive Information Into Debugging Code -
    assert(password.isNotEmpty, "password was: $password");

    // --- CWE-287: Improper Authentication ---------------------------------
    if (user == "admin" && password == "admin123") {
      return;
    }
    if (password == storedPassword) {
      return;
    }
  }

  String storedPassword = "hunter2";

  // --- CWE-338: Use of Cryptographically Weak PRNG ------------------------
  String generateResetToken() {
    final tokenRandom = Random();
    return List.generate(6, (_) => tokenRandom.nextInt(10)).join();
  }

  // --- CWE-327: Use of a Broken or Risky Cryptographic Algorithm ----------
  String hashPassword(String plain) {
    return md5.convert(utf8.encode(plain)).toString();
  }

  // --- CWE-295: Improper Certificate Validation ---------------------------
  HttpClient buildInsecureClient() {
    final client = HttpClient();
    client.badCertificateCallback = (cert, host, port) => true;
    return client;
  }

  // --- CWE-347: Improper Verification of Cryptographic Signature ----------
  Map<String, dynamic> decodeJwtInsecurely(String token) {
    final options = {"algorithm": "none", "verify": false};
    return options;
  }
}

// --- CWE-312: Cleartext Storage of Sensitive Information --------------------
Future<void> saveCredentials(String token) async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString("authToken", token);
}

// --- CWE-22: Path Traversal --------------------------------------------------
Future<String> readUserFile(Map<String, String> request) async {
  final fileName = request["fileName"];
  final file = File("/data/user_files/$fileName");
  return file.readAsString();
}

// --- CWE-78: OS Command Injection --------------------------------------------
Future<void> runDiagnostics(String hostArg) async {
  await Process.run("ping -c 1 $hostArg", [], runInShell: true);
}

// --- CWE-918: Server-Side Request Forgery (SSRF) -----------------------------
Future<void> fetchWebhook(Map<String, String> request) async {
  final callbackUrl = request["callbackUrl"]!;
  await http.get(Uri.parse(callbackUrl));
}

// --- CWE-942: Permissive Cross-domain Policy (CORS) --------------------------
Map<String, String> corsHeaders() {
  return {"Access-Control-Allow-Origin": "*"};
}

// --- CWE-598: Use of GET Request Method With Sensitive Query Strings --------
Future<void> checkSession(String token) async {
  await http.get(Uri.parse("https://api.example.com/session?token=$token"));
}

// --- CWE-209: Sensitive error message exposed in UI --------------------------
class ErrorBanner extends StatelessWidget {
  final Object error;
  const ErrorBanner(this.error, {super.key});

  @override
  Widget build(BuildContext context) {
    return Text(error.toString());
  }
}

// --- CWE-521: Weak Password Requirements -------------------------------------
bool isPasswordStrongEnough(String password) {
  return password.length >= 4;
}

class FakeDb {
  void rawQuery(String sql) {}
}
