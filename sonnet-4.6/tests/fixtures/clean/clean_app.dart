// A deliberately "clean" file: mirrors the structure of the vulnerable
// example but follows secure coding practices. dart_sast must report ZERO
// findings for this file; used by tests/test_no_false_positives.py.

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class AuthService {
  final String loginUrl = "https://api.example.com/login";
  final String apiKey = String.fromEnvironment('API_KEY');

  Future<void> login(String user, String password) async {
    final db = FakeDb();
    db.rawQuery("SELECT * FROM users WHERE name = ?", [user]);

    // no sensitive data is logged
    // ignore: avoid_print
    print("Attempting login for user: $user");

    if (!constantTimeEquals(password, storedPasswordHash)) {
      return;
    }
  }

  String storedPasswordHash = "";

  bool constantTimeEquals(String a, String b) {
    if (a.length != b.length) return false;
    var result = 0;
    for (var i = 0; i < a.length; i++) {
      result |= a.codeUnitAt(i) ^ b.codeUnitAt(i);
    }
    return result == 0;
  }

  String generateResetToken() {
    final secureRandom = Random.secure();
    return List.generate(6, (_) => secureRandom.nextInt(10)).join();
  }

  String hashPassword(String plain) {
    return sha256.convert(utf8.encode(plain)).toString();
  }

  HttpClient buildSecureClient() {
    return HttpClient();
  }
}

Future<void> saveCredentials(String token) async {
  const storage = FlutterSecureStorage();
  await storage.write(key: "authToken", value: token);
}

Future<String> readUserFile(String fileName) async {
  final safeName = fileName.replaceAll(RegExp(r'[^a-zA-Z0-9._-]'), '');
  final file = File("/data/user_files/$safeName");
  return file.readAsString();
}

Future<void> runDiagnostics(String host) async {
  await Process.run("ping", ["-c", "1", host]);
}

Future<void> fetchAllowedResource(String path) async {
  await http.get(Uri.https("api.example.com", path));
}

Map<String, String> corsHeaders() {
  return {"Access-Control-Allow-Origin": "https://trusted.example.com"};
}

Future<void> checkSession(String token) async {
  await http.get(
    Uri.https("api.example.com", "/session"),
    headers: {"Authorization": "Bearer $token"},
  );
}

class ErrorBanner extends StatelessWidget {
  final Object error;
  const ErrorBanner(this.error, {super.key});

  @override
  Widget build(BuildContext context) {
    return const Text("Something went wrong. Please try again.");
  }
}

bool isPasswordStrongEnough(String password) {
  return password.length >= 12;
}

class FakeDb {
  void rawQuery(String sql, [List<Object?>? args]) {}
}
