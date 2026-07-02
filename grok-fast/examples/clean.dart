// Clean Dart example

import 'dart:io';
import 'package:envied/envied.dart';

@Envied(path: '.env')
abstract class Env {
  @EnviedField(varName: 'API_KEY')
  static const String apiKey = _Env.apiKey;
}

void main() {
  final safeQuery = "SELECT * FROM users WHERE id = ?";
  // Use parameterized queries
  print("Clean code - no hard-coded secrets");
}