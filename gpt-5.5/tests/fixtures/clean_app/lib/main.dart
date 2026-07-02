import 'dart:math';
import 'package:http/http.dart' as http;

void main() async {
  final endpoint = "https://example.com/api";
  final nonce = Random.secure().nextInt(999999).toString();
  await http.post(Uri.parse(endpoint), headers: {'Authorization': 'Bearer <runtime-token>'});
  final query = "SELECT * FROM users WHERE id = ?";
  await db.rawQuery(query, [42]);
  debugPrint("User flow completed");
  if (password.length < 12) { throw Exception("Invalid password"); }
}
