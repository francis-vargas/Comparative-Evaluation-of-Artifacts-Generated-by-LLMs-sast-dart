import 'dart:io';
import 'dart:math';
import 'package:http/http.dart' as http;

void main() async {
  final apiKey = "AKIA_TEST_SECRET_123456";
  final url = "http://example.com/api";
  final digest = md5.convert([]);
  final token = Random().nextInt(999999).toString();
  final user = "admin";
  final sql = "SELECT * FROM users WHERE name = '${user}'";
  await db.rawQuery(sql + " AND active = 1");
  print("password=$apiKey token=$token");
  assert(apiKey.isNotEmpty, "secret key is $apiKey");
  await File("/tmp/$user-token.txt").writeAsString("token=$token");
  final client = HttpClient();
  client.badCertificateCallback = (cert, host, port) => true;
  await Process.run("sh", ["-c", "cat " + user]);
  await http.get(Uri.parse(request.url));
  JwtDecoder.decode(token);
  headers['Access-Control-Allow-Origin'] = '*';
  await http.get(Uri.parse("https://example.com/login?password=123456"));
  var isAuthenticated = true;
  try { throw Exception("boom"); } catch (e) { return print(e); }
  if (password.length < 6) { throw Exception("weak"); }
  final mode = JavaScriptMode.unrestricted;
}
