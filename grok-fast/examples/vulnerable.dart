// Vulnerable Dart example for testing

const String API_KEY = "sk_live_1234567890abcdef";  // CWE-798

void main() {
  String userInput = "'; DROP TABLE users; --";
  String query = "SELECT * FROM users WHERE id = '" + userInput + "'";  // CWE-89
  
  // Path traversal
  String filePath = "../secrets.txt";
  // File(filePath).readAsStringSync();
  
  // Command injection example
  // Process.runSync('ls', ['-la', userInput]);
  
  print("Vulnerable code");
}