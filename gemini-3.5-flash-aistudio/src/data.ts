export interface CWETemplate {
  id: string;
  cwe: string;
  name: string;
  severity: "HIGH" | "MEDIUM" | "LOW";
  description: string;
  recommendation: string;
  vulnerableCode: string;
  secureCode: string;
}

export const CWE_TEMPLATES: CWETemplate[] = [
  {
    id: "DS-001",
    cwe: "CWE-798",
    name: "Hardcoded Credentials",
    severity: "HIGH",
    description: "Identificação de chaves de API, segredos ou senhas gravadas diretamente no código-fonte.",
    recommendation: "Use variáveis de ambiente (String.fromEnvironment) ou cofres seguros (Flutter Secure Storage) para carregar chaves. Nunca commite segredos em seu repositório de controle de versão.",
    vulnerableCode: `// Código Vulnerável: Chaves expostas no código
const String apiKey = "AIzaSyD-un4RkS_SECRETa128913_example";
final String stripeSecret = "sk_live_51NvM798_vulnerable_stripe_key_example";

void main() {
  print("Carregando chaves de API: $apiKey");
}`,
    secureCode: `// Código Seguro: Chaves carregadas por variáveis de ambiente
const String apiKey = String.fromEnvironment("GEMINI_API_KEY");

void main() {
  if (apiKey.isEmpty) {
    print("Nenhuma chave de API configurada.");
  } else {
    print("Chave carregada de forma segura do ambiente.");
  }
}`
  },
  {
    id: "DS-002",
    cwe: "CWE-319",
    name: "Cleartext Transmission",
    severity: "HIGH",
    description: "Uso do protocolo http:// sem criptografia, tornando a comunicação vulnerável a ataques man-in-the-middle.",
    recommendation: "Sempre utilize o protocolo criptografado https:// para requisições de rede.",
    vulnerableCode: `// Código Vulnerável: Comunicação sem criptografia
import 'dart:io';

void fetchData() async {
  var url = 'http://api.vulnerable-app.com/v1/users'; 
  var client = HttpClient();
  var request = await client.getUrl(Uri.parse(url));
  var response = await request.close();
}`,
    secureCode: `// Código Seguro: Uso obrigatório de HTTPS
import 'dart:io';

void fetchData() async {
  var url = 'https://api.vulnerable-app.com/v1/users'; 
  var client = HttpClient();
  var request = await client.getUrl(Uri.parse(url));
  var response = await request.close();
}`
  },
  {
    id: "DS-003",
    cwe: "CWE-327",
    name: "Weak Crypto Algorithm",
    severity: "HIGH",
    description: "Utilização de algoritmos criptográficos fracos, quebrados ou obsoletos, como MD5 ou SHA1.",
    recommendation: "Utilize hashes fortes como SHA-256 ou SHA-512. Para cifrar dados, use AES-GCM.",
    vulnerableCode: `// Código Vulnerável: Uso de MD5 (obsoleto)
import 'package:crypto/crypto.dart';
import 'dart:convert';

String hashPassword(String password) {
  var bytes = utf8.encode(password);
  var digest = md5.convert(bytes); 
  return digest.toString();
}`,
    secureCode: `// Código Seguro: Uso de SHA-256 (forte)
import 'package:crypto/crypto.dart';
import 'dart:convert';

String hashPassword(String password) {
  var bytes = utf8.encode(password);
  var digest = sha256.convert(bytes); 
  return digest.toString();
}`
  },
  {
    id: "DS-004",
    cwe: "CWE-338",
    name: "Insecure PRNG",
    severity: "MEDIUM",
    description: "Uso de geradores de números pseudo-aleatórios simples (como math.Random()) para gerar tokens ou chaves de segurança.",
    recommendation: "Use o gerador criptográfico forte Random.secure() de 'dart:math'.",
    vulnerableCode: `// Código Vulnerável: PRNG comum
import 'dart:math' as math;

String generateSessionToken() {
  var rng = math.Random(); 
  return rng.nextInt(1000000).toString();
}`,
    secureCode: `// Código Seguro: PRNG seguro
import 'dart:math' as math;

String generateSessionToken() {
  var rng = math.Random.secure(); 
  return rng.nextInt(1000000).toString();
}`
  },
  {
    id: "DS-005",
    cwe: "CWE-89",
    name: "SQL Injection",
    severity: "HIGH",
    description: "Concatenação direta de entradas do usuário em comandos SQL brutos, expondo o banco a injeção de dados maliciosos.",
    recommendation: "Sempre utilize queries parametrizadas (prepared statements) e placeholders (?).",
    vulnerableCode: `// Código Vulnerável: String interpolation no SQL
import 'package:sqlite3/sqlite3.dart';

void queryUser(Database db, String userInput) {
  db.execute("SELECT * FROM users WHERE username = '$userInput'");
}`,
    secureCode: `// Código Seguro: Uso de placeholders parametrizados
import 'package:sqlite3/sqlite3.dart';

void queryUser(Database db, String userInput) {
  db.execute("SELECT * FROM users WHERE username = ?", [userInput]);
}`
  },
  {
    id: "DS-006",
    cwe: "CWE-532",
    name: "Sensitive Info Leak in Logs",
    severity: "MEDIUM",
    description: "Vazamento de dados confidenciais (chaves, tokens, senhas) no terminal do desenvolvedor ou arquivos de log.",
    recommendation: "Remova ou mascare dados pessoais e credenciais antes de invocar comandos de impressão/log.",
    vulnerableCode: `// Código Vulnerável: Printando segredos
void loginUser(String username, String password) {
  print("Attempting login for user $username with password: $password");
}`,
    secureCode: `// Código Seguro: Sanitizando segredos antes de registrar
void loginUser(String username, String password) {
  print("Attempting login for user: $username");
}`
  },
  {
    id: "DS-007",
    cwe: "CWE-215",
    name: "Sensitive Info in Debug Code",
    severity: "LOW",
    description: "Inclusão de credenciais em declarações assert de debug, que podem persistir no ciclo de vida.",
    recommendation: "Evite asserções de validação envolvendo segredos ou chaves de segurança.",
    vulnerableCode: `// Código Vulnerável: Assert com chaves privadas
void checkDebugState(String secretToken) {
  assert(secretToken == "SUPER_SECRET_ASSERT_TOKEN");
}`,
    secureCode: `// Código Seguro: Evitar asserção de credenciais
void checkDebugState(String secretToken) {
  assert(secretToken.isNotEmpty);
}`
  },
  {
    id: "DS-008",
    cwe: "CWE-312",
    name: "Cleartext Storage",
    severity: "HIGH",
    description: "Armazenamento em texto plano de informações confidenciais em SharedPreferences locais sem cifragem.",
    recommendation: "Utilize o pacote flutter_secure_storage para gravar credenciais de forma cifrada no Keychain do iOS e Keystore do Android.",
    vulnerableCode: `// Código Vulnerável: Salvando dados sensíveis sem cifragem
import 'package:shared_preferences/shared_preferences.dart';

void storeData() async {
  final prefs = await SharedPreferences.getInstance();
  prefs.setString("user_password", "mySuperSecretPassword123");
}`,
    secureCode: `// Código Seguro: Armazenamento seguro criptografado
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

void storeData() async {
  final storage = const FlutterSecureStorage();
  await storage.write(key: "user_password", value: "mySuperSecretPassword123");
}`
  },
  {
    id: "DS-009",
    cwe: "CWE-295",
    name: "Improper Cert Validation",
    severity: "HIGH",
    description: "Burlar a validação de certificados SSL (HttpClient), expondo o tráfego do app a qualquer atacante (interceptação MITM).",
    recommendation: "Nunca retorne 'true' indiscriminadamente no badCertificateCallback. Em produção, use cadeias válidas ou SSL Pinning.",
    vulnerableCode: `// Código Vulnerável: Aceitar todos os certificados de forma insegura
import 'dart:io';

class MyHttpOverrides extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return super.createHttpClient(context)
      ..badCertificateCallback = (X509Certificate cert, String host, int port) => true;
  }
}`,
    secureCode: `// Código Seguro: Utilizar validações normais de CA confiável
import 'dart:io';

class SecureHttpOverrides extends HttpOverrides {
  // Use as validações padrão com ACs globais autorizadas.
}`
  },
  {
    id: "DS-010",
    cwe: "CWE-22",
    name: "Path Traversal",
    severity: "MEDIUM",
    description: "Concatenação insegura de arquivos com entrada do usuário sem verificar caracteres de travessia como '../'.",
    recommendation: "Sanitize os nomes de arquivos recebidos e valide que o caminho final reside estritamente no sandbox do app.",
    vulnerableCode: `// Código Vulnerável: Concatenação insegura de caminhos
import 'dart:io';

void readFile(String userFilename) {
  var file = File("/data/user/files/$userFilename");
  var contents = file.readAsStringSync();
}`,
    secureCode: `// Código Seguro: Sanitização de entrada de arquivo
import 'dart:io';

void readFile(String safeFilename) {
  final sanitizedFilename = safeFilename.replaceAll("../", "");
  final fullPath = "/data/user/files/" + sanitizedFilename;
  var file = File(fullPath);
  if (file.existsSync()) {
    var contents = file.readAsStringSync();
  }
}`
  },
  {
    id: "DS-011",
    cwe: "CWE-926",
    name: "Android Component Export",
    severity: "MEDIUM",
    description: "Declaração de atividades ou receptores expostos com android:exported='true' no AndroidManifest.xml sem proteção de permissões.",
    recommendation: "Configure android:exported='false' para componentes internos que não necessitam ser acionados por aplicativos externos.",
    vulnerableCode: `<!-- Código Vulnerável: Atividade exportada livremente -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name=".VulnerableActivity" android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
            </intent-filter>
        </activity>
    </application>
</manifest>`,
    secureCode: `<!-- Código Seguro: Atividade interna segura -->
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name=".SecureActivity" android:exported="false" />
    </application>
</manifest>`
  },
  {
    id: "DS-012",
    cwe: "CWE-1104",
    name: "Unmaintained Dependency",
    severity: "MEDIUM",
    description: "Declaração de dependências inseguras, obsoletas ou abandonadas no pubspec.yaml.",
    recommendation: "Substitua bibliotecas não mantidas por alternativas ativas e auditadas pela comunidade Flutter.",
    vulnerableCode: `# Código Vulnerável: Dependência obsoleta listada
name: vulnerable_project
dependencies:
  flutter:
    sdk: flutter
  http_multi_server: ^2.2.0
  flutter_local_auth_device: ^1.0.0`,
    secureCode: `# Código Seguro: Uso de bibliotecas atualizadas
name: secure_project
dependencies:
  flutter:
    sdk: flutter
  http: ^1.1.0
  local_auth: ^2.1.6`
  },
  {
    id: "DS-013",
    cwe: "CWE-78",
    name: "OS Command Injection",
    severity: "HIGH",
    description: "Injeção de comandos de terminal através de variáveis dinâmicas inseridas diretamente no Process.run.",
    recommendation: "Passe argumentos como um array estruturado de Strings em vez de injetá-los diretamente em uma string de execução única.",
    vulnerableCode: `// Código Vulnerável: Variável injetada na string do shell
import 'dart:io';

void runShellCommand(String scriptArgs) async {
  var result = await Process.run("sh", ["-c", "run_backup.sh $scriptArgs"]);
}`,
    secureCode: `// Código Seguro: Argumentos como lista parametrizada
import 'dart:io';

void runShellCommandSecurely(String safeArg) async {
  var result = await Process.run("backup_utility", [safeArg]);
}`
  },
  {
    id: "DS-014",
    cwe: "CWE-918",
    name: "Server-Side Request Forgery",
    severity: "HIGH",
    description: "Permitir que usuários forneçam URLs arbítrias para requisições de backend ou de rede do app.",
    recommendation: "Valide destinos contra uma whitelist estrita e evite carregar destinos diretos do cliente.",
    vulnerableCode: `// Código Vulnerável: Endpoint de rede controlado pelo cliente
import 'dart:io';

void fetchExternalUrl(String clientUrl) async {
  var client = HttpClient();
  var request = await client.getUrl(Uri.parse(clientUrl));
  var response = await request.close();
}`,
    secureCode: `// Código Seguro: Endpoints fixos ou validados em whitelist
import 'dart:io';

void fetchWhitelistedUrl(String relativeEndpoint) async {
  final baseUri = Uri.parse("https://api.my-app-domain.com/");
  final finalUri = baseUri.resolve(relativeEndpoint); 
  var client = HttpClient();
  var request = await client.getUrl(finalUri);
  var response = await request.close();
}`
  },
  {
    id: "DS-015",
    cwe: "CWE-347",
    name: "Signature Verification Bypass",
    severity: "HIGH",
    description: "Configuração que desativa a validação de assinatura de chaves criptográficas ou tokens JWT recebidos.",
    recommendation: "Sempre exija validação estrita da assinatura e autenticidade de tokens (verify: true).",
    vulnerableCode: `// Código Vulnerável: Ignorando a assinatura do JWT
void verifyToken(String jwtToken) {
  verifyJWT(jwtToken, verify: false);
}`,
    secureCode: `// Código Seguro: Assinatura obrigatória exigida
void verifyTokenSecurely(String jwtToken) {
  verifyJWT(jwtToken, verify: true);
}`
  },
  {
    id: "DS-016",
    cwe: "CWE-942",
    name: "Permissive CORS Access",
    severity: "MEDIUM",
    description: "Definição excessivamente permissiva de Cross-Origin Resource Sharing (CORS) com curinga '*' no backend local do Flutter.",
    recommendation: "Defina origens específicas e evite aceitar credenciais quando o curinga estiver ativo.",
    vulnerableCode: `// Código Vulnerável: CORS irrestrito (*)
void configureCORS() {
  var settings = cors(origin: "*");
}`,
    secureCode: `// Código Seguro: Domínios restritos
void configureCORS() {
  var settings = cors(origin: "https://trusted-portal.com");
}`
  },
  {
    id: "DS-017",
    cwe: "CWE-598",
    name: "GET with Sensitive Data",
    severity: "HIGH",
    description: "Envio de chaves confidenciais ou tokens como parâmetros de consulta em requisições HTTP GET.",
    recommendation: "Transmita dados confidenciais apenas no cabeçalho Authorization ou corpo seguro de requisições POST/PUT.",
    vulnerableCode: `// Código Vulnerável: Segredos enviados na Query String de GET
import 'package:http/http.dart' as http;

void sendSecretsViaGet(String secretKey) async {
  var response = await http.get(Uri.parse("https://api.secure.com/auth?token=$secretKey"));
}`,
    secureCode: `// Código Seguro: Dados enviados em POST com corpo seguro
import 'package:http/http.dart' as http;

void sendSecretsViaPost(String secretKey) async {
  var response = await http.post(
    Uri.parse("https://api.secure.com/auth"),
    body: {"token": secretKey}
  );
}`
  },
  {
    id: "DS-018",
    cwe: "CWE-287",
    name: "Improper Authentication",
    severity: "HIGH",
    description: "Ignorar ou tratar de forma incompleta o fluxo de validação biométrica local, abrindo caminhos para bypass.",
    recommendation: "Sempre capture o booleano retornado na validação biométrica e trate cenários de exceções.",
    vulnerableCode: `// Código Vulnerável: Chamada de biometria sem checar booleano de retorno
void triggerBiometricAuth() {
  authenticateWithBiometrics(); 
}`,
    secureCode: `// Código Seguro: Verificação rigorosa do booleano de retorno
bool triggerBiometricAuthSecurely() {
  bool isAuthenticated = authenticateWithBiometrics();
  if (isAuthenticated) {
    return true;
  } else {
    print("Falha na autenticação biométrica.");
    return false;
  }
}`
  },
  {
    id: "DS-019",
    cwe: "CWE-209",
    name: "Sensitive Info in Errors",
    severity: "LOW",
    description: "Impressão direta de detalhes técnicos, strings do banco ou rastros de pilha (stack trace) em saídas públicas.",
    recommendation: "Use alertas amigáveis e genéricos no console do cliente, salvando detalhes detalhados em logs de depuração internos criptografados.",
    vulnerableCode: `// Código Vulnerável: Expondo detalhes técnicos na saída
void runDBTransaction() {
  try {
    // transações do banco
  } catch (e, s) {
    print(e);
  }
}`,
    secureCode: `// Código Seguro: Mensagem genérica para segurança do usuário
void runDBTransactionSecurely() {
  try {
    // transações do banco
  } catch (e, s) {
    print("Database connection error"); 
  }
}`
  },
  {
    id: "DS-020",
    cwe: "CWE-521",
    name: "Weak Password",
    severity: "MEDIUM",
    description: "Políticas fracas ou inexistentes de complexidade e comprimento de senha na verificação de inputs.",
    recommendation: "Exija senhas de comprimento apropriado (8+ caracteres) com verificação de complexidade (letras maiúsculas, minúsculas, símbolos e números).",
    vulnerableCode: `// Código Vulnerável: Apenas comprimento superficial aceito
bool validatePassword(String password) {
  return password.length > 6;
}`,
    secureCode: `// Código Seguro: Verificação rigorosa de complexidade
bool validatePasswordSecurely(String password) {
  final lengthValid = password.length >= 8;
  final hasDigit = password.contains(RegExp(r'[0-9]'));
  final hasSpecial = password.contains(RegExp(r'[!@#\\$&*~]'));
  return lengthValid && hasDigit && hasSpecial;
}`
  }
];
