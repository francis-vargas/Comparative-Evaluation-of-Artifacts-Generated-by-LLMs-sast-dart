# dart_sast

**dart_sast** é uma ferramenta de SAST (*Static Application Security
Testing*) de código aberto para projetos **Dart/Flutter**. Ela analisa
arquivos `.dart`, `pubspec.yaml` e `AndroidManifest.xml` em busca de
padrões de código associados a vulnerabilidades conhecidas (catalogadas
pelo CWE — *Common Weakness Enumeration*), e produz relatórios em
console, JSON ou SARIF prontos para integração em pipelines de CI/CD.

Este artefato foi desenvolvido seguindo os critérios de avaliação de
artefatos científicos do **SBRC 2026**
([doc-artefatos.github.io/sbrc2026](https://doc-artefatos.github.io/sbrc2026/)):
código público e versionado (SeloD), ferramenta executável com exemplo
mínimo de uso (SeloF), organização modular e documentada (SeloS), e
instruções suficientes para qualquer pessoa reproduzir os resultados
(SeloR).

> Consulte também `docs/ARCHITECTURE.md` para as decisões de design e
> `CONTRIBUTING.md` para o guia de contribuição.

---

## Sumário

- [Motivação](#motivação)
- [Vulnerabilidades detectadas](#vulnerabilidades-detectadas)
- [Dependências](#dependências)
- [Instalação](#instalação)
- [Uso](#uso)
- [Exemplo de uso mínimo](#exemplo-de-uso-mínimo)
- [Flags da CLI](#flags-da-cli)
- [Formatos de saída](#formatos-de-saída)
- [Distribuição](#distribuição)
- [Estrutura do repositório](#estrutura-do-repositório)
- [Executando os testes](#executando-os-testes)
- [Limitações conhecidas](#limitações-conhecidas)
- [Referências](#referências)
- [Licença](#licença)

---

## Motivação

O ecossistema Dart/Flutter cresceu rapidamente para aplicações móveis,
web e backend (via `shelf`/`dart_frog`), mas o tooling de segurança
estática disponível para essa linguagem é escasso quando comparado a
ecossistemas como Java/Kotlin (Android) ou JavaScript/TypeScript. Times
de desenvolvimento frequentemente introduzem vulnerabilidades comuns —
credenciais hard-coded, tráfego HTTP não criptografado, validação de
certificado desabilitada, armazenamento local sem criptografia — sem
qualquer verificação automatizada antes do merge. `dart_sast` busca
preencher essa lacuna com uma ferramenta leve, sem dependências externas,
fácil de rodar localmente ou em CI, e extensível pela comunidade.

## Vulnerabilidades detectadas

| Regra | CWE | Descrição |
|---|---|---|
| `DART-SAST-CWE798` | [CWE-798](https://cwe.mitre.org/data/definitions/798.html) | Credenciais hardcoded |
| `DART-SAST-CWE319` | [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | Comunicação sem criptografia (HTTP) |
| `DART-SAST-CWE327` | [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | Algoritmo criptográfico fraco (MD5/SHA-1/DES/RC4/ECB) |
| `DART-SAST-CWE338` | [CWE-338](https://cwe.mitre.org/data/definitions/338.html) | PRNG inseguro para fins de segurança |
| `DART-SAST-CWE89`  | [CWE-89](https://cwe.mitre.org/data/definitions/89.html)  | SQL Injection |
| `DART-SAST-CWE532` | [CWE-532](https://cwe.mitre.org/data/definitions/532.html) | Informação sensível em log |
| `DART-SAST-CWE215` | [CWE-215](https://cwe.mitre.org/data/definitions/215.html) | Informação sensível em código de depuração |
| `DART-SAST-CWE312` | [CWE-312](https://cwe.mitre.org/data/definitions/312.html) | Armazenamento em texto claro |
| `DART-SAST-CWE295` | [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | Validação imprópria de certificado TLS |
| `DART-SAST-CWE22`  | [CWE-22](https://cwe.mitre.org/data/definitions/22.html)  | Path Traversal |
| `DART-SAST-CWE926` | [CWE-926](https://cwe.mitre.org/data/definitions/926.html) | Exportação imprópria de componente Android (AndroidManifest.xml) |
| `DART-SAST-CWE1104`| [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html) | Componente de terceiro não mantido (pubspec.yaml) |
| `DART-SAST-CWE78`  | [CWE-78](https://cwe.mitre.org/data/definitions/78.html)  | OS Command Injection |
| `DART-SAST-CWE918` | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | Server-Side Request Forgery (SSRF) |
| `DART-SAST-CWE347` | [CWE-347](https://cwe.mitre.org/data/definitions/347.html) | Verificação imprópria de assinatura (JWT) |
| `DART-SAST-CWE942` | [CWE-942](https://cwe.mitre.org/data/definitions/942.html) | CORS excessivamente permissivo |
| `DART-SAST-CWE598` | [CWE-598](https://cwe.mitre.org/data/definitions/598.html) | Dados sensíveis em requisição GET |
| `DART-SAST-CWE287` | [CWE-287](https://cwe.mitre.org/data/definitions/287.html) | Autenticação imprópria |
| `DART-SAST-CWE209` | [CWE-209](https://cwe.mitre.org/data/definitions/209.html) | Mensagem de erro com informação sensível |
| `DART-SAST-CWE521` | [CWE-521](https://cwe.mitre.org/data/definitions/521.html) | Requisitos de senha fraca |

Rode `dart_sast --list-rules` para ver esta lista diretamente na sua
versão instalada.

## Dependências

- **Python** >= 3.9 (testado em 3.9, 3.10, 3.11 e 3.12).
- **Nenhuma dependência externa em tempo de execução** — o parser de
  `pubspec.yaml` e todas as regras usam apenas a biblioteca padrão.
- Dependências de desenvolvimento (opcionais, para rodar os testes):
  - `pytest >= 7.4`
  - `pytest-cov >= 4.1`

## Instalação

### Opção 1 — a partir do código-fonte (pip)

```bash
git clone https://github.com/example/dart_sast.git
cd dart_sast
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install .
dart_sast --version
```

### Opção 2 — modo desenvolvimento (com testes)

```bash
pip install -e ".[dev]"
```

### Opção 3 — Docker

```bash
docker build -t dart_sast:latest .
docker run --rm -v "$(pwd)":/src dart_sast:latest /src --format console
```

### Opção 4 — GitHub Action (CI/CD de outros projetos)

```yaml
- name: Run dart_sast
  uses: example/dart_sast@main
  with:
    path: "."
    format: sarif
    output: dart-sast-report.sarif
    fail-on: HIGH
```

Veja `.github/workflows/example-consumer-usage.yml` para um exemplo
completo, incluindo o upload do SARIF para o GitHub Code Scanning.

## Uso

```bash
dart_sast <arquivo.dart|diretório> [opções]
```

## Exemplo de uso mínimo

O repositório inclui um app Flutter de exemplo com vulnerabilidades
intencionais em `examples/vulnerable_app/`, usado tanto na documentação
quanto nos testes de integração:

```bash
dart_sast examples/vulnerable_app
```

Saída (resumida):

```
==============================================================================
dart_sast - Static Application Security Testing for Dart/Flutter
==============================================================================

lib/main.dart
-------------
  [CRITICAL] DART-SAST-CWE798 (CWE-798) - Use of Hard-coded Credentials
    line 17, col 14: const String apiKey = "sk_live_51Hqz2m9d8f7g6h5j4k3l2";
    ...

==============================================================================
Summary
==============================================================================
  CRITICAL: 6
  HIGH: 11
  MEDIUM: 7
  LOW: 2
  TOTAL findings: 26
  Files scanned: 3 (.dart: 1, pubspec.yaml: 1)
```

Rodando apenas em um único arquivo, com saída JSON:

```bash
dart_sast examples/vulnerable_app/lib/main.dart --format json
```

Gerando um relatório SARIF para importar no GitHub Code Scanning ou no
DefectDojo:

```bash
dart_sast . --format sarif --output report.sarif
```

Falhando o build de CI apenas para severidade CRITICAL, ignorando o resto:

```bash
dart_sast . --format sarif --output report.sarif --fail-on CRITICAL
```

Excluindo diretórios gerados e rodando apenas duas regras específicas:

```bash
dart_sast . --exclude "lib/generated/*" --rules DART-SAST-CWE798,DART-SAST-CWE319
```

## Flags da CLI

| Flag | Descrição | Padrão |
|---|---|---|
| `path` | Arquivo ou diretório a analisar | `.` |
| `--format {console,json,sarif,all}` | Formato de saída | `console` |
| `-o, --output FILE` | Escreve em arquivo em vez de stdout | stdout |
| `--min-severity {INFO,LOW,MEDIUM,HIGH,CRITICAL}` | Filtra achados abaixo desta severidade | `INFO` |
| `--fail-on {never,INFO,...,CRITICAL}` | Severidade mínima que causa código de saída 1 | `HIGH` |
| `--exclude GLOB` | Padrão glob a excluir (repetível) | — |
| `--rules ID,ID,...` | Roda somente estas regras | todas |
| `--exclude-rules ID,ID,...` | Pula estas regras | nenhuma |
| `--list-rules` | Lista todas as regras disponíveis e sai | — |
| `--no-color` | Desativa cores ANSI no console | cores ligadas |
| `--version` | Mostra a versão instalada | — |

Código de saída: `0` se nenhum achado atingiu o limiar de `--fail-on`
(ou se `--fail-on never`); `1` caso contrário; `2` em erro de uso (ex.:
`--rules` filtrando para um conjunto vazio).

## Formatos de saída

- **console** — legível por humanos, com cores por severidade.
- **json** — estrutura estável (`tool`, `version`, `target`, `summary`,
  `findings[]`) para consumo por scripts.
- **sarif** — [SARIF 2.1.0](https://sarifweb.azurewebsites.net/), lido
  nativamente pelo GitHub Code Scanning, Azure DevOps e importável em
  ferramentas como o DefectDojo.
- **all** — imprime o console em stdout e escreve `.json`/`.sarif`
  (usando `--output` como prefixo).

## Distribuição

A ferramenta é distribuída de três formas, cobrindo diferentes fluxos de
adoção por desenvolvedores Dart/Flutter e times de segurança:

1. **Pacote Python (pip)** — instalação direta via `pip install .` a
   partir do código-fonte (ver `pyproject.toml`); expõe o comando
   `dart_sast` via `project.scripts`.
2. **Imagem Docker** — `Dockerfile` na raiz do repositório, para uso sem
   precisar de um ambiente Python local.
3. **GitHub Action** (`action.yml`, composite action) — para integração
   de um clique no CI/CD de qualquer projeto Dart/Flutter hospedado no
   GitHub, com saída SARIF pronta para o Code Scanning.

## Estrutura do repositório

```
dart_sast/
├── pyproject.toml              # Empacotamento (pip install .)
├── Dockerfile / .dockerignore  # Distribuição via Docker
├── action.yml                  # GitHub Action (composite)
├── LICENSE                     # MIT
├── README.md                   # Este arquivo
├── CONTRIBUTING.md             # Guia de contribuição
├── docs/
│   └── ARCHITECTURE.md         # Decisões de design (SeloS)
├── .github/workflows/
│   ├── ci.yml                       # CI deste repositório (testes)
│   └── example-consumer-usage.yml   # Exemplo de uso da Action
├── src/dart_sast/
│   ├── cli.py                  # Ponto de entrada da CLI
│   ├── engine/                 # Motor de scanning (agnóstico de regras)
│   ├── rules/                  # 20 regras, uma por arquivo (cweNNN_*.py)
│   └── reporters/              # console.py, json_reporter.py, sarif.py
├── tests/                      # Suíte pytest (positivo/negativo/integração/CLI)
└── examples/vulnerable_app/    # App de exemplo com vulnerabilidades intencionais
```

Veja `docs/ARCHITECTURE.md` para a descrição detalhada de cada arquivo e
a justificativa das decisões de organização/extensibilidade.

## Executando os testes

```bash
pip install -e ".[dev]"
pytest -q
```

Para relatório de cobertura:

```bash
pytest -q --cov=dart_sast --cov-report=term-missing
```

A suíte cobre, conforme exigido:

- **Detecção positiva por regra** (`tests/test_rules_positive.py`): cada
  uma das 20 regras é executada isoladamente contra
  `tests/fixtures/vulnerable/` e deve produzir ao menos um achado.
- **Ausência de falsos positivos** (`tests/test_no_false_positives.py`):
  todas as regras rodando juntas contra `tests/fixtures/clean/` devem
  produzir zero achados.
- **Teste de integração** (`tests/test_integration_example_app.py`):
  roda o scanner completo contra `examples/vulnerable_app/` (arquivo
  `.dart` real + `pubspec.yaml` + `AndroidManifest.xml`) e verifica que
  todas as 20 regras disparam nesse cenário realista.
- **Parser de pubspec.yaml, scanner (exclusão de diretórios) e CLI**
  (flags, códigos de saída, formatos de saída) também têm cobertura
  dedicada.

## Limitações conhecidas

`dart_sast` usa expressões regulares e heurísticas de nomenclatura por
linha, não um parser de AST completo do Dart. Isso implica:

- Padrões que dependem de contexto multi-linha complexo (ex.: uma
  variável sensível atribuída em uma linha e usada de forma insegura
  muitas linhas depois) podem não ser detectados.
- Renomear uma variável para um nome que não contenha palavras-chave
  como `password`/`token`/`secret` pode evitar a detecção (falso
  negativo) — e, inversamente, nomes de variável coincidentes (ex.:
  `tokenExpiryDisplay`) podem gerar falsos positivos.
- Código gerado, comentado, ou dentro de blocos de comentário de bloco
  aninhados de forma incomum pode não ser tratado perfeitamente pelo
  rastreador simples de comentários do motor.

Essas limitações são inerentes à abordagem escolhida (ver
`docs/ARCHITECTURE.md`, seção 3) e são compensadas por zero dependências
externas, velocidade de execução e facilidade de adicionar novas regras.

## Referências

- OWASP Mobile Top 10 (2023) — <https://owasp.org/www-project-mobile-top-10/>
- OWASP Top Ten — <https://owasp.org/www-project-top-ten/>
- MITRE CWE — <https://cwe.mitre.org/>
- SARIF 2.1.0 — <https://sarifweb.azurewebsites.net/>
- Critérios de avaliação de artefatos SBRC 2026 — <https://doc-artefatos.github.io/sbrc2026/>
- `flutter_secure_storage` — <https://pub.dev/packages/flutter_secure_storage>
- Dart `Random.secure()` — <https://api.dart.dev/stable/dart-math/Random/Random.secure.html>
- NIST SP 800-63B (requisitos de senha) — <https://pages.nist.gov/800-63-3/sp800-63b.html>

## Licença

MIT — veja [`LICENSE`](LICENSE).
