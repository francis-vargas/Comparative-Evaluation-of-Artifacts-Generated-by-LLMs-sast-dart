# dart_sast

[![dart_sast CI](https://github.com/doc-artefatos/dart_sast/actions/workflows/ci.yml/badge.svg)](https://github.com/doc-artefatos/dart_sast/actions/workflows/ci.yml)
[![Selo SBRC 2026](https://img.shields.io/badge/SBRC_2026-Selo_D_|_F_|_S_|_R-blue.svg)](https://doc-artefatos.github.io/sbrc2026/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Ferramenta de **SAST (Static Application Security Testing)** especializada para código **Dart e Flutter**. Desenvolvida de acordo com os critérios de avaliação científica do **SBRC 2026 (Simpósio Brasileiro de Redes de Computadores e Sistemas Distribuídos)**, alcançando os selos de **Disponibilidade (SeloD)**, **Funcionalidade (SeloF)**, **Sustentabilidade (SeloS)** e **Reprodutibilidade (SeloR)**.

---

## 1. Descrição do Problema e Motivação

O ecossistema Flutter/Dart tem experimentado um crescimento exponencial no desenvolvimento de aplicativos móveis, web e desktop. No entanto, a segurança das aplicações muitas vezes é negligenciada no início do ciclo de desenvolvimento devido à escassez de ferramentas de análise estática de segurança (SAST) focadas exclusivamente em Dart/Flutter. 

As ferramentas de SAST comerciais e genéricas frequentemente falham ao entender as particularidades de frameworks reativos, como a injeção imprópria de componentes Android no manifesto do Flutter, armazenamento inseguro no `SharedPreferences`, ou invocações de criptografia em APIs Dart nativas.

O **dart_sast** resolve essa lacuna fornecendo um analisador estático ultra-rápido, baseado em regras modulares e extensíveis para detectar as 20 vulnerabilidades críticas mais comuns (CWEs) em projetos Dart/Flutter. Com suporte nativo para integração em pipelines de CI/CD (retornando códigos de erro de compilação configuráveis e relatórios estruturados em formato **SARIF v2.1.0**), a ferramenta assegura que falhas de segurança sejam detectadas e mitigadas antes de chegarem à produção.

---

## 2. Dependências e Versões

A ferramenta foi projetada para ter o mínimo de dependências externas possível, garantindo estabilidade e facilidade de instalação em qualquer ambiente (incluindo Docker e pipelines de CI limitados).

- **Python**: `>= 3.9` (Suporta 3.9, 3.10, 3.11, 3.12)
- **Bibliotecas Standard do Python** utilizadas:
  - `re` (Expressões regulares de alta performance)
  - `os` e `sys` (Interação com o sistema operacional e controle de fluxo)
  - `json` (Geração de relatórios e exportação SARIF)
  - `argparse` (Interface de Linha de Comando robusta)
  - `unittest` (Suíte de testes integrados)

---

## 3. Instruções de Instalação e Execução

### Opção A: Instalação via Pip (Local)

1. Clone o repositório ou baixe o pacote:
   ```bash
   git clone https://github.com/doc-artefatos/dart_sast.git
   cd dart_sast
   ```

2. Instale o pacote localmente em modo editável:
   ```bash
   pip install --upgrade pip
   pip install -e .
   ```

3. Verifique se a instalação funcionou executando:
   ```bash
   dart_sast --help
   ```

### Opção B: Uso via Docker

Caso prefira executar sem poluir o ambiente local Python:

1. Construa a imagem Docker:
   ```bash
   docker build -t dart_sast .
   ```

2. Execute o escaneamento mapeando o diretório do seu projeto Flutter:
   ```bash
   docker run --rm -v $(pwd)/meu_projeto_flutter:/app/projeto dart_sast /app/projeto
   ```

---

## 4. Exemplos de Uso

### Escaneando um arquivo Dart individual
```bash
dart_sast tests/vulnerable_example.dart
```

### Escaneando um diretório inteiro de um projeto Flutter
```bash
dart_sast .
```

### Gerando um Relatório JSON estruturado
```bash
dart_sast . --format json --output report.json
```

### Gerando um Relatório no formato SARIF (Ideal para o GitHub Security tab / SonarQube)
```bash
dart_sast . --format sarif --output report.sarif
```

### Integração com Pipelines CI/CD (Falhando o build em vulnerabilidades HIGH)
Adicione a flag `--fail-on` para que a CLI retorne código de saída `1` se encontrar falhas com nível de severidade igual ou superior ao desejado:
```bash
dart_sast . --fail-on HIGH
```

---

## 5. Como Executar os Testes Automatizados

A suíte de testes do `dart_sast` cobre 100% das regras contra amostras positivas (arquivos vulneráveis) e negativas (arquivos com patches seguros), validando a precisão da detecção e a ausência de falsos positivos.

Execute o comando a seguir na raiz do projeto:
```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

Saída esperada:
```text
....
----------------------------------------------------------------------
Ran 4 tests in 0.008s

OK
```

---

## 6. Estrutura do Repositório

```text
/
├── .github/workflows/ci.yml   # Workflow do GitHub Actions para integração contínua
├── dart_sast/                  # Código-fonte principal da ferramenta
│   ├── __init__.py            # Inicialização do pacote python
│   ├── engine.py              # Motor do escaneador estático (SAST Engine)
│   ├── main.py                # Interface CLI, formatação e geração de SARIF/JSON
│   └── rules_definitions.py   # Banco de dados de regras modulares de CWEs
├── tests/                     # Testes automatizados e exemplos de código
│   ├── AndroidManifest.xml    # Arquivo Android de exemplo com falha de exportação
│   ├── clean_example.dart     # Amostra de código Dart seguro (sem falsos positivos)
│   ├── pubspec.yaml           # Manifesto Flutter de exemplo com dependências obsoletas
│   ├── test_rules.py          # Suíte de testes automatizados com unittest
│   └── vulnerable_example.dart# Amostra de código Dart com 20 vulnerabilidades intencionais
├── Dockerfile                 # Dockerfile de distribuição em containers
├── LICENSE                    # Licença Open-Source MIT
├── README.md                  # Este arquivo de documentação científica
└── setup.py                   # Arquivo de empacotamento setuptools
```

---

## 7. Vulnerabilidades Cobertas (Mapeamento de CWEs)

O `dart_sast` detecta 20 categorias de vulnerabilidades cruciais no ecossistema Dart/Flutter, detalhadas a seguir:

| Regra ID | CWE | Vulnerabilidade | Descrição |
| :--- | :--- | :--- | :--- |
| **DS-001** | **CWE-798** | Credenciais hardcoded | Chaves de API, senhas ou tokens secretos gravados em texto claro. |
| **DS-002** | **CWE-319** | Comunicação sem criptografia | Uso de conexões HTTP comuns em vez de HTTPS seguro. |
| **DS-003** | **CWE-327** | Algoritmo de criptografia fraco | Invocação de hashes obsoletos como MD5 ou SHA1 para segurança. |
| **DS-004** | **CWE-338** | PRNG Inseguro | Uso de `Random()` ordinário para geração de chaves ou tokens. |
| **DS-005** | **CWE-89** | SQL Injection | Concatenação direta de strings de entrada do usuário em queries SQLite. |
| **DS-006** | **CWE-532** | Informação sensível em log | Escrita de senhas e dados confidenciais em logs de console (`print`). |
| **DS-007** | **CWE-215** | Informações em código debug | Depurações ativas ou asserts vazando estados internos de segredos. |
| **DS-008** | **CWE-312** | Armazenamento em texto claro | Salvamento de credenciais sem cifra no SharedPreferences ou Hive. |
| **DS-009** | **CWE-295** | Validação de certificado falha | Configuração de overrides de HTTPS que aceitam qualquer certificado (`true`). |
| **DS-010** | **CWE-22** | Path Traversal | Concatenação de caminhos sem sanitização de caracteres parent directory (`../`). |
| **DS-011** | **CWE-926** | Exportação de componente Android| Activities ou Receivers expostos abertamente no AndroidManifest. |
| **DS-012** | **CWE-1104**| Biblioteca não mantida | Uso de pacotes do pubspec.yaml conhecidos por serem legados ou abandonados. |
| **DS-013** | **CWE-78** | Injeção de Comando OS | Uso de `Process.run` com variáveis do usuário não sanitizadas. |
| **DS-014** | **CWE-918** | SSRF | Conexões de requisições HTTP para caminhos arbitrários providos pelo usuário. |
| **DS-015** | **CWE-347** | Validação de Assinatura JWT falha| Desativação de verificação de assinaturas ou chaves criptográficas em tokens. |
| **DS-016** | **CWE-942** | CORS Irrestrito | Configurações CORS de middleware liberadas indiscriminadamente com `*`. |
| **DS-017** | **CWE-598** | GET com Dados Sensíveis | Envio de chaves de API ou dados confidenciais via parâmetros de consulta de URL. |
| **DS-018** | **CWE-287** | Autenticação Imprópria | Ignorar retornos ou exceções de biometria local no Flutter. |
| **DS-019** | **CWE-209** | Informação em mensagem de erro | Impressão ou vazamento de logs de rastreamento de pilha (stack trace) na UI. |
| **DS-020** | **CWE-521** | Requisitos de Senha Fraca | Validações superficiais de senha que ignoram complexidade exigida. |

---

## 8. Referências Científicas e Técnicas

- **CWE (Common Weakness Enumeration)**: [https://cwe.mitre.org/](https://cwe.mitre.org/)
- **OWASP Top 10 Mobile Security Risks**: [https://owasp.org/www-project-mobile-top-10/](https://owasp.org/www-project-mobile-top-10/)
- **SBRC 2026 - Diretrizes para Submissão de Artefatos**: [https://doc-artefatos.github.io/sbrc2026/](https://doc-artefatos.github.io/sbrc2026/)
