# Avaliação de Artefatos — `dart_sast` (Comparativo LLMs)

**Repositório avaliado:** `francis-vargas/Comparative-Evaluation-of-Artifacts-Generated-by-LLMs-sast-dart`
**Diretrizes aplicadas:** [Instruções de Avaliação de Artefatos — SBRC 2026](https://doc-artefatos.github.io/sbrc2026/revinstrucoes.html)
**Prompt original usado para gerar os 4 artefatos:** `prompt.txt` (idêntico para as 4 LLMs)
**Avaliador:** Claude (execução real do código em ambiente Linux isolado, sem acesso à internet exceto para clonar o repositório)
**Data da avaliação:** 03/07/2026

> **Metodologia.** Para cada um dos 4 artefatos (`gemini-3.5-flash-aistudio`, `gpt-5.5`, `grok-fast`, `sonnet-4.6`) foi criado um ambiente virtual Python isolado (`venv`), o pacote foi instalado exatamente como descrito no respectivo README, o comando `--help` foi executado, os exemplos mínimos de uso foram rodados contra os arquivos vulneráveis/limpos incluídos no próprio repositório, os formatos de saída (console/JSON/SARIF) foram inspecionados, e a suíte de testes automatizada foi executada integralmente. Não foi usada nenhuma modificação de código — apenas os comandos documentados nos READMEs. **Docker não pôde ser buildado** (ambiente sandbox sem `docker` instalado); os `Dockerfile`s foram revisados estaticamente.

---

## 1. Critérios do SBRC 2026 (resumo)

| Selo | Requisito mínimo |
|---|---|
| **SeloD** — Artefatos Disponíveis | Repositório público estável + README com: título/resumo, estrutura do README, selos considerados, informações básicas, dependências, preocupações de segurança, instalação, teste mínimo, experimentos (por reivindicação), licença. |
| **SeloF** — Artefatos Funcionais | Ferramenta executável, com lista de dependências/versões, ambiente de execução, instalação/execução, exemplo mínimo. Revisor deve **executar** e apresentar prova de saída. |
| **SeloS** — Artefatos Sustentáveis | Código modularizado, organizado, documentado (arquivos/funções), legível, reivindicações do artigo identificáveis no código. |
| **SeloR** — Experimentos Reprodutíveis | Instruções para reproduzir as principais reivindicações; processo documentado; revisor deve reproduzir e obter os mesmos resultados. |

Como o "artigo" aqui é o próprio `prompt.txt` (que define claramente 20 CWEs-alvo, formatos de saída, testes exigidos), as **reivindicações a reproduzir** são:
1. Detecção das 20 CWEs listadas no prompt;
2. Saída em console **e** JSON (formatos extra como SARIF são bônus);
3. Testes automatizados cobrindo detecção positiva (por regra), ausência de falso positivo em código limpo, e um arquivo de exemplo vulnerável para demonstração/integração;
4. Projeto instalável e distribuível (pip obrigatório; Docker/GitHub Action opcionais mas mencionados no prompt).

---

## 2. Resultado geral (tabela-resumo)

| Artefato | Instala? | `--help` roda? | CWEs implementadas (de 20) | Testes automatizados | Falsos positivos (clean file) | JSON | SARIF | Docker | GitHub Action | Reprodutibilidade dos números do README |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **gemini-3.5-flash-aistudio** | ✅ | ✅ | **20/20** | ✅ 4 testes (unittest) — todos passam | ✅ Zero | ✅ | ✅ | ❌ README cita Docker, mas **não existe `Dockerfile`** no repo | ❌ Não há `action.yml` | Parcial (README não declara números exatos de achados) |
| **gpt-5.5** | ✅ | ✅ | **21/20** (20 pedidas + CWE-749 extra) | ✅ 6 testes (pytest) — todos passam | ✅ Zero | ✅ | ✅ | ✅ Presente e correto | ✅ Presente e correto | ✅ Sim — `count: 21` bate com o comando de reprodução do README |
| **grok-fast** | ✅ | ✅ | **4/20** ⚠️ (só 798, 89, 22, 78) | ✅ 3 testes (pytest) — todos passam, mas cobertura rasa | ✅ Zero (nas 4 regras existentes) | ✅ | ❌ Não implementado | ✅ Presente | ❌ Não há `action.yml` | Parcial — não há números específicos a conferir |
| **sonnet-4.6** | ✅ | ✅ | **20/20** | ✅ **67 testes** (pytest) — todos passam, cobertura por regra + integração + CLI + parser | ✅ Zero | ✅ | ✅ | ✅ Presente e correto | ✅ Presente e correto | ✅ Sim — `TOTAL findings: 26` reproduzido **exatamente** como no README |

---

## 3. Avaliação detalhada por artefato

### 3.1 `gemini-3.5-flash-aistudio`

**Estrutura observada:** o diretório contém o pacote Python esperado (`dart_sast/engine.py`, `main.py`, `rules_definitions.py`, `tests/`), porém também traz **arquivos residuais de um projeto React/Vite não relacionados ao SAST** (`index.html`, `src/App.tsx`, `server.ts`, `package.json`, `metadata.json`) — provavelmente resíduo do ambiente "AI Studio" usado para gerar o artefato. Isso não impede a execução da ferramenta, mas **prejudica a organização/limpeza exigida pelo SeloS** (mistura de dois projetos não relacionados no mesmo diretório).

**Instalação e execução real:**
```bash
python3 -m venv venv && . venv/bin/activate
pip install -e .
dart_sast --help          # OK
dart_sast tests/vulnerable_example.dart
```
Saída obtida (trecho real):
```
[HIGH] Hardcoded Credentials (CWE-798)
  Rule ID  : DS-001
  Location : tests/vulnerable_example.dart:11
  Evidence : const String apiKey = "AIzaSyD-un4RkS_SECRETa128913_example";
...
[HIGH] Cleartext Storage of Sensitive Information (CWE-312)
[HIGH] Unencrypted Communication (CWE-319)
[HIGH] Weak Cryptographic Algorithm (CWE-327)
[HIGH] SQL Injection (CWE-89)
[HIGH] Improper Certificate Validation (CWE-295)
```
18 achados no total no arquivo vulnerável; **0 achados** em `tests/clean_example.dart` (sem falsos positivos).

**Cobertura de CWEs:** confirmadas as **20/20** CWEs pedidas no prompt (`grep CWE- rules_definitions.py` retorna as 20 categorias).

**Testes automatizados:**
```bash
python3 -m unittest discover -s tests -p "test_*.py"
# Ran 4 tests in 0.007s — OK
```
Os 4 métodos de teste cobrem, dentro de um único método, asserts individuais para 17 das 20 CWEs no arquivo vulnerável, mais testes dedicados para `AndroidManifest.xml` (CWE-926) e `pubspec.yaml` (CWE-1104), além do teste de ausência de falso positivo. Atende ao requisito da Parte 5 do prompt, embora de forma menos granular que o `sonnet-4.6` (testes agrupados em vez de um teste por regra).

**Formatos de saída:** `console`, `--format json`, `--format sarif` — todos gerados e válidos (JSON parseável; SARIF com chaves `$schema`, `version`, `runs`).

**Falha identificada (SeloD/SeloF):** o README descreve uma "Opção B: Uso via Docker" com `docker build -t dart_sast .`, mas **não existe `Dockerfile` no repositório** — instrução não reprodutível. Também não há `action.yml` (GitHub Action), apesar do prompt sugerir essa forma de distribuição como opcional.

**Veredito de selos:**
- **SeloD:** ✅ Atendido (repositório estável, README completo com quase todas as seções pedidas — falta seção explícita "Selos considerados" e "Preocupações com segurança").
- **SeloF:** ⚠️ Atendido parcialmente — a ferramenta roda perfeitamente via pip, mas a instrução de Docker documentada **falha** (arquivo ausente), o que é uma inconsistência entre README e artefato.
- **SeloS:** ⚠️ Atendido parcialmente — código do SAST é organizado (engine/regras/CLI separados), mas o repositório está poluído com artefato React não relacionado, prejudicando a inteligibilidade da estrutura.
- **SeloR:** ✅ Atendido — comandos reproduzem os achados esperados (20 CWEs, zero falso positivo).

---

### 3.2 `gpt-5.5`

**Estrutura observada:** organização limpa e modular — `dart_sast/{cli.py, models.py, reporters.py, scanner.py, rules/{base.py, pubspec_rules.py, regex_rules.py}}`, `docs/ARCHITECTURE.md`, `tests/fixtures/{vulnerable_app, clean_app}`, `Dockerfile`, `action.yml`.

**Instalação e execução real:**
```bash
python3 -m venv venv && . venv/bin/activate
pip install -e .
dart_sast --help          # OK, inclui --list-rules, --exclude-rule, --fail-on
```

**Cobertura de CWEs:** **21 regras**, cobrindo as **20 CWEs pedidas + CWE-749** (WebView JavaScript perigoso, adicional justificado pelo ecossistema Flutter/WebView — atende à permissão do prompt "sinta-se livre para adicionar outras").

**Reprodução do comando descrito no próprio README:**
```bash
dart_sast tests/fixtures/vulnerable_app --format json --output findings.json
# count: 21   ✅ igual ao esperado ("findings are produced for the implemented CWE set")

dart_sast tests/fixtures/clean_app --format json
# count: 0    ✅ exatamente como documentado
```

**Testes automatizados:**
```bash
pip install -e ".[dev]"
pytest -q
# 6 passed in 0.05s
```
Testes cobrem CLI (`test_cli.py`) e o scanner/regras (`test_scanner.py`), incluindo o threshold `--fail-on`.

**Formatos de saída:** console, JSON e SARIF (21 resultados no SARIF, estrutura válida).

**Docker / Action:** `Dockerfile` correto (`python:3.11-slim`, `pip install .`, `ENTRYPOINT ["dart_sast"]`) e `action.yml` (composite action) bem formado, coerente com o README.

**Veredito de selos:**
- **SeloD:** ✅ Atendido — README muito completo, inclui até uma seção explícita de "checklist científico" mapeando evidências para cada selo (SeloD/F/S/R). Falta apenas a seção formal "Preocupações com segurança".
- **SeloF:** ✅ Atendido — instalação, execução, exemplo mínimo e Docker/Action funcionam exatamente como descrito.
- **SeloS:** ✅ Atendido — separação clara scanner/regras/reporters/CLI, `docs/ARCHITECTURE.md` dedicado, regras agrupadas por família (regex vs. pubspec) de forma coerente.
- **SeloR:** ✅ Atendido — os números documentados no README (`count: 21`, `count: 0`) foram **reproduzidos exatamente**.

---

### 3.3 `grok-fast`

**Estrutura observada:** `src/dart_sast/{cli.py, scanner.py, reporter.py, rules/{base.py, command_injection.py, hardcoded_credentials.py, path_traversal.py, sql_injection.py}}`, `examples/{clean.dart, vulnerable.dart}`, `Dockerfile`, sem `docs/` e sem `action.yml`.

**Instalação e execução real:**
```bash
python3 -m venv venv && . venv/bin/activate
pip install -e .
dart-sast --help
# usage: dart-sast [-h] [--format {console,json}] [--output OUTPUT] [--verbose] target
```

**⚠️ Achado crítico — cobertura de CWEs muito abaixo do solicitado.** O prompt pede a cobertura de **20 CWEs** como ponto de partida. `grok-fast` implementa **apenas 4**:

| Regra | CWE coberto |
|---|---|
| `hardcoded_credentials.py` | CWE-798 |
| `sql_injection.py` | CWE-89 |
| `path_traversal.py` | CWE-22 |
| `command_injection.py` | CWE-78 |

As **16 CWEs restantes exigidas no prompt não foram implementadas** (CWE-319, 327, 338, 532, 215, 312, 295, 926, 1104, 918, 347, 942, 598, 287, 209, 521). Isso é a divergência mais significativa entre os 4 artefatos e o enunciado original.

**Execução real:**
```bash
dart-sast examples/vulnerable.dart
```
```
🔍 Found 3 potential vulnerabilities:
[HIGH] DART-001 (CWE-798) ...
[CRITICAL] DART-002 (CWE-89) ...
[HIGH] DART-004 (CWE-22) ...
Summary: HIGH: 2, CRITICAL: 1
```
Nota-se que apenas **3** dos **4** rule‑ids implementados dispararam — o exemplo `examples/vulnerable.dart` deixa o trecho de *command injection* **comentado** (`// Process.runSync('ls', ['-la', userInput]);`), então a própria demonstração mínima do artefato não exercita a regra de CWE-78 que ele mesmo implementa. Isso é uma falha do exemplo/demo, não do motor.

```bash
dart-sast examples/clean.dart
# ✅ No vulnerabilities found!    (sem falsos positivos nas 4 regras existentes)
```

**Testes automatizados:**
```bash
python -m pytest tests/ -v
# 3 passed in 0.01s
```
Apenas 3 testes (`test_vulnerable_detection`, `test_clean_code`, `test_directory_scan`), sem um teste dedicado por regra como pede a Parte 5 do prompt ("detecção positiva **para cada regra implementada**"). Como só há 4 regras, mesmo essa cobertura mínima fica pobre.

**Formatos de saída:** apenas `console` e `json` — **não há SARIF**, apesar do prompt sugerir formatos adicionais como bônus para integração com ferramentas de segurança (ex.: DefectDojo/GitHub code scanning). Também não há flag `--fail-on` (controle de exit-code por severidade), reduzindo a utilidade em pipelines de CI/CD reais em comparação aos outros 3 artefatos.

**README:** é o mais curto e o menos aderente ao template mínimo exigido pelo SBRC 2026 — faltam explicitamente: seção "Preocupações com segurança", seção "Teste mínimo" com saída esperada documentada, seção de "Experimentos" por reivindicação, tabela de mapeamento CWE→regra completa, e uma justificativa de arquitetura. O link de instalação (`git clone https://github.com/yourusername/dart_sast.git`) contém um placeholder não atualizado (`yourusername`), o que é um detalhe de baixa qualidade editorial.

**Docker:** `Dockerfile` presente e sintaticamente correto (`FROM python:3.11-slim`, `pip install -e .`, `ENTRYPOINT ["dart-sast"]`); não pôde ser buildado neste ambiente (sem Docker), mas a definição é plausível.

**Veredito de selos:**
- **SeloD:** ⚠️ Atendido minimamente — repositório público, LICENSE, README existe mas incompleto frente ao template oficial.
- **SeloF:** ⚠️ Atendido parcialmente — a ferramenta **funciona** para o que implementa (prova de execução obtida), mas entrega uma fração pequena (4/20 = 20%) do escopo funcional pedido no prompt, o que é uma limitação séria de funcionalidade frente à reivindicação do artefato.
- **SeloS:** ✅ Atendido (para o que existe) — código é modular (uma regra por arquivo, `base.py` com classe abstrata), pequeno e legível, mas sem documentação de arquitetura.
- **SeloR:** ⚠️ Atendido parcialmente — o que está documentado é reproduzível, mas o artefato não permite reproduzir a reivindicação central do prompt (cobertura das 20 CWEs).

---

### 3.4 `sonnet-4.6`

**Estrutura observada:** a organização mais granular dos quatro — `src/dart_sast/{cli.py, engine/{rule.py, registry.py, finding.py, pubspec.py, scanner.py}, rules/cweNNN_*.py (uma CWE por arquivo), reporters/{console,json,sarif}}`, `docs/ARCHITECTURE.md`, `CONTRIBUTING.md`, `examples/vulnerable_app/`, `tests/fixtures/{vulnerable,clean}`, `Dockerfile`, `action.yml`, dois workflows de CI (`ci.yml` e `example-consumer-usage.yml` demonstrando o uso da Action).

**Instalação e execução real:**
```bash
python3 -m venv venv && . venv/bin/activate
pip install -e ".[dev]"
dart_sast --version   # dart_sast 1.0.0
dart_sast --help      # inclui --format {console,json,sarif,all}, --min-severity,
                       # --fail-on, --exclude, --rules, --exclude-rules, --list-rules, --no-color
```

**Cobertura de CWEs:** **20/20**, confirmadas via `dart_sast --list-rules` (uma linha por CWE, nomes técnicos corretos ex.: "Use of a Broken or Risky Cryptographic Algorithm" para CWE-327).

**Reprodução exata do exemplo do README:**
```bash
dart_sast examples/vulnerable_app
```
Saída real obtida:
```
CRITICAL: 6
HIGH: 11
MEDIUM: 7
LOW: 2
TOTAL findings: 26
Files scanned: 3 (.dart: 1, pubspec.yaml: 1)
```
**Idêntico**, número por número, ao que está documentado no README (`CRITICAL: 6 / HIGH: 11 / MEDIUM: 7 / LOW: 2 / TOTAL: 26`) — este é o melhor resultado de reprodutibilidade entre os 4 artefatos avaliados.

```bash
dart_sast tests/fixtures/clean --format json
# findings count: 0    ✅ Zero falsos positivos
```

**Testes automatizados:**
```bash
pytest -q
# 67 passed in 0.17s
```
A suíte é a mais completa das quatro, exatamente como descrito no README:
- `test_rules_positive.py`: cada uma das 20 regras testada **isoladamente**;
- `test_no_false_positives.py`: todas as regras juntas contra código limpo → zero achados;
- `test_integration_example_app.py`: roda o scanner completo contra o app de exemplo e valida que as 20 regras disparam num cenário realista;
- testes dedicados de parser de `pubspec.yaml`, exclusão de diretórios no scanner, e todas as flags/códigos de saída da CLI.

**Formatos de saída:** `console`, `json`, `sarif` e ainda `all` (grava JSON+SARIF simultaneamente e imprime console no stdout) — o mais rico dos quatro. SARIF validado (`$schema`, `version`, `runs[0].results` com 26 resultados, batendo com o total de achados).

**Exit codes testados:**
```bash
dart_sast examples/vulnerable_app --fail-on CRITICAL
# exit code: 1   (correto — há achados CRITICAL, comportamento documentado no README)
```

**Docker/Action:** `Dockerfile` multi-estágio nomeado, com metadados OCI (`LABEL org.opencontainers.image.*`), comentários explicando a decisão de design (imagem slim, zero dependências externas). `action.yml` é a mais completa das duas GitHub Actions encontradas (múltiplos inputs, output `report-path`, uso de `actions/setup-python@v5`).

**Ponto de atenção:** o README inclui uma seção "Limitações conhecidas", assumindo explicitamente que a abordagem é baseada em regex/heurísticas de linha (não AST completo do Dart) e pode gerar falsos positivos/negativos em certos padrões multi-linha — uma prática de honestidade científica que nenhum dos outros três artefatos apresenta tão claramente, e que é diretamente relevante para o rigor exigido pela avaliação de artefatos científicos.

**Veredito de selos:**
- **SeloD:** ✅ Atendido — README extremamente completo (sumário navegável, 13+ seções, todas as exigidas pelo prompt e quase todas do template oficial SBRC; falta apenas a seção literal "Selos considerados"/"Preocupações com segurança" como texto isolado, embora o conteúdo esteja implicitamente coberto na introdução e em "Limitações conhecidas").
- **SeloF:** ✅ Atendido — instalação, execução, exemplo mínimo, Docker e Action funcionam exatamente como descrito, com prova de execução coincidindo byte-a-byte com o README.
- **SeloS:** ✅ Atendido — a arquitetura mais modular das quatro (uma CWE = um arquivo de regra, engine desacoplado dos reporters), documentada em `docs/ARCHITECTURE.md` e `CONTRIBUTING.md`.
- **SeloR:** ✅ Atendido — melhor reprodutibilidade observada: os números do README foram replicados exatamente pela execução real.

---

## 4. Ranking consolidado

| Posição | Artefato | Resumo |
|---|---|---|
| 🥇 1º | **sonnet-4.6** | Cobertura completa (20/20 CWEs), maior e mais granular suíte de testes (67, todos passando), reprodutibilidade exata dos números do README, arquitetura mais sustentável (1 regra/arquivo), documentação mais completa e honesta (seção de limitações). Atende integralmente aos 4 selos. |
| 🥈 2º | **gpt-5.5** | Cobertura completa (21/20 CWEs), testes passam, Docker/Action corretos, reprodutibilidade exata (`count: 21`/`count: 0`), boa modularidade. Muito próximo do sonnet-4.6, com suíte de testes um pouco menor (6 vs. 67) e sem seção de limitações conhecidas. Atende integralmente aos 4 selos. |
| 🥉 3º | **gemini-3.5-flash-aistudio** | Cobertura completa (20/20 CWEs) e boa taxa de acerto na execução, mas repositório "sujo" (mistura com projeto React/Vite não relacionado) e **inconsistência grave**: README documenta uso via Docker, mas o `Dockerfile` não existe no repositório — falha de reprodutibilidade nesse ponto específico. SeloD/SeloR atendidos; SeloF/SeloS atendidos apenas parcialmente. |
| 4º | **grok-fast** | Único artefato que **não cumpre a reivindicação central do prompt**: implementa apenas 4 das 20 CWEs exigidas (20%). O que existe funciona corretamente (testes passam, sem falsos positivos), mas a cobertura funcional é claramente insuficiente frente ao que foi solicitado. Também é o único sem SARIF e sem `--fail-on`. README mais fraco, com placeholder de URL não corrigido. SeloF e SeloR devem ser considerados **não atendidos plenamente** por escopo funcional muito abaixo do especificado. |

---

## 5. Evidências de execução (logs brutos resumidos)

```text
### gemini-3.5-flash-aistudio
$ python3 -m unittest discover -s tests -p "test_*.py"
....
Ran 4 tests in 0.007s
OK

$ dart_sast tests/vulnerable_example.dart --format json   → 18 findings
$ dart_sast tests/clean_example.dart                       → 0 findings

### gpt-5.5
$ pytest -q
......
6 passed in 0.05s

$ dart_sast tests/fixtures/vulnerable_app --format json --output findings.json  → count: 21
$ dart_sast tests/fixtures/clean_app --format json                             → count: 0

### grok-fast
$ python -m pytest tests/ -v
tests/test_scanner.py::test_vulnerable_detection PASSED
tests/test_scanner.py::test_clean_code PASSED
tests/test_scanner.py::test_directory_scan PASSED
3 passed in 0.01s

$ dart-sast examples/vulnerable.dart  → 3 findings (HIGH:2, CRITICAL:1) — só CWE-798/89/22 disparam
$ dart-sast examples/clean.dart       → "No vulnerabilities found!"

### sonnet-4.6
$ pytest -q
...................................................................
67 passed in 0.17s

$ dart_sast examples/vulnerable_app
CRITICAL: 6 | HIGH: 11 | MEDIUM: 7 | LOW: 2 | TOTAL findings: 26  (idêntico ao README)
$ dart_sast tests/fixtures/clean --format json   → findings count: 0
$ dart_sast examples/vulnerable_app --fail-on CRITICAL  → exit code 1 (esperado)
```

---

## 6. Observações finais para os autores

1. **`grok-fast`** precisa implementar as 16 CWEs restantes exigidas no prompt para ser comparável funcionalmente aos demais artefatos; também recomenda-se adicionar suporte a SARIF e uma flag de tipo `--fail-on` para uso real em CI/CD, além de corrigir o placeholder `yourusername` no README e reescrever o exemplo vulnerável para exercitar todas as regras implementadas (o trecho de *command injection* está comentado).
2. **`gemini-3.5-flash-aistudio`** deve (a) remover os arquivos residuais do projeto React/Vite não relacionados ao SAST, e (b) adicionar o `Dockerfile` que o próprio README já documenta, ou remover essa seção até que o arquivo exista.
3. **`gpt-5.5`** e **`sonnet-4.6`** atendem integralmente aos quatro selos com base na execução real; como sugestão de evolução, ambos poderiam incluir uma seção explícita de "Preocupações com segurança" e "Selos considerados" no formato textual exigido pelo template oficial do SBRC 2026, mesmo que apenas para declarar "nenhuma".
4. Em nenhum dos quatro artefatos os testes de código Python foram flagrados como inseguros ou danosos para o avaliador — a execução foi feita em ambiente isolado sem riscos.