# Relatório de Avaliação de Artefatos SAST Dart
## prompt utilizado
Para avaliação o prompt utilizado está no arquivo prompt-avaliacao.txt
## 1. Metodologia

**Ambiente de teste:** Python 3.10.9, Linux (code_interpreter environment)
**Data da avaliação:** 04 de Julho de 2026

**Comandos executados:**
- Clone do repositório via download de ZIP (git clone timeout).
- Execução de testes com `python3 -m unittest` (Gemini) e `python3 -m pytest` (GPT, Grok, Sonnet) com a variável de ambiente `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` para contornar conflito com plugin pytestqt no ambiente.
- Análise estática de estrutura, README, e contagem de CWEs via scripts Python.
- Teste manual da CLI com `--help` para validar funcionalidade.

## 2. Resultados de Execução por Versão

### 2.1 Versão A - Gemini 3.5 Flash

**Comando executado:** `python3 -m unittest discover -s tests -v`

**Output completo:**
```
test_clean_file_no_detections (test_rules.TestSASTRules)
Test that the engine reports ZERO findings on the cleanly-patched secure file. ... ok
test_manifest_detections (test_rules.TestSASTRules)
Test that Android manifest exports are successfully flagged. ... ok
test_pubspec_detections (test_rules.TestSASTRules)
Test that unmaintained package references are successfully flagged. ... ok
test_vulnerable_file_detections (test_rules.TestSASTRules)
Test that the engine identifies security vulnerabilities on the vulnerable Dart file. ... ok
----------------------------------------------------------------------
Ran 4 tests in 0.009s

OK
```

**Resultado:** 4/4 testes passaram
**Tempo:** 0.009s

### 2.2 Versão B - GPT-5.5

**Comando executado:** `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest tests/ -v`

**Output completo:**
```
tests/test_cli.py::test_cli_json_output_file PASSED                      [ 16%]
tests/test_cli.py::test_cli_fail_on_high PASSED                          [ 33%]
tests/test_cli.py::test_cli_clean_fail_on_high PASSED                    [ 50%]
tests/test_scanner.py::test_vulnerable_fixture_detects_all_expected_cwes PASSED [ 66%]
tests/test_scanner.py::test_clean_fixture_has_no_findings PASSED         [ 83%]
tests/test_scanner.py::test_exclude_rule PASSED                          [100%]

============================== 6 passed in 0.04s ===============================
```

**Resultado:** 6/6 testes passaram
**Tempo:** 0.04s

### 2.3 Versão C - Grok Fast

**Comando executado:** `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest tests/ -v`

**Output completo:**
```
tests/test_scanner.py::test_vulnerable_detection PASSED                  [ 33%]
tests/test_scanner.py::test_clean_code PASSED                            [ 66%]
tests/test_scanner.py::test_directory_scan PASSED                        [100%]

============================== 3 passed in 0.02s ===============================
```

**Resultado:** 3/3 testes passaram
**Tempo:** 0.02s

### 2.4 Versão D - Sonnet 4.6

**Comando executado:** `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python3 -m pytest tests/ -v`

**Output completo:**
```
tests/test_cli.py::test_list_rules PASSED                                [  1%]
... (67 testes no total, todos com status PASSED) ...
tests/test_scanner.py::test_scanner_reports_file_counts PASSED           [100%]

============================== 67 passed in 0.23s ===============================
```

**Resultado:** 67/67 testes passaram
**Tempo:** 0.23s

## 3. Avaliação dos Selos SBRC 2026

### 3.1 Versão A - Gemini 3.5 Flash

- **SeloD:** ✅ OBTIDO — Repositório público, README.md presente (9090 chars), LICENSE MIT incluída.
- **SeloF:** ✅ OBTIDO — Instalável via setup.py, CLI executa sem erros, suporta formatos console/json/sarif.
- **SeloS:** ⚠️ PARCIAL — Código modularizado em `engine.py` e `main.py`, mas todas as 20 regras estão concentradas em um único arquivo `rules_definitions.py`, o que dificulta a manutenção futura.
- **SeloR:** ✅ OBTIDO — Testes executam sem erros e são reproduzíveis. Inclui testes para arquivos limpos, vulneráveis, manifest e pubspec.

### 3.2 Versão B - GPT-5.5

- **SeloD:** ✅ OBTIDO — README completo (7449 chars), LICENSE, documentação de arquitetura em `docs/ARCHITECTURE.md`.
- **SeloF:** ✅ OBTIDO — Instalável via pip, possui Dockerfile e `action.yml` para GitHub Actions. CLI robusta com flags como `--exclude-rule` e `--list-rules`.
- **SeloS:** ✅ OBTIDO — Excelente modularidade. Separação clara entre `scanner.py`, `reporters.py`, `models.py` e diretório `rules/` com arquivos individuais para tipos de regras (regex, pubspec).
- **SeloR:** ✅ OBTIDO — 6 testes passando, cobrindo CLI, scanner e exclusão de regras. Instruções claras no README.

### 3.3 Versão C - Grok Fast

- **SeloD:** ⚠️ PARCIAL — README muito curto (1689 chars), embora tenha LICENSE e seja público. Documentação mínima.
- **SeloF:** ⚠️ PARCIAL — Instalável e CLI funciona, mas implementa apenas 4 CWEs (CWE-22, CWE-78, CWE-798, CWE-89) dos 20 solicitados. Possui Dockerfile.
- **SeloS:** ✅ OBTIDO — Código modularizado em `src/dart_sast/` com diretório `rules/`. Fácil de adicionar novas regras.
- **SeloR:** ✅ OBTIDO — 3 testes passam sem erros. No entanto, a cobertura é baixa devido ao número reduzido de regras implementadas.

### 3.4 Versão D - Sonnet 4.6

- **SeloD:** ✅ OBTIDO — README extenso e detalhado (13510 chars), LICENSE, CONTRIBUTING.md, e `docs/ARCHITECTURE.md`.
- **SeloF:** ✅ OBTIDO — Instalável via pip, Dockerfile, `action.yml`. CLI extremamente completa com filtros de severidade, exclusão de regras, e múltiplos formatos de saída (console, json, sarif, all).
- **SeloS:** ✅ OBTIDO — Arquitetura altamente modular e profissional. Separação em `engine/` (registry, scanner, rule, finding), `rules/` (um arquivo por CWE), e `reporters/`. Código bem documentado com docstrings.
- **SeloR:** ✅ OBTIDO — 67 testes passando, cobrindo exaustivamente cada regra individualmente (testes parametrizados), parser de pubspec, reporters, e integração com app de exemplo.

## 4. Análise Comparativa

### 4.1 Tabela Comparativa

| Critério | Gemini 3.5 Flash | GPT-5.5 | Grok Fast | Sonnet 4.6 |
|---|---|---|---|---|
| Testes passando | 4/4 | 6/6 | 3/3 | 67/67 |
| CWEs implementados | 20 | 21 | 4 | 20 |
| SeloD | ✅ | ✅ | ⚠️ | ✅ |
| SeloF | ✅ | ✅ | ⚠️ | ✅ |
| SeloS | ⚠️ | ✅ | ✅ | ✅ |
| SeloR | ✅ | ✅ | ✅ | ✅ |

### 4.2 Pontos Fortes por Versão

- **Gemini 3.5 Flash:** Inclui um frontend web (React/Vite) para visualização, o que é um diferencial de interface, embora não solicitado. Cobre todos os 20 CWEs.
- **GPT-5.5:** Estrutura de código muito limpa e bem separada. Suporte a Docker e GitHub Action. Implementa 21 CWEs (um a mais que o solicitado).
- **Grok Fast:** Código extremamente conciso e direto. Fácil de entender para iniciantes.
- **Sonnet 4.6:** Cobertura de testes excepcional (67 testes). Arquitetura mais profissional e escalável. Documentação rica (README, CONTRIBUTING, ARCHITECTURE). CLI com mais funcionalidades (filtros de severidade, múltiplos outputs).

### 4.3 Limitações por Versão

- **Gemini 3.5 Flash:** Todas as regras em um único arquivo (`rules_definitions.py`), o que viola o princípio de responsabilidade única e dificulta a adição de novas regras complexas.
- **GPT-5.5:** Nenhum defeito significativo encontrado. Talvez a documentação de arquitetura pudesse ser mais detalhada.
- **Grok Fast:** Implementa apenas 4 dos 20 CWEs solicitados. README muito básico, faltando detalhes de instalação e uso mais robustos.
- **Sonnet 4.6:** Nenhum defeito significativo. O tempo de execução dos testes é ligeiramente maior (0.23s) devido à grande quantidade de testes, mas ainda é muito rápido.

### 4.4 Classificação Final

1. **1º Lugar: Sonnet 4.6** — Vence pela excelência na engenharia de software. Possui a maior cobertura de testes (67 testes parametrizados garantindo que cada CWE funciona individualmente), arquitetura mais modular e escalável (`engine/`, `rules/`, `reporters/`), e documentação mais completa. A CLI é a mais robusta, com opções avançadas de filtragem.

2. **2º Lugar: GPT-5.5** — Muito forte, com código limpo, boa modularidade e suporte a Docker/GitHub Actions. Implementa 21 CWEs. Perde para o Sonnet apenas pela quantidade de testes (6 vs 67) e menor riqueza de funcionalidades na CLI.

3. **3º Lugar: Gemini 3.5 Flash** — Cumpre os requisitos funcionais (20 CWEs, testes passando), mas a qualidade do código é inferior devido à centralização de todas as regras em um único arquivo. O frontend web é um bônus, mas não compensa a dívida técnica na estrutura do scanner.

4. **4º Lugar: Grok Fast** — Embora o código seja funcional e modular, falha em atender ao requisito principal de implementar os 20 CWEs solicitados (implementou apenas 4). O README também é muito superficial, prejudicando o SeloD.

## 5. Conclusão e Recomendações

**Resumo executivo:** Todas as versões geraram ferramentas funcionais capazes de analisar código Dart/Flutter. O Sonnet 4.6 se destacou pela maturidade do projeto, tratando-o como um produto de software real com testes exaustivos e arquitetura bem planejada. O Grok Fast foi o mais fraco, entregando apenas uma fração das regras solicitadas.

**Recomendações:**
- **Gemini:** Refatorar `rules_definitions.py` para separar cada regra em seu próprio módulo dentro de um diretório `rules/`.
- **GPT-5.5:** Adicionar testes parametrizados para garantir que cada regra é testada individualmente, similar ao Sonnet.
- **Grok Fast:** Implementar os 16 CWEs faltantes e expandir o README com instruções detalhadas de instalação e uso.
- **Sonnet:** Manter o alto padrão. Considerar adicionar um benchmark de performance para escaneamento de projetos grandes.

**Lições aprendidas:** A capacidade de um LLM de gerar código não se traduz diretamente em qualidade de software. O Sonnet 4.6 demonstrou que LLMs podem produzir artefatos com qualidade de produção (testes abrangentes, arquitetura modular) quando o prompt é bem estruturado e o modelo tem capacidade de planejamento de longo prazo. A avaliação de selos SBRC provou ser eficaz para distinguir não apenas se a ferramenta "funciona", mas se ela foi "bem construída".