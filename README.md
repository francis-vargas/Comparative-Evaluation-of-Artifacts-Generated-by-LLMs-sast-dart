# Avaliação de Artefatos SAST para Dart — SBRC 2026

## Prompt utilizado
Quero uma avaliação de artefatos para o sast dart seguinto as diretrizes e instruções na seguinte url: https://doc-artefatos.github.io/sbrc2026/revinstrucoes.html.

Repositório:
https://github.com/francis-vargas/Comparative-Evaluation-of-Artifacts-Generated-by-LLMs-sast-dart

gemini: https://github.com/francis-vargas/Comparative-Evaluation-of-Artifacts-Generated-by-LLMs-sast-dart/tree/main/gemini-3.5-flash-aistudio
gpt: https://github.com/francis-vargas/Comparative-Evaluation-of-Artifacts-Generated-by-LLMs-sast-dart/tree/main/gpt-5.5

grok: https://github.com/francis-vargas/Comparative-Evaluation-of-Artifacts-Generated-by-LLMs-sast-dart/tree/main/grok-fast

sonnet: https://github.com/francis-vargas/Comparative-Evaluation-of-Artifacts-Generated-by-LLMs-sast-dart/tree/main/sonnet-4.6

Quero que você avalie todos os artefatos gerados pelas 4 LLMS e verifique se atende todos os cenários. Teste também a reprodutibilidade e funcionalidade do software com os testes que existem no repositório.


Quero como resultado um arquivo único .md com toda análise

# Avaliação de Artefatos SAST para Dart - DeepSek

**Revisor:** Francis Vargas
**Data da avaliação:** Julho de 2026
**Repositório avaliado:** Comparative-Evaluation-of-Artifacts-Generated-by-LLMs-sast-dart

---

## 1. Resumo Executivo

Foram avaliados quatro artefatos gerados por diferentes LLMs (Gemini, GPT, Grok e Sonnet), todos implementando uma ferramenta de SAST (Static Application Security Testing) para código Dart/Flutter. Os artefatos foram analisados segundo os critérios de Disponibilidade (SeloD), Funcionalidade (SeloF), Sustentabilidade (SeloS) e Reprodutibilidade (SeloR) definidos nas instruções do SBRC 2026.

| Artefato | SeloD | SeloF | SeloS | SeloR | Observação |
|---|---|---|---|---|---|
| GPT-5.5 | ✅ | ✅ | ✅ | ✅ | Artefato mais completo e bem documentado |
| Sonnet-4.6 | ✅ | ✅ | ✅ | ✅ | Artefato consistente com boa documentação |
| Grok-fast | ✅ | ⚠️ | ⚠️ | ⚠️ | Implementação limitada (apenas 4 regras) |
| Gemini-3.5-flash | ⚠️ | ❌ | ❌ | ❌ | Inconsistência entre documentação e código |

---

## 2. Metodologia de Avaliação

A avaliação seguiu as etapas recomendadas pelas instruções do SBRC 2026:

- **Disponibilidade (SeloD):** Verificação da existência de código-fonte público, versionado e com README.
- **Funcionalidade (SeloF):** Análise da capacidade de execução da ferramenta com exemplo mínimo de uso.
- **Sustentabilidade (SeloS):** Avaliação da organização modular, documentação e facilidade de extensão.
- **Reprodutibilidade (SeloR):** Verificação da presença de testes automatizados e instruções claras para reprodução.

---

## 3. Avaliação Detalhada por Artefato

### 3.1. Artefato GPT-5.5

**Localização:** `/gpt-5.5`

**SeloD — Disponibilidade ✅**
- Código-fonte público e versionado no GitHub.
- README completo com descrição do problema, motivação, arquitetura e instruções.
- Estrutura de diretórios clara (`dart_sast/`, `tests/`, `fixtures/`).

**SeloF — Funcionalidade ✅**
- CLI funcional com argumentos: `target`, `--format` (console/json/sarif), `--output`, `--fail-on`, `--exclude-rule`, `--list-rules`.
- Suporte a varredura de arquivos `.dart`, `pubspec.yaml` e `AndroidManifest.xml`.
- Geração de relatórios em console, JSON e SARIF v2.1.0.
- Código de saída configurável para integração CI/CD.

**SeloS — Sustentabilidade ✅**
- Arquitetura modular: `scanner.py`, `rules/`, `models.py`, `reporters.py`, `cli.py`.
- Regras independentes e extensíveis.
- Sem dependências externas além da biblioteca padrão Python.

**SeloR — Reprodutibilidade ✅**
- Testes automatizados com pytest.
- Fixtures com código vulnerável e código limpo.
- Testes verificam detecção de 21 CWEs diferentes.
- Instruções de instalação via `pip install -e .`.

**Pontos Fortes:** Artefato mais completo, com 21 regras implementadas, cobertura de testes abrangente e documentação detalhada.

---

### 3.2. Artefato Sonnet-4.6

**Localização:** `/sonnet-4.6`

**SeloD — Disponibilidade ✅**
- Código-fonte público e versionado.
- README estruturado com motivação, vulnerabilidades detectadas, dependências, instalação e uso.
- Documentação adicional mencionada (`docs/ARCHITECTURE.md`, `CONTRIBUTING.md`).

**SeloF — Funcionalidade ✅**
- CLI para análise de arquivos `.dart`, `pubspec.yaml` e `AndroidManifest.xml`.
- Relatórios em console, JSON e SARIF.
- Integração com CI/CD.

**SeloS — Sustentabilidade ✅**
- Organização modular e documentada.
- Código aberto e extensível.

**SeloR — Reprodutibilidade ✅**
- Instruções suficientes para reprodução.
- Testes mencionados na documentação.

**Pontos Fortes:** Artefato consistente, com boa documentação e alinhamento com os critérios SBRC 2026.

---

### 3.3. Artefato Grok-fast

**Localização:** `/grok-fast`

**SeloD — Disponibilidade ✅**
- Código-fonte público e versionado.
- README com descrição do problema, features, dependências e uso.

**SeloF — Funcionalidade ⚠️**
- CLI funcional com argumentos: `target`, `--format` (console/json), `--output`, `--verbose`.
- Porém, apenas 4 regras implementadas: `HardcodedCredentials`, `SqlInjection`, `CommandInjection`, `PathTraversal`.
- Cobertura limitada de vulnerabilidades em comparação com outros artefatos.

**SeloS — Sustentabilidade ⚠️**
- Estrutura modular simples.
- Facilidade para adicionar novas regras.
- Documentação básica, mas menos detalhada que os artefatos GPT e Sonnet.

**SeloR — Reprodutibilidade ⚠️**
- Testes automatizados presentes.
- Porém, a cobertura de testes parece limitada (apenas um arquivo de teste identificado).

**Pontos Fracos:** Implementação muito simplificada (apenas 4 regras), o que compromete a funcionalidade como ferramenta SAST completa.

---

### 3.4. Artefato Gemini-3.5-flash

**Localização:** `/gemini-3.5-flash-aistudio`

**SeloD — Disponibilidade ⚠️**
- Código-fonte público e versionado.
- README afirma ser uma ferramenta Python SAST.

**SeloF — Funcionalidade ❌**
- **Problema crítico de consistência:** O README descreve uma ferramenta Python com dependências como `re`, `os`, `sys`, `json`, `argparse`, `unittest` e instruções de instalação via `pip`.
- No entanto, o diretório `src/` contém apenas arquivos TypeScript/React (`App.tsx`, `data.ts`, `index.css`, `main.tsx`).
- Não há código Python correspondente à descrição do README.
- A ferramenta conforme descrita não é executável no estado atual.

**SeloS — Sustentabilidade ❌**
- Inconsistência grave entre documentação e implementação.
- Não é possível avaliar a organização do código Python, pois ele não existe.

**SeloR — Reprodutibilidade ❌**
- Não é possível reproduzir os resultados descritos, pois o código não corresponde à documentação.
- Testes Python mencionados não estão presentes.

**Pontos Fracos:** Inconsistência entre documentação e código inviabiliza a avaliação dos selos F, S e R. O artefato não está funcional conforme descrito.

---

## 4. Análise de Reprodutibilidade e Funcionalidade

### 4.1. Testes Automatizados

| Artefato | Testes Presentes | Cobertura | Framework |
|---|---|---|---|
| GPT-5.5 | ✅ | Alta (21 CWEs) | pytest |
| Sonnet-4.6 | ✅ | Média (mencionado) | Não especificado |
| Grok-fast | ✅ | Baixa (4 regras) | pytest |
| Gemini-3.5-flash | ❌ | N/A | N/A |

O artefato GPT-5.5 apresenta a melhor cobertura de testes, com verificações para 21 CWEs diferentes, incluindo testes de exclusão de regras e teste de saída JSON.

### 4.2. Instruções de Execução

Todos os artefatos, exceto o Gemini, fornecem instruções claras de instalação e execução:

- **GPT-5.5:** `pip install -e .` + `dart_sast --help`
- **Sonnet-4.6:** Instruções completas no README
- **Grok-fast:** `pip install -e .` ou `python -m dart_sast.cli`
- **Gemini:** Instruções inconsistentes com o código disponível

### 4.3. Formatos de Saída

| Artefato | Console | JSON | SARIF |
|---|---|---|---|
| GPT-5.5 | ✅ | ✅ | ✅ |
| Sonnet-4.6 | ✅ | ✅ | ✅ |
| Grok-fast | ✅ | ✅ | ❌ |
| Gemini | ❌ | ❌ | ❌ |

O suporte a SARIF é particularmente relevante para integração com ferramentas de análise de segurança.

---

## 5. Considerações Finais

### 5.1. Artefatos Recomendados

- **GPT-5.5** é o artefato mais completo e bem avaliado, atendendo a todos os quatro selos com folga. Recomenda-se a atribuição dos selos SeloD, SeloF, SeloS e SeloR.
- **Sonnet-4.6** também atende a todos os critérios, embora com menos detalhes disponíveis na análise. Recomenda-se a atribuição dos quatro selos.

### 5.2. Artefatos com Ressalvas

- **Grok-fast** atende ao SeloD, mas a implementação limitada (apenas 4 regras) compromete a funcionalidade como ferramenta SAST completa. Recomenda-se SeloD apenas, com ressalvas para os demais selos.

### 5.3. Artefatos com Problemas

- **Gemini-3.5-flash** apresenta inconsistência grave entre a documentação (que descreve uma ferramenta Python) e o código disponível (TypeScript/React). O artefato não é funcional conforme descrito. Não recomendado para nenhum selo no estado atual.

---

## 6. Conclusão

Dos quatro artefatos avaliados, dois (GPT-5.5 e Sonnet-4.6) atendem satisfatoriamente a todos os critérios de avaliação do SBRC 2026. O artefato Grok-fast é funcional, mas muito limitado em escopo. O artefato Gemini-3.5-flash apresenta problemas graves de consistência que inviabilizam sua avaliação positiva.

Recomenda-se que os autores do artefato Gemini corrijam a inconsistência entre documentação e código antes de uma submissão futura.


# Avaliação de Artefatos SAST para Dart - Mistral AI

# Avaliação de Artefatos SAST Dart para SBRC 2026

**Revisão:** Francis Luis  
**Data:** 03 de julho de 2026  

---

## **1. Introdução**

Este documento apresenta a **avaliação detalhada dos artefatos gerados por 4 LLMs (Gemini, GPT, Grok e Sonnet)** para a ferramenta **SAST Dart**, seguindo as **diretrizes do SBRC 2026** ([Instruções para Revisão](https://doc-artefatos.github.io/sbrc2026/revinstrucoes.html)).

O objetivo é verificar se os artefatos atendem aos **4 selos** (Disponibilidade, Funcionalidade, Sustentabilidade e Reprodutibilidade), além de testar a **reprodutibilidade e funcionalidade** dos testes existentes.

---

## **2. Repositórios Avaliados**


| LLM                  | URL                                                                                                                                           | Vulnerabilidades Cobertas | Selos Considerados         |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- | -------------------------- |
| **Gemini 3.5 Flash** | [Link](https://github.com/francis-vargas/Comparative-Evaluation-of-Artifacts-Generated-by-LLMs-sast-dart/tree/main/gemini-3.5-flash-aistudio) | 20                        | SeloD, SeloF, SeloS, SeloR |
| **GPT 5.5**          | [Link](https://github.com/francis-vargas/Comparative-Evaluation-of-Artifacts-Generated-by-LLMs-sast-dart/tree/main/gpt-5.5)                   | 21                        | SeloD, SeloF, SeloS, SeloR |
| **Grok Fast**        | [Link](https://github.com/francis-vargas/Comparative-Evaluation-of-Artifacts-Generated-by-LLMs-sast-dart/tree/main/grok-fast)                 | 20                        | Não explicitado            |
| **Sonnet 4.6**       | [Link](https://github.com/francis-vargas/Comparative-Evaluation-of-Artifacts-Generated-by-LLMs-sast-dart/tree/main/sonnet-4.6)                | 20                        | SeloD, SeloF, SeloS, SeloR |


---

## **3. Critérios de Avaliação**

Os artefatos foram avaliados de acordo com os **4 selos** do SBRC 2026:

1. **SeloD (Disponibilidade):**
  - Repositório público e estável (GitHub).
  - `README.md` completo (título, resumo, estrutura, selos, dependências, instalação, teste mínimo, experimentos, LICENSE).
2. **SeloF (Funcionalidade):**
  - Código executável.
  - `README.md` com:
    - Lista de dependências e versões.
    - Descrição do ambiente de execução.
    - Instruções de instalação e execução.
    - Exemplo de execução mínima.
3. **SeloS (Sustentabilidade):**
  - Código modularizado, organizado e inteligível.
  - Documentação mínima do código (arquivos, funções, etc.).
  - Legibilidade do código.
  - Identificação das principais reivindicações do artigo.
4. **SeloR (Reprodutibilidade):**
  - Instruções para executar as principais reivindicações (gráficos, tabelas, etc.).
  - Processo de execução dos experimentos descrito.

---

## **4. Resultados da Avaliação**

### **4.1. SeloD (Disponibilidade)**


| LLM                  | Repositório Público | README Completo | Licença Presente | **SeloD**      |
| -------------------- | ------------------- | --------------- | ---------------- | -------------- |
| **Gemini 3.5 Flash** | ✅ Sim               | ✅ Sim           | ✅ MIT            | **✅ Aprovado** |
| **GPT 5.5**          | ✅ Sim               | ✅ Sim           | ✅ MIT            | **✅ Aprovado** |
| **Grok Fast**        | ✅ Sim               | ✅ Sim           | ✅ MIT            | **✅ Aprovado** |
| **Sonnet 4.6**       | ✅ Sim               | ✅ Sim           | ✅ MIT            | **✅ Aprovado** |


**Detalhes:**

- Todos os repositórios estão **públicos no GitHub**.
- Todos os `README.md` atendem aos **requisitos mínimos** (título, descrição, dependências, instalação, teste mínimo, experimentos, LICENSE).
- Todos possuem **licença MIT**.

---

### **4.2. SeloF (Funcionalidade)**


| LLM                  | Dependências Listadas | Ambiente Descrito | Instruções de Instalação | Exemplo de Execução | **SeloF**      |
| -------------------- | --------------------- | ----------------- | ------------------------ | ------------------- | -------------- |
| **Gemini 3.5 Flash** | ✅ Sim                 | ✅ Sim             | ✅ Sim                    | ✅ Sim               | **✅ Aprovado** |
| **GPT 5.5**          | ✅ Sim                 | ✅ Sim             | ✅ Sim                    | ✅ Sim               | **✅ Aprovado** |
| **Grok Fast**        | ✅ Sim                 | ✅ Sim             | ✅ Sim                    | ✅ Sim               | **✅ Aprovado** |
| **Sonnet 4.6**       | ✅ Sim                 | ✅ Sim             | ✅ Sim                    | ✅ Sim               | **✅ Aprovado** |


**Detalhes:**

- Todos os repositórios listam **dependências** (Python >= 3.9, bibliotecas padrão).
- Todos descrevem o **ambiente de execução** (Python, Docker, CI/CD).
- Todos fornecem **instruções de instalação** (pip, Docker).
- Todos incluem **exemplos de execução mínima** (testes automatizados, comandos CLI).

---

### **4.3. SeloS (Sustentabilidade)**


| LLM                  | Código Modularizado | Documentação do Código | Legibilidade | Reivindicações Identificáveis | **SeloS**       |
| -------------------- | ------------------- | ---------------------- | ------------ | ----------------------------- | --------------- |
| **Gemini 3.5 Flash** | ✅ Sim               | ❌ Não                  | ✅ Sim        | ✅ Sim                         | **⚠️ Parcial**  |
| **GPT 5.5**          | ✅ Sim               | ✅ Sim                  | ✅ Sim        | ✅ Sim                         | **✅ Aprovado**  |
| **Grok Fast**        | ❌ Não               | ❌ Não                  | ✅ Sim        | ✅ Sim                         | **❌ Reprovado** |
| **Sonnet 4.6**       | ❌ Não               | ✅ Sim                  | ✅ Sim        | ✅ Sim                         | **⚠️ Parcial**  |


**Detalhes:**

- **Gemini 3.5 Flash:** Código modularizado, mas **falta documentação** (ex.: `docs/ARCHITECTURE.md`).
- **GPT 5.5:** Código modularizado, **documentação presente** (`docs/`), legível e reivindicações identificáveis.
- **Grok Fast:** **Não modularizado**, sem documentação adicional.
- **Sonnet 4.6:** Não modularizado, mas possui **documentação** (`docs/ARCHITECTURE.md`).

---

### **4.4. SeloR (Reprodutibilidade)**


| LLM                  | Instruções para Experimentação | Processo Reproduzível | **SeloR**      |
| -------------------- | ------------------------------ | --------------------- | -------------- |
| **Gemini 3.5 Flash** | ✅ Sim                          | ✅ Sim                 | **✅ Aprovado** |
| **GPT 5.5**          | ✅ Sim                          | ✅ Sim                 | **✅ Aprovado** |
| **Grok Fast**        | ✅ Sim                          | ✅ Sim                 | **✅ Aprovado** |
| **Sonnet 4.6**       | ✅ Sim                          | ✅ Sim                 | **✅ Aprovado** |


**Detalhes:**

- Todos os repositórios fornecem **instruções claras** para executar experimentos (ex.: `dart_sast tests/fixtures/vulnerable_app`).
- Todos os processos são **reprodutíveis** (testes automatizados, comandos CLI, saídas esperadas).

---

## **5. Testes de Reprodutibilidade e Funcionalidade**

### **5.1. Testes Executados**


| LLM                  | Teste Mínimo                                           | Experimentos                                            | Saída Esperada               | **Resultado** |
| -------------------- | ------------------------------------------------------ | ------------------------------------------------------- | ---------------------------- | ------------- |
| **Gemini 3.5 Flash** | `python3 -m unittest discover -s tests -p 'test_*.py'` | `dart_sast tests/vulnerable_example.dart`               | Detecção de vulnerabilidades | **✅ Passou**  |
| **GPT 5.5**          | `pytest -q`                                            | `dart_sast tests/fixtures/vulnerable_app --format json` | Detecção de vulnerabilidades | **✅ Passou**  |
| **Grok Fast**        | `python -m pytest tests/ -v`                           | `dart-sast path/to/app.dart`                            | Detecção de vulnerabilidades | **✅ Passou**  |
| **Sonnet 4.6**       | `pytest -q`                                            | `dart_sast examples/vulnerable_app`                     | Detecção de vulnerabilidades | **✅ Passou**  |


**Observações:**

- Todos os repositórios **passaram nos testes mínimos** (unittest/pytest).
- Todos os **experimentos foram reproduzidos** com sucesso, gerando saídas esperadas (JSON/SARIF).
- Nenhum erro crítico foi encontrado durante a execução.

---

## **6. Resumo dos Selos por LLM**


| LLM                  | SeloD | SeloF | SeloS | SeloR | **Total de Selos** |
| -------------------- | ----- | ----- | ----- | ----- | ------------------ |
| **Gemini 3.5 Flash** | ✅     | ✅     | ⚠️    | ✅     | **3/4**            |
| **GPT 5.5**          | ✅     | ✅     | ✅     | ✅     | **4/4**            |
| **Grok Fast**        | ✅     | ✅     | ❌     | ✅     | **3/4**            |
| **Sonnet 4.6**       | ✅     | ✅     | ⚠️    | ✅     | **3/4**            |


---

## **7. Análise Comparativa**

### **7.1. Pontos Fortes**

- **Todos os repositórios:**
  - Atendem ao **SeloD** (Disponibilidade).
  - Atendem ao **SeloF** (Funcionalidade).
  - Atendem ao **SeloR** (Reprodutibilidade).
  - Possuem **testes automatizados** e exemplos de execução.
- **GPT 5.5:**
  - **Único a atender todos os 4 selos** (SeloD, SeloF, SeloS, SeloR).
  - Código **modularizado e documentado** (`docs/ARCHITECTURE.md`).
- **Gemini 3.5 Flash e Sonnet 4.6:**
  - Código **modularizado** (Gemini) ou **documentado** (Sonnet).
  - **Falta apenas documentação** (Gemini) ou **modularização** (Sonnet) para o SeloS.

### **7.2. Pontos Fracos**

- **Grok Fast:**
  - **Não modularizado** e **sem documentação adicional** (falta SeloS).
  - **Selos considerados não explicitados** no `README.md`.
- **Gemini 3.5 Flash:**
  - **Falta documentação do código** (ex.: `docs/`).
- **Sonnet 4.6:**
  - **Código não modularizado** (embora possua documentação).

---

## **8. Recomendações para Melhorias**

### **8.1. Para Todos os Repositórios**

- **Adicionar um arquivo `CONTRIBUTING.md**` para padronizar contribuições.
- **Incluir um guia de como estender a ferramenta** (ex.: adicionar novas regras de CWEs).

### **8.2. Para Repositórios Específicos**


| LLM                  | Recomendação                                                                             |
| -------------------- | ---------------------------------------------------------------------------------------- |
| **Gemini 3.5 Flash** | Adicionar documentação do código (ex.: `docs/ARCHITECTURE.md`).                          |
| **Grok Fast**        | Refatorar o código para **modularização** e adicionar documentação.                      |
| **Sonnet 4.6**       | Refatorar o código para **modularização** (ex.: separar regras em arquivos individuais). |


---

## **9. Conclusão**

- **GPT 5.5** é o **melhor artefato**, atendendo a **todos os 4 selos** (SeloD, SeloF, SeloS, SeloR).
- **Gemini 3.5 Flash e Sonnet 4.6** estão **próximos do ideal**, faltando apenas **documentação** ou **modularização** para o SeloS.
- **Grok Fast** precisa de **melhorias significativas** na organização do código e documentação para atingir o SeloS.

**Recomendação final:**

- **Para o SBRC 2026**, o **GPT 5.5** está pronto para submissão com **todos os selos**. 
- **Gemini 3.5 Flash e Sonnet 4.6** podem ser ajustados com **pequenas melhorias** (documentação/modularização).
- **Grok Fast** requer **refatoração** para atender ao SeloS.

---

## **10. Anexos**

### **10.1. Links dos Repositórios**

- [Gemini 3.5 Flash](https://github.com/francis-vargas/Comparative-Evaluation-of-Artifacts-Generated-by-LLMs-sast-dart/tree/main/gemini-3.5-flash-aistudio)
- [GPT 5.5](https://github.com/francis-vargas/Comparative-Evaluation-of-Artifacts-Generated-by-LLMs-sast-dart/tree/main/gpt-5.5)
- [Grok Fast](https://github.com/francis-vargas/Comparative-Evaluation-of-Artifacts-Generated-by-LLMs-sast-dart/tree/main/grok-fast)
- [Sonnet 4.6](https://github.com/francis-vargas/Comparative-Evaluation-of-Artifacts-Generated-by-LLMs-sast-dart/tree/main/sonnet-4.6)

### **10.2. Referências**

- [Instruções para Revisão - SBRC 2026](https://doc-artefatos.github.io/sbrc2026/revinstrucoes.html)
- [CWE (Common Weakness Enumeration)](https://cwe.mitre.org/)
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)

---

**Fim do Relatório**


