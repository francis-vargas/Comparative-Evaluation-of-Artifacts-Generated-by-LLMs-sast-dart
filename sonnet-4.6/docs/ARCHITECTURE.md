# Arquitetura do dart_sast

Este documento descreve a organização do código-fonte e a justificativa das
principais decisões de design, para atender ao critério **SeloS
(Sustentabilidade)** do SBRC 2026: "código modularizado, organizado,
legível, com documentação descrevendo arquivos e funções".

## Visão geral

```
dart_sast/
├── src/dart_sast/
│   ├── cli.py                 # Ponto de entrada da linha de comando
│   ├── engine/                 # Núcleo agnóstico de regras
│   │   ├── finding.py           # Modelo de dado Finding/Severity
│   │   ├── rule.py              # Classes-base Rule/RegexRule/PubspecRule/ManifestRule
│   │   ├── registry.py          # Auto-registro e descoberta de regras
│   │   ├── scanner.py           # Percorre o filesystem e executa as regras
│   │   └── pubspec.py           # Parser mínimo de pubspec.yaml (sem PyYAML)
│   ├── rules/                  # Uma regra por arquivo (cweNNN_*.py)
│   └── reporters/              # console.py, json_reporter.py, sarif.py
├── tests/                       # pytest: positivo, negativo, integração, CLI
└── examples/vulnerable_app/     # App Flutter de exemplo, com vulnerabilidades
                                  # intencionais, usado nos testes e no README
```

## Por que esta separação?

### 1. `engine/` não conhece nenhuma CWE específica

O pacote `engine` define *como* uma regra funciona (uma classe com um
método `analyze_file`/`analyze_pubspec`/`analyze_manifest` que devolve
`Finding`s) mas não contém nenhuma lógica de detecção específica. Isso
significa que o núcleo do scanner pode ser testado, mantido e otimizado
independentemente das regras, e que novas regras nunca precisam alterar o
motor.

### 2. Cada regra é um arquivo independente e auto-registrado

`rules/cwe798_hardcoded_credentials.py` define uma única classe decorada
com `@register_rule`. `registry.load_all_rules()` importa todos os módulos
de `dart_sast.rules` via `pkgutil.iter_modules`, então o simples ato de
criar o arquivo já é suficiente para a regra ser descoberta — não existe
uma lista central "todas as regras" que precise ser editada. Isso reduz
conflitos de merge e facilita contribuições externas (ver
`CONTRIBUTING.md`).

Duas classes-base cobrem a esmagadora maioria dos casos:

- **`RegexRule`** — a regra apenas declara uma lista de expressões
  regulares (`patterns`); o motor cuida de iterar linha a linha, ignorar
  comentários simples, e gerar os `Finding`s. Usada por 17 das 20 regras.
- **`PubspecRule`** / **`ManifestRule`** — para as regras que não operam
  sobre `.dart` (dependências em `pubspec.yaml`, componentes exportados em
  `AndroidManifest.xml`), o motor entrega uma estrutura já parseada em vez
  de texto bruto.

Regras com necessidades mais complexas (como CWE-926, que precisa casar
tags XML que podem ocupar várias linhas) podem sobrescrever
`analyze_manifest`/`analyze_file` diretamente, como classes normais.

### 3. Por que regras baseadas em expressão regular, e não um parser de AST?

Implementar um parser completo de Dart (léxico + sintático + resolução de
tipos) está fora do escopo viável para esta ferramenta e traria uma
dependência pesada. Expressões regulares por linha, com heurísticas de
nomes de variáveis (`password`, `token`, `secret`, ...) e padrões de API
conhecidos (`Process.run`, `SharedPreferences.setString`, `http.get`, ...)
são a mesma abordagem usada por ferramentas de SAST amplamente adotadas
para linguagens sem parser dedicado disponível (ex.: regras customizadas
do Semgrep, Bandit em partes de seu conjunto de regras). A limitação
principal — não detectar padrões que atravessam muitas linhas de forma
não-trivial, ou renomear via alias — está documentada no README em
"Limitações conhecidas".

### 4. Saída plugável

`reporters/` segue o mesmo princípio de módulo único: `console.py`,
`json_reporter.py` e `sarif.py` cada um expõe uma única função
`render(...)`. Adicionar um novo formato (ex.: um exportador direto para a
API do DefectDojo) significa adicionar um novo arquivo em `reporters/` e
uma nova opção em `cli.py` — nenhum outro módulo precisa mudar.

### 5. `pubspec.py`: por que não usar PyYAML?

O enunciado pede para evitar dependências externas desnecessárias.
`pubspec.yaml` usa um subconjunto pequeno e previsível de YAML (mapas
aninhados por indentação, listas de bloco, e ocasionalmente um mapa de
fluxo de uma linha para dependências git/path). Um parser de ~150 linhas
específico para esse subconjunto é mais simples de auditar e não adiciona
uma dependência de terceiros só para ler alguns metadados de dependência.

## Extensibilidade: adicionando uma nova regra

1. Crie `src/dart_sast/rules/cweNNN_nome_curto.py`.
2. Herde de `RegexRule` (ou `PubspecRule`/`ManifestRule`/`Rule` conforme o
   alvo) e preencha `rule_id`, `cwe`, `title`, `description`, `severity`,
   `recommendation`, `references` e `patterns`.
3. Decore a classe com `@register_rule`.
4. Adicione um caso positivo em `examples/vulnerable_app/lib/main.dart` (ou
   `tests/fixtures/vulnerable/`) e um caso negativo em
   `tests/fixtures/clean/clean_app.dart`.
5. `pytest` já cobre automaticamente a nova regra: `test_rules_positive.py`
   itera sobre `get_all_rules()`, então basta rodar os testes.

Nenhuma alteração em `cli.py`, `scanner.py` ou `registry.py` é necessária.
