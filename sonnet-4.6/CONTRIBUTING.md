# Contribuindo com o dart_sast

Obrigado por considerar contribuir! Veja também `docs/ARCHITECTURE.md` para
entender a organização do projeto antes de começar.

## Ambiente de desenvolvimento

```bash
git clone https://github.com/example/dart_sast.git
cd dart_sast
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

## Adicionando uma nova regra

Veja a seção "Extensibilidade" em `docs/ARCHITECTURE.md`. Resumo:

1. Novo arquivo em `src/dart_sast/rules/`.
2. Uma classe decorada com `@register_rule`, herdando de `RegexRule`,
   `PubspecRule`, `ManifestRule` ou `Rule`.
3. Caso de teste positivo (no app de exemplo) e um caso negativo (na
   fixture "clean").
4. `pytest -q` deve passar sem alterar nenhum outro arquivo.

## Reportando falsos positivos/negativos

Abra uma issue com: trecho de código Dart mínimo que reproduz o problema,
o `rule_id` envolvido, e o comportamento esperado. Como as regras são
baseadas em expressões regulares e heurísticas de nomenclatura (não em um
parser de AST completo), algum nível de falso positivo/negativo é
esperado — issues específicas ajudam a calibrar os padrões sem
regredir a suíte de testes existente.

## Estilo de código

- Python 3.9+, sem dependências externas em tempo de execução.
- Cada regra deve ser independente e não deve importar de outras regras.
- Toda regra pública precisa de `rule_id`, `cwe`, `title`, `description`,
  `severity` e `recommendation` preenchidos — esses campos alimentam a
  saída em console, JSON e SARIF diretamente.

## Pull requests

- Rode `pytest -q` localmente antes de abrir o PR.
- Descreva a CWE/motivação da mudança e inclua o trecho de código de
  exemplo que passou a ser detectado (ou deixou de gerar falso positivo).
