# Contributing

Thanks for your interest. This repo is a STIX 2.1 **specification** (`docs/SPEC.md`) plus
a reference implementation. Changes to one should keep the other honest.

## Development setup

```bash
python -m pip install -e ".[dev]"   # editable install + pytest, ruff, mypy
```

## Before opening a pull request

```bash
ruff check src tests
pytest -q
```

Both must pass. CI runs the same on Python 3.10–3.12.

The connector under `connectors/opencti-prompt-correlation/` has its own pure-logic tests
that need `promptprint` on the path:

```bash
PYTHONPATH="../promptprint/src:connectors/opencti-prompt-correlation/src" \
  python connectors/opencti-prompt-correlation/tests/test_enrichment.py
```

## Guidelines

- **Spec and code move together.** If you change emitted STIX (a label convention, a
  marking, a property), update `docs/SPEC.md` and `CHANGELOG.md` in the same change. The
  spec is the source of truth; the code must conform to it.
- **Confident mapping only.** ATLAS/OWASP mapping must not guess. New keyword rules must
  come with tests, and any short/abbreviation-like keyword must be whole-word anchored
  and tested against the unrelated words it could otherwise sweep in (see
  `tests/test_mappings.py`).
- **Don't pollute shared data.** ATLAS attack-pattern reference objects carry no
  attribution, labels, or markings (SPEC §10.2). Traceability flows through the
  `indicates` relationship only.
- **Markings fail closed.** Never default an unknown trust level to a permissive marking.
- **Validate STIX.** New object shapes should be checked against a STIX 2.1 validator, not
  only unit-tested.
