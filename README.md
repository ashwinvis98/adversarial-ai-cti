# adversarial-ai-cti

A STIX 2.1 data model and reference implementation for representing adversarial AI
activity — prompt injection and jailbreaks — as structured threat intelligence that
any OpenCTI / STIX 2.1 platform can ingest.

> **Status:** early work in progress. Layout and interfaces will change.

## What this is

Most threat intelligence tooling has no first-class way to represent a prompt attack.
This project converts source-agnostic prompt-attack records into standard STIX 2.1
objects — an `ai-prompt` observable (the fact), indicators (the analysis), MITRE
ATLAS technique mappings, OWASP-LLM labels, and TLP markings — so prompt attacks can
be stored, attributed, scored, and shared like any other indicator.

It is platform-agnostic. The reference integration targets OpenCTI.

## Quick start

```bash
pip install -e .

# build an example bundle from one record
python examples/prompt_to_stix.py

# run the tests
PYTHONPATH=src python tests/test_mappings.py
PYTHONPATH=src python tests/test_engine.py
```

```python
from adversarial_ai_cti import StixEngine, EngineConfig, PromptAttackRecord

engine = StixEngine(EngineConfig(source_name="My Source", tlp_level="green"))
bundle = engine.build_bundle([record])   # -> a valid STIX 2.1 Bundle
```

## The design decision worth arguing: two indicators per prompt

Prior art models each prompt with a *single* indicator — either a STIX pattern (exact
match) or a NOVA pattern (behavioural). This project emits **both** over the same
observable:

| | STIX-pattern indicator | NOVA-pattern indicator |
|---|---|---|
| Matches | the exact prompt string | behaviour (keywords + semantics + LLM judgement) |
| Strength | portable, engine-agnostic, exact correlation key | durable against paraphrase and noise |
| Weakness | brittle — trivial rewrites evade it | needs a NOVA engine to evaluate |

Ship only the STIX pattern and detection is brittle; ship only NOVA and you lose a
portable exact-match key. The cost is two indicators per prompt and keeping their
metadata in sync. Full rationale in [`docs/SPEC.md`](docs/SPEC.md) §8.

## Correlation

Exact-string observables don't correlate reworded prompts. That gap is handled by a
separate similarity-digest package,
[`prompt-semhash`](https://github.com/ashwinvis98/prompt-semhash); design note in
[`docs/correlation-digest.md`](docs/correlation-digest.md).

## Repository layout

```
adversarial-ai-cti/
├── docs/
│   ├── SPEC.md               # the STIX 2.1 data model (the contribution)
│   └── correlation-digest.md # design note for the semantic-correlation digest
├── src/adversarial_ai_cti/   # reference implementation
├── examples/                 # runnable example (record -> bundle)
└── tests/                    # mapping and engine tests
```

## Non-goals

- Not a runtime detection engine — detection logic belongs in tools built for it (NOVA).
- Not a new sharing format — it uses STIX 2.1 and existing community extensions.
- Ships code, not a corpus. Bring your own sources.

## Limitations (honest ones)

- Automated ATLAS/OWASP mapping is word-boundary keyword matching; it leaves ambiguous
  input unmapped rather than guessing.
- The correlation digest baseline is lexical, not semantic (see the design note).

## Prior art and attribution

Builds on public work and does not claim others' contributions:

- **[Thomas Roccia](https://github.com/fr0gger)** — the *Indicator of Prompt
  Compromise* concept and the [NOVA](https://github.com/Nova-Hunting/nova-framework)
  framework.
- **[dogesec / David Greenwood](https://github.com/muchdogesec)** — modelling prompts
  in STIX (the `ai-prompt` observable) and `stix2extensions`.
- **[Push Security](https://pushsecurity.com/blog/the-pyramid-of-pain-in-the-ai-era)**
  — the Pyramid of Pain in the AI era.

## License

[Apache-2.0](LICENSE).
