# adversarial-ai-cti

A STIX 2.1 data model and reference implementation for representing adversarial AI
activity — prompt injection and jailbreaks — as structured threat intelligence that
any OpenCTI / STIX 2.1 platform can ingest.

> **Status:** early work in progress. Layout and interfaces will change.

## What this is

Most threat intelligence tooling has no first-class way to represent a prompt attack.
This project provides a small, generic library that converts adversarial-prompt
records into standard STIX 2.1 objects — observables, indicators, and technique
mappings — so they can be stored, attributed, and shared like any other indicator.

It is platform-agnostic. The reference integration targets OpenCTI.

## Non-goals

- Not a runtime detection engine — detection logic belongs in tools built for it.
- Not a new sharing format — it uses STIX 2.1 and existing community extensions.
- Ships code, not a corpus. Bring your own sources.

## Prior art and attribution

This builds on public work by others and does not claim their contributions:

- **[Thomas Roccia](https://github.com/fr0gger)** — the *Indicator of Prompt
  Compromise* concept and the [NOVA](https://github.com/Nova-Hunting/nova-framework)
  prompt pattern-matching framework.
- **[dogesec / David Greenwood](https://github.com/muchdogesec)** — modelling prompts
  in STIX (the `ai-prompt` observable) and the `stix2extensions` project.
- **[Push Security](https://pushsecurity.com/blog/the-pyramid-of-pain-in-the-ai-era)**
  — the Pyramid of Pain in the AI era.

## License

[Apache-2.0](LICENSE).
