# Changelog

All notable changes to `adversarial-ai-cti` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - 2026-08-16

Review-driven correctness and interoperability fixes. Some changes alter the emitted
STIX (label values, the review label, the AMBER+STRICT marking id), so consumers that
pinned exact strings should re-ingest.

### Fixed
- **ATLAS/OWASP prefix false positives.** Keyword matching anchored only the *start* of
  a keyword, so short abbreviation-like keywords matched unrelated words as prefixes
  (`dangerous`→Jailbreak via `dan`, `wormhole`→Self-Replication via `worm`, `rage`→
  Embedding Weaknesses via `rag`, `personal`→Jailbreak via `persona`). Those keywords
  are now matched as whole words; morphological variants (`injections`, `tools`,
  `hallucination`) still match by design.
- **Marking fail-open.** `tlp_marking()` returned the most permissive marking for an
  unknown/misspelled level. It now fails closed (raises), so a config typo cannot
  silently downgrade sharing.

### Changed
- **Mapping provenance.** `map_to_atlas` / `map_to_owasp` now return
  `(id, name, method)` where `method` is `keyword` or `category-fallback`; the ATLAS
  `indicates` relationship records it as `x_promptprint_mapping_method`, so a technique
  distribution can separate inferred from fallback mappings.
- **Consistent label normalization.** All free-text label values are case-folded
  (`Jailbreak` and `jailbreak` no longer produce two labels); the review flag is
  namespaced `status.review-required`; the naming convention is documented in SPEC.md.
- **TLP:AMBER+STRICT id** is now a reproducible UUIDv5 derived from a documented
  namespace + label, instead of an invented constant. `TLP:CLEAR` still maps to
  `TLP:WHITE` as a deliberate, documented compatibility choice.
- **ATLAS versioning.** Added `ATLAS_VERSION` and a note to validate the technique table
  against the official ATLAS STIX bundle before publishing distributions.

### Added
- **`x_promptprint_digest` similarity-digest property** on the `ai-prompt` SCO
  (SPEC.md §7.5), and a reference OpenCTI enrichment connector that computes it and draws
  `related-to` edges. The connector now stores the digest as this first-class property
  (not an external reference) and documents its candidate-selection recall bound.
- `CHANGELOG.md`, `CONTRIBUTING.md`.

## [0.1.0] - 2026-08-15

First public release: a STIX 2.1 data model and reference implementation for
representing prompt-injection and jailbreak activity (the `ai-prompt` SCO, two-indicator
design, ATLAS/OWASP mapping, faceted labels, TLP conventions), with `docs/SPEC.md`.
