# Correlation digest (design note)

## The problem

An `ai-prompt` observable is keyed on its exact text. Reword a prompt — even trivially
— and it becomes a different observable with no link to the original, so a feed of
reworded jailbreaks reads as many unrelated items instead of one campaign. Detection
(the NOVA-pattern indicator) handles paraphrase; **correlation** does not.

## The idea

Attach a *similarity digest* to the prompt observable: a compact value where similar
prompts produce similar digests, so a platform can cluster near-duplicates the way
`ssdeep`/`TLSH` cluster malware variants. Two digests are compared to estimate how
alike the underlying prompts are, without re-reading raw text — which also enables
correlation across parties who cannot share the prompt itself.

## Status and honesty

- The digest is implemented as a separate package,
  [`prompt-semhash`](https://github.com/ashwinvis98/prompt-semhash), so it stays
  useful outside this project.
- The **shipping baseline is lexical** (MinHash over word-shingles). It catches
  copy-paste-and-tweak rewording, not full semantic paraphrase.
- A **semantic variant** (embedding-derived, quantized digest behind the same compare
  interface) is the intended direction and an **open problem** — this note does not
  claim it is solved.

## How it would attach to STIX

The digest is carried as a property/label on the `ai-prompt` observable. A consumer
(e.g. an OpenCTI enrichment connector) computes the digest on ingest and creates
similarity relationships between observables whose digests are close. Defining the
digest as a stable, serialisable property — rather than an ad-hoc offline script — is
what makes it a shareable correlation mechanism rather than a one-off clustering job.

## Open questions

- What digest length / similarity threshold balances precision and recall on real
  corpora?
- Does clustering by digest actually recover known attack families, and where does the
  lexical baseline fail? (Needs evaluation on a public prompt-attack corpus.)
- Can a semantic digest be made deterministic and privacy-preserving enough for
  cross-organisation correlation?
