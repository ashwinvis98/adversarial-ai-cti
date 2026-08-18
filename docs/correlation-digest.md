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

## Status

- The digest is implemented as a separate package,
  [`promptlsh`](https://github.com/ashwinvis98/promptlsh), so it stays
  useful outside this project.
- The **default is lexical** (`plm1`, MinHash over word-shingles). It catches
  copy-paste-and-tweak rewording, not full semantic paraphrase, and is dependency-free.
- A **semantic variant** (`pls1`/`pls1c`, an embedding-derived SimHash digest behind the
  same compare interface) is implemented and evaluated on public data. It recovers the
  majority of heavily-reworded attacks — better than lexical — but a compact digest
  trails the raw-embedding ceiling by 11–21 points of recall@1. See
  [`promptlsh` RESULTS](https://github.com/ashwinvis98/promptlsh/blob/main/RESULTS.md).
- Both are **deterministic** (fixed hash + seed; the semantic variant also fixes the
  embedding model and, for `pls1c`, a shared reference mean), which is what lets
  independent parties compare digests without a shared service.
- The semantic digest **carries its comparability identity inline** —
  `pls1:<model_id>:<n_bits>:<hex>` and `pls1c:<model_id>:<ref_id>:<n_bits>:<hex>` — and
  `compare()` raises on a mismatched model or reference mean, so comparability is enforced
  by the digest format rather than relying on out-of-band agreement.

## How it would attach to STIX

The digest is carried as a property/label on the `ai-prompt` observable. A consumer
(e.g. an OpenCTI enrichment connector) computes the digest on ingest and creates
similarity relationships between observables whose digests are close. Defining the
digest as a stable, serialisable property — rather than an ad-hoc offline script — is
what makes it a shareable correlation mechanism rather than a one-off clustering job.

## What the evaluation now shows

The evaluation in [`promptlsh` RESULTS](https://github.com/ashwinvis98/promptlsh/blob/main/RESULTS.md)
answers several of the original open questions:

- **Redundancy is real.** The lexical digest collapses >half of a public corpus
  (HackAPrompt) as exact duplicates, plus more as near-duplicates.
- **Cross-org correlation works on shared source material** — exchanging only digests
  finds ~2.9x the overlap that exact matching does (35.1% vs 12.2%). A genuinely
  cross-corpus test (not a split of one corpus) is still outstanding.
- **The semantic digest is deterministic** and recovers most reworded attacks, but the
  compact form costs recall versus the full embedding; comparability requires a shared
  model and reference mean.

## Still open

- Threshold selection is corpus-dependent; the connector defaults (0.7, see its README)
  are a starting point, not a calibrated value for every feed.
- Adversarial robustness: the scheme is public, so a motivated adversary can evade it
  (word reorder defeats the lexical digest). This is a triage aid, not a security control.
