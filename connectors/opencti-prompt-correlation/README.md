# OpenCTI connector: prompt correlation (promptprint)

An OpenCTI **internal-enrichment** connector that makes reworded prompt attacks
correlate. When an `ai-prompt` observable is enriched, it:

1. computes a [`promptprint`](https://github.com/ashwinvis98/promptprint)
   similarity digest and stores it on the observable as the custom property
   `x_promptprint_digest` (a first-class, queryable attribute — see SPEC.md §7.5);
2. reads the digests already stored on other `ai-prompt` observables;
3. creates a `related-to` relationship to each one whose digest is similar enough
   (>= a configurable threshold), with the similarity score in the description.

The effect: a feed of near-duplicate jailbreaks stops looking like N unrelated items
and starts forming clusters you can pivot through.

## How it works

```
ai-prompt observable ──enrich──▶ compute digest ──▶ store as x_promptprint_digest
                                        │
                                        ▼
                         compare against other prompts' digests
                                        │
                                        ▼
                       related-to relationship for each match (>= threshold)
```

The decision logic (digest, extract, match) lives in `src/enrichment.py` and is unit
tested (`tests/test_enrichment.py`) with no OpenCTI dependency. `src/main.py` wires it
into OpenCTI via `pycti`.

## Requirements and caveats

- **A running OpenCTI** is required to execute the connector end to end; only the pure
  logic is unit tested here.
- **Pin `pycti` to your OpenCTI platform version.** The pycti API surface changes
  between releases; the unpinned `requirements.txt` is a starting point.
- The `ai-prompt` observable type must be recognised by your instance (via the
  `stix2extensions` `ai-prompt` SCO / the `adversarial-ai-cti` producer).
- Comparing against up to `max_candidates` prompts per enrichment is `O(candidates)`;
  for large instances, lower `max_candidates` or pre-filter.

## Configuration

Configure with environment variables or `config.yml` (copy `config.yml.sample`). Key
settings:

| Setting | Env | Default | Meaning |
|---|---|---|---|
| threshold | `PROMPT_CORRELATION_THRESHOLD` | `0.7` | minimum digest similarity to link |
| max candidates | `PROMPT_CORRELATION_MAX_CANDIDATES` | `500` | prompts to compare against per enrichment |
| max edges | `PROMPT_CORRELATION_MAX_EDGES` | `25` | max `related-to` links created per enrichment |

Plus the standard OpenCTI connector variables (`OPENCTI_URL`, `OPENCTI_TOKEN`,
`CONNECTOR_ID`, `CONNECTOR_SCOPE=AI-Prompt`, etc.).

## Design decisions

These are deliberate choices, not defaults to accept blindly. Tune them for your feed.

- **Threshold (`0.7`).** The digest similarity above which two prompts are linked. On
  `ppl1` (lexical MinHash) 0.7 corresponds to strong shared phrasing; lower it toward
  0.5 to catch looser rewording at the cost of false links. Calibrate against your own
  corpus — see [`promptprint` RESULTS.md](https://github.com/ashwinvis98/promptprint/blob/main/RESULTS.md).
- **Per-object edge cap (`max_edges = 25`).** Without a cap, enriching one member of a
  family of *N* near-identical prompts creates *N-1* edges, and doing so for every
  member is O(N²) relationships — a hairball that helps no one. The cap keeps only the
  highest-scoring links per enrichment. Raise it if you would rather have complete edges
  than a bounded graph.
- **Pairwise links, not a cluster representative.** This connector draws pairwise
  `related-to` edges between similar observables. It does **not** elect one
  "representative" prompt per family and link the rest to it. Pairwise is simpler and
  survives incremental ingest (no representative to re-elect as new variants arrive), at
  the cost of a denser graph — which is what the edge cap bounds. A representative /
  clustering model is a reasonable alternative if you want one node per family.
- **Confidence carries the score.** Each relationship's `confidence` is the digest
  similarity × 100, so a 0.72 near-match and a 0.99 duplicate are distinguishable in the
  UI and in filters.
- **Rollback.** The digest lives in the `x_promptprint_digest` property and every
  relationship description is prefixed `promptprint similarity`. To undo the connector's
  effect, clear `x_promptprint_digest` on the observables and delete the `related-to`
  relationships carrying that description prefix. Nothing else is mutated.

- **Candidate selection & recall.** Each enrichment compares against the
  `max_candidates` most-recently-created prompts (`orderBy=created_at`, descending). A
  near-duplicate older than that window is not found: recall is bounded to the window.
  This is a deliberate reference-connector simplification. For unbounded recall, LSH
  banding (split the MinHash signature into *b* bands of *r* rows, index band hashes,
  retrieve only colliding candidates) is the standard approach and is **future work**;
  it trades a characterised recall/precision curve for sublinear retrieval. Throughput:
  the comparison itself is O(candidates) digest comparisons per enrichment, each a
  slot-wise integer compare over `num_perm` slots — on the order of a few thousand
  prompts/second in pure Python for the default `max_candidates=500`; benchmark on your
  own hardware before relying on the figure.

Comparability caveat: the stored digest is only meaningful to compare against other
digests produced with the **same scheme and parameters** (and, for the semantic
`pps1c` variant, the same embedding model and reference mean). Mixed-scheme candidates
are skipped rather than mis-scored.

## Run

```bash
docker build -t opencti-prompt-correlation .
docker run --rm --env-file .env opencti-prompt-correlation
```

## Tests

```bash
# with promptprint and this connector's src on the path
PYTHONPATH="../promptprint/src:connectors/opencti-prompt-correlation/src" \
  python connectors/opencti-prompt-correlation/tests/test_enrichment.py
```

## License

[Apache-2.0](../../LICENSE).
