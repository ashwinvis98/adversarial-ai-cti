# OpenCTI connector: prompt correlation (prompt-semhash)

An OpenCTI **internal-enrichment** connector that makes reworded prompt attacks
correlate. When an `ai-prompt` observable is enriched, it:

1. computes a [`prompt-semhash`](https://github.com/ashwinvis98/prompt-semhash)
   similarity digest and stores it on the observable as an external reference;
2. reads the digests already stored on other `ai-prompt` observables;
3. creates a `related-to` relationship to each one whose digest is similar enough
   (>= a configurable threshold), with the similarity score in the description.

The effect: a feed of near-duplicate jailbreaks stops looking like N unrelated items
and starts forming clusters you can pivot through.

## How it works

```
ai-prompt observable ──enrich──▶ compute digest ──▶ store as external reference
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
| max candidates | `PROMPT_CORRELATION_MAX_CANDIDATES` | `500` | prompts to compare against |

Plus the standard OpenCTI connector variables (`OPENCTI_URL`, `OPENCTI_TOKEN`,
`CONNECTOR_ID`, `CONNECTOR_SCOPE=AI-Prompt`, etc.).

## Run

```bash
docker build -t opencti-prompt-correlation .
docker run --rm --env-file .env opencti-prompt-correlation
```

## Tests

```bash
# from the repo root, with prompt-semhash and this connector's src on the path
PYTHONPATH="../prompt-semhash/src:connectors/opencti-prompt-correlation/src" \
  python connectors/opencti-prompt-correlation/tests/test_enrichment.py
```

## License

[Apache-2.0](../../LICENSE).
