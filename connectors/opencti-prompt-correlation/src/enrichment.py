"""Pure enrichment logic for the prompt-correlation connector.

This module is deliberately free of any OpenCTI / pycti dependency so it can be unit
tested on its own. It does three things:

- turn a prompt into a portable similarity digest, packaged as an external reference
  to store on the observable (:func:`digest_external_reference`);
- read that digest back off an observable's external references
  (:func:`extract_digest`);
- given a new prompt and a set of candidate ``(id, digest)`` pairs, decide which are
  similar enough to link (:func:`find_similar`).

The connector (``main.py``) wires these into OpenCTI: attach the digest on ingest,
then create ``related-to`` relationships to prompts whose digests are close.
"""

from __future__ import annotations

from prompt_semhash import compare, digest

SOURCE_NAME = "prompt-semhash"


def digest_external_reference(value: str) -> dict:
    """Return an external-reference dict carrying the prompt's similarity digest."""
    return {
        "source_name": SOURCE_NAME,
        "external_id": digest(value),
        "description": "prompt-semhash lexical similarity digest (psh1)",
    }


def extract_digest(external_references) -> str | None:
    """Return the stored digest from an observable's external references, or None."""
    for ref in external_references or []:
        if ref.get("source_name") == SOURCE_NAME:
            return ref.get("external_id")
    return None


def find_similar(
    target_value: str,
    candidates,
    threshold: float = 0.7,
) -> list[tuple[str, float]]:
    """Return ``(candidate_id, score)`` for candidates whose digest is >= *threshold*.

    ``candidates`` is an iterable of ``(id, digest_or_none)``. Candidates without a
    stored digest, or whose digest uses a different scheme, are skipped. Results are
    sorted by descending score.
    """
    target_digest = digest(target_value)
    matches: list[tuple[str, float]] = []
    for candidate_id, candidate_digest in candidates:
        if not candidate_digest:
            continue
        try:
            score = compare(target_digest, candidate_digest)
        except ValueError:
            # different scheme / malformed digest -> not comparable
            continue
        if score >= threshold:
            matches.append((candidate_id, round(score, 4)))
    matches.sort(key=lambda pair: pair[1], reverse=True)
    return matches
