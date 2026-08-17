"""Pure enrichment logic for the prompt-correlation connector.

This module is deliberately free of any OpenCTI / pycti dependency so it can be unit
tested on its own. It does three things:

- compute the promptprint similarity digest for a prompt (:func:`compute_digest`);
- read the digest stored as a first-class property on an observable
  (:func:`extract_digest`);
- given a new prompt and a set of candidate ``(id, digest)`` pairs, decide which are
  similar enough to link (:func:`find_similar`).

The digest is stored as a custom SCO property, ``x_promptprint_digest`` (see
docs/SPEC.md §7.5), **not** as an external reference: it is a computed property of the
prompt, not a pointer to an external source. Storing it as a property is what makes it a
first-class, queryable, shareable attribute of the observable rather than a side-channel.
"""

from __future__ import annotations

from promptprint import compare, digest

#: Custom property name carrying the similarity digest on an ``ai-prompt`` observable.
DIGEST_PROPERTY = "x_promptprint_digest"


def compute_digest(value: str) -> str:
    """Return the promptprint lexical (``ppl1``) similarity digest for a prompt."""
    return digest(value)


def extract_digest(observable) -> str | None:
    """Return the stored digest from an observable, or ``None``.

    Accepts the observable as a mapping and looks for ``x_promptprint_digest`` at the top
    level and inside a nested custom-properties container, tolerating the shapes pycti
    returns for a custom SCO property.
    """
    if not observable:
        return None
    value = observable.get(DIGEST_PROPERTY)
    if value:
        return value
    for container_key in ("customProperties", "custom_properties", "extensions"):
        container = observable.get(container_key)
        if isinstance(container, dict) and container.get(DIGEST_PROPERTY):
            return container[DIGEST_PROPERTY]
    return None


def find_similar(
    target_value: str,
    candidates,
    threshold: float = 0.7,
    max_edges: int | None = None,
) -> list[tuple[str, float]]:
    """Return ``(candidate_id, score)`` for candidates whose digest is >= *threshold*.

    ``candidates`` is an iterable of ``(id, digest_or_none)``. Candidates without a
    stored digest, or whose digest uses a different scheme, are skipped. Results are
    sorted by descending score.

    ``max_edges`` caps how many links a single enrichment may create (the highest-
    scoring matches win). This bounds edge explosion on dense clusters: without a cap,
    enriching one member of a family of N near-identical prompts would create N-1 edges
    every time, giving O(N^2) relationships across the family. ``None`` means no cap.
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
    if max_edges is not None:
        matches = matches[:max_edges]
    return matches
