"""Faceted label construction.

Naming convention (see docs/SPEC.md): every label is ``<facet>.<value>``, dot-separated.
Free-text values (category, threat, tag, model, severity, source) are **case-folded** so
``Jailbreak`` and ``jailbreak`` collapse to one label rather than proliferating. Standard
identifiers are left in their canonical form (OWASP ``LLM01``). The intent-category
controlled vocabulary emits ``iopc.<snake_case>`` labels, and the review flag is
namespaced ``status.review-required``. An optional constant umbrella label may be applied
to every object.
"""

from __future__ import annotations

REVIEW_REQUIRED_LABEL = "status.review-required"

# intent category -> four-category controlled vocabulary label
_IOPC_VOCAB = {
    "manipulation": "iopc.prompt_manipulation",
    "abuse": "iopc.abusing_legitimate_functions",
    "patterns": "iopc.suspicious_patterns",
    "outputs": "iopc.abnormal_outputs",
}


def _add(labels: list[str], value: str | None) -> None:
    if value and value not in labels:
        labels.append(value)


def _norm(value: str) -> str:
    """Case-fold and trim a free-text label value for consistent, non-duplicating labels."""
    return value.strip().casefold()


def iopc_vocab_labels(categories) -> list[str]:
    labels: list[str] = []
    for cat in categories or []:
        _add(labels, _IOPC_VOCAB.get(cat.strip().lower()))
    return labels


def build_labels(record, config, owasp_ids=None) -> list[str]:
    """Build the faceted label list for a record per the engine config."""
    labels: list[str] = []
    if config.enable_faceted_labels:
        for c in record.categories:
            _add(labels, f"category.{_norm(c)}")
        for t in record.threats:
            _add(labels, f"threat.{_norm(t)}")
        for tag in record.tags:
            _add(labels, f"tag.{_norm(tag)}")
        if record.severity:
            _add(labels, f"severity.{_norm(record.severity)}")
        for m in record.model_labels:
            _add(labels, f"model.{_norm(m)}")
        if record.source:
            _add(labels, f"source.{_norm(record.source)}")
        for oid in owasp_ids or []:
            # canonical OWASP identifier, left in its standard uppercase form
            _add(labels, f"owasp-llm.{oid}")
    else:
        for value in [*record.categories, *record.threats, *record.tags]:
            _add(labels, _norm(value))

    for label in iopc_vocab_labels(record.categories):
        _add(labels, label)

    if config.umbrella_label:
        _add(labels, config.umbrella_label)
    if not record.vetted:
        _add(labels, REVIEW_REQUIRED_LABEL)
    return labels
