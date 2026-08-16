"""Faceted label construction.

Faceted labels are namespaced ``facet.value`` so dimensions never collide and a
dashboard can select cleanly on any one of them. Independently, each mapped intent
category emits an ``iopc.<category>`` controlled-vocabulary label (the four-category
taxonomy), and an optional constant umbrella label can be applied to every object.
"""

from __future__ import annotations

REVIEW_REQUIRED_LABEL = "review-required"

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
            _add(labels, f"category.{c}")
        for t in record.threats:
            _add(labels, f"threat.{t}")
        for tag in record.tags:
            _add(labels, f"tag.{tag}")
        if record.severity:
            _add(labels, f"severity.{record.severity.lower()}")
        for m in record.model_labels:
            _add(labels, f"model.{m}")
        if record.source:
            _add(labels, f"source.{record.source.lower()}")
        for oid in owasp_ids or []:
            _add(labels, f"owasp-llm.{oid}")
    else:
        for value in [*record.categories, *record.threats, *record.tags]:
            _add(labels, value)

    for label in iopc_vocab_labels(record.categories):
        _add(labels, label)

    if getattr(config, "umbrella_label", None):
        _add(labels, config.umbrella_label)
    if not record.vetted:
        _add(labels, REVIEW_REQUIRED_LABEL)
    return labels
