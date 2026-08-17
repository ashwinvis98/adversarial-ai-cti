"""TLP marking selection by source trust level.

Notes on TLP versions (see docs/SPEC.md):

- STIX 2.1 predefines ``marking-definition`` objects (with fixed spec ids) only for
  **TLP 1.0** (WHITE/GREEN/AMBER/RED). There is no canonical STIX object id for the
  TLP 2.0 additions (CLEAR, AMBER+STRICT), and ``python-stix2`` ships no constant for
  them. For AMBER+STRICT we therefore derive a **deterministic UUIDv5** from a documented
  namespace and the label, so any implementer reproduces the exact same id and markings
  interoperate — rather than minting an opaque constant nobody else can arrive at. It uses
  ``definition_type="statement"`` because STIX requires ``definition_type="tlp"`` to be one
  of the four predefined TLP 1.0 markings and forbids other ``tlp`` markings.
- ``clear`` maps to ``TLP:WHITE`` (TLP 1.0) deliberately: some importers (e.g. MISP) reject
  bundles carrying a TLP:CLEAR marking they don't recognise, and WHITE is the interoperable
  equivalent today. Revisit when TLP:CLEAR is broadly accepted downstream.
"""

from __future__ import annotations

import uuid

import stix2

# Documented derivation: UUIDv5(namespace, label). Reproducible by anyone.
_TLP_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "https://github.com/ashwinvis98/adversarial-ai-cti/tlp"
)
_AMBER_STRICT_ID = f"marking-definition--{uuid.uuid5(_TLP_NAMESPACE, 'TLP:AMBER+STRICT')}"

_AMBER_STRICT = stix2.MarkingDefinition(
    id=_AMBER_STRICT_ID,
    definition_type="statement",
    definition={"statement": "TLP:AMBER+STRICT"},
    allow_custom=True,
    custom_properties={
        "x_opencti_definition_type": "TLP",
        "x_opencti_definition": "TLP:AMBER+STRICT",
    },
)

_MARKINGS = {
    "white": stix2.TLP_WHITE,
    "clear": stix2.TLP_WHITE,  # deliberate TLP 2.0 -> 1.0 compatibility mapping (see module docstring)
    "green": stix2.TLP_GREEN,
    "amber": stix2.TLP_AMBER,
    "amber+strict": _AMBER_STRICT,
    "red": stix2.TLP_RED,
}


def tlp_marking(level: str | None) -> stix2.MarkingDefinition:
    """Return the STIX TLP marking for a configured trust level.

    Fails **closed**: an unknown or misspelled level raises rather than silently
    defaulting to a permissive marking (a config typo must not downgrade sharing).
    """
    key = (level or "clear").strip().lower()
    try:
        return _MARKINGS[key]
    except KeyError:
        raise ValueError(
            f"unknown TLP level {level!r}; valid levels: {sorted(_MARKINGS)}"
        ) from None
