"""TLP marking selection by source trust level."""

from __future__ import annotations

import stix2

# TLP:AMBER+STRICT has no built-in constant in stix2; define it once.
_AMBER_STRICT = stix2.MarkingDefinition(
    id="marking-definition--a1b2c3d4-0000-4000-8000-000000000001",
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
    "clear": stix2.TLP_WHITE,
    "green": stix2.TLP_GREEN,
    "amber": stix2.TLP_AMBER,
    "amber+strict": _AMBER_STRICT,
    "red": stix2.TLP_RED,
}


def tlp_marking(level: str | None) -> stix2.MarkingDefinition:
    """Return the STIX TLP marking for a configured trust level (defaults to CLEAR)."""
    return _MARKINGS.get((level or "clear").lower(), stix2.TLP_WHITE)
