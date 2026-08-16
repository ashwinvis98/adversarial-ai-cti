"""Source-agnostic input model.

A collector converts its raw records into :class:`PromptAttackRecord` objects and
hands them to :class:`adversarial_ai_cti.engine.StixEngine`. The engine never sees a
raw source format, so a prompt attack from any source is represented identically.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class PromptAttackRecord:
    """A single adversarial-prompt record, normalised across sources."""

    # provenance
    source: str
    source_ref_url: str
    external_id: str | None = None

    # content
    prompt_text: str = ""
    title: str | None = None
    impact_description: str | None = None
    mitigation: str | None = None
    nova_rule: str | None = None

    # taxonomy
    categories: list[str] = field(default_factory=list)
    threats: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    severity: str | None = None

    # signals
    average_score: float | None = None
    total_ratings: int | None = None
    model_labels: list[str] = field(default_factory=list)

    # authorship / timing
    author: str | None = None
    created_at: datetime | None = None

    # governance
    vetted: bool = True


@dataclass
class EngineConfig:
    """Configuration for the STIX engine. All source-specific values are here."""

    source_name: str = "Example Source"
    source_identity_class: str = "organization"
    source_url: str = "https://example.invalid"
    source_description: str = "Adversarial prompt source."

    # marking level: clear | green | amber | amber+strict | red
    tlp_level: str = "clear"

    # enrichment toggles
    enable_atlas_mapping: bool = True
    enable_owasp_mapping: bool = True
    enable_faceted_labels: bool = True

    # optional constant label applied to every object (deployment branding).
    # MUST NOT encode an organisation name in a shared/public bundle.
    umbrella_label: str | None = None

    # confidence damping: ratings needed before the rating signal is fully trusted
    confidence_saturation_k: int = 5
