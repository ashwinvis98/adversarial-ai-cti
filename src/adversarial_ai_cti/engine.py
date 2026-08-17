"""The STIX engine: :class:`PromptAttackRecord` -> STIX 2.1 objects.

For each record the engine emits:

- one ``ai-prompt`` observable (the fact),
- a STIX-pattern Indicator and, when a NOVA rule exists, a NOVA-pattern Indicator
  (the two-indicator design — see docs/SPEC.md §8),
- ``based-on`` relationships (Indicator -> observable),
- minimal MITRE ATLAS attack-pattern reference objects and ``indicates`` relationships,
- source and author Identity objects.

IDs are deterministic (UUIDv5) so re-ingesting the same input is idempotent. Shared
ATLAS reference objects carry no attribution, labels, or markings — traceability to a
producer flows only through the ``indicates`` relationship.
"""

from __future__ import annotations

import uuid

import stix2
from stix2.properties import StringProperty

from . import labels as labels_mod
from .mappings import map_to_atlas, map_to_owasp
from .markings import tlp_marking
from .model import EngineConfig, PromptAttackRecord
from .scoring import calculate_confidence, calculate_score

# The ai-prompt SCO (dogesec stix2extensions). Registering it makes stix2 aware of the
# type; ``value`` is the id-contributing property, giving a deterministic UUIDv5 id.
_AI_PROMPT_EXTENSION = "extension-definition--3557a8d5-4e04-5f87-a7af-d48a1384d3ca"


@stix2.CustomObservable(
    "ai-prompt",
    [("value", StringProperty(required=True))],
    ["value"],
)
class AIPrompt:
    """Custom SCO representing an AI prompt (see docs/SPEC.md §7)."""


_NS = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")  # RFC 4122 URL namespace


def _det_id(prefix: str, *parts: str) -> str:
    return f"{prefix}--{uuid.uuid5(_NS, '|'.join(parts))}"


def _escape_pattern_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


class StixEngine:
    """Builds the STIX object graph for prompt-attack records."""

    def __init__(self, config: EngineConfig | None = None) -> None:
        self.config = config or EngineConfig()
        self.marking = tlp_marking(self.config.tlp_level)
        self.source_identity = stix2.Identity(
            id=_det_id("identity", self.config.source_name, self.config.source_identity_class),
            name=self.config.source_name,
            identity_class=self.config.source_identity_class,
            description=self.config.source_description,
            external_references=[
                stix2.ExternalReference(source_name=self.config.source_name, url=self.config.source_url)
            ],
        )
        self._identity_cache: dict[str, stix2.Identity] = {}
        self._atlas_cache: dict[str, stix2.AttackPattern] = {}

    # -- helpers ------------------------------------------------------------- #
    def _author(self, name: str) -> stix2.Identity:
        if name in self._identity_cache:
            return self._identity_cache[name]
        ident = stix2.Identity(
            id=_det_id("identity", name, "individual-or-org"),
            name=name,
            identity_class="individual" if self._looks_like_person(name) else "organization",
            created_by_ref=self.source_identity.id,
        )
        self._identity_cache[name] = ident
        return ident

    @staticmethod
    def _looks_like_person(name: str) -> bool:
        parts = name.split()
        return 2 <= len(parts) <= 3 and all(p[:1].isupper() and p.isalpha() for p in parts)

    def _atlas_pattern(self, atlas_id: str, technique_name: str) -> stix2.AttackPattern:
        if atlas_id in self._atlas_cache:
            return self._atlas_cache[atlas_id]
        # Minimal reference object: no created_by_ref, no labels, no marking. Merges
        # with the authoritative ATLAS dataset on x_mitre_id in the consumer.
        ap = stix2.AttackPattern(
            id=_det_id("attack-pattern", atlas_id),
            name=technique_name,
            external_references=[
                stix2.ExternalReference(
                    source_name="mitre-atlas",
                    external_id=atlas_id,
                    url=f"https://atlas.mitre.org/techniques/{atlas_id}",
                )
            ],
            allow_custom=True,
            custom_properties={"x_mitre_id": atlas_id},
        )
        self._atlas_cache[atlas_id] = ap
        return ap

    def _relationship(
        self,
        rel_type: str,
        src: str,
        tgt: str,
        author_id: str,
        mapping_method: str | None = None,
    ) -> stix2.Relationship:
        kwargs = dict(
            id=_det_id("relationship", rel_type, src, tgt),
            relationship_type=rel_type,
            source_ref=src,
            target_ref=tgt,
            created_by_ref=author_id,
            object_marking_refs=[self.marking.id],
            allow_custom=True,
        )
        # For ATLAS ``indicates`` edges, record how the technique was derived so a
        # downstream distribution can separate keyword-inferred from category-fallback.
        if mapping_method is not None:
            kwargs["description"] = f"ATLAS technique mapped via {mapping_method}"
            kwargs["custom_properties"] = {"x_promptprint_mapping_method": mapping_method}
        return stix2.Relationship(**kwargs)

    def _indicator(self, *, ind_id, name, pattern, pattern_type, record, labels, author_id, score, confidence):
        kwargs = dict(
            id=ind_id,
            name=name,
            description=record.impact_description or "",
            pattern=pattern,
            pattern_type=pattern_type,
            valid_from=record.created_at,
            labels=labels,
            created_by_ref=author_id,
            object_marking_refs=[self.marking.id],
            allow_custom=True,
            custom_properties={"x_opencti_score": score, "x_opencti_main_observable_type": "AI-Prompt"},
        )
        if confidence is not None:
            kwargs["confidence"] = confidence
        return stix2.Indicator(**kwargs)

    # -- main build ---------------------------------------------------------- #
    def build(self, record: PromptAttackRecord) -> list:
        """Build the STIX object graph for a single record."""
        cfg = self.config
        objects: list = [self.source_identity]

        author = self._author(record.author or "Unknown")
        objects.append(author)

        score = calculate_score(record.severity, record.average_score)
        confidence = calculate_confidence(record.average_score, record.total_ratings, cfg.confidence_saturation_k)

        owasp_ids = [oid for oid, _, _ in map_to_owasp(record.threats, record.categories, record.tags)] if cfg.enable_owasp_mapping else []
        labels = labels_mod.build_labels(record, cfg, owasp_ids)

        prompt_text = record.prompt_text or ""

        observable = AIPrompt(
            value=prompt_text,
            object_marking_refs=[self.marking.id],
            custom_properties={
                "x_opencti_score": score,
                "x_opencti_description": record.impact_description or record.title or "",
                "x_opencti_labels": labels,
                "created_by_ref": author.id,
            },
        )
        objects.append(observable)

        stix_pattern = f"[ai-prompt:value = '{_escape_pattern_value(prompt_text)}']"
        stix_indicator = self._indicator(
            ind_id=_det_id("indicator", stix_pattern),
            name=record.title or "Prompt attack",
            pattern=stix_pattern,
            pattern_type="stix",
            record=record,
            labels=labels,
            author_id=author.id,
            score=score,
            confidence=confidence,
        )
        objects.append(stix_indicator)
        objects.append(self._relationship("based-on", stix_indicator.id, observable.id, author.id))

        indicators = [stix_indicator]
        if record.nova_rule:
            nova_indicator = self._indicator(
                ind_id=_det_id("indicator", record.nova_rule),
                name=f"{record.title or 'Prompt attack'} (Nova Rule)",
                pattern=record.nova_rule,
                pattern_type="nova",
                record=record,
                labels=labels,
                author_id=author.id,
                score=score,
                confidence=confidence,
            )
            objects.append(nova_indicator)
            objects.append(self._relationship("based-on", nova_indicator.id, observable.id, author.id))
            indicators.append(nova_indicator)

        if cfg.enable_atlas_mapping:
            for atlas_id, technique_name, method in map_to_atlas(
                record.threats, record.categories, record.tags
            ):
                ap = self._atlas_pattern(atlas_id, technique_name)
                objects.append(ap)
                for ind in indicators:
                    objects.append(
                        self._relationship("indicates", ind.id, ap.id, author.id, mapping_method=method)
                    )

        return objects

    def build_bundle(self, records) -> stix2.Bundle:
        """Build a de-duplicated STIX bundle from an iterable of records."""
        seen: dict[str, object] = {}
        for record in records:
            for obj in self.build(record):
                seen[obj["id"]] = obj
        return stix2.Bundle(objects=list(seen.values()), allow_custom=True)
