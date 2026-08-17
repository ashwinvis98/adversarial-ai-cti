"""OpenCTI internal-enrichment connector: correlate similar prompt observables.

On each `ai-prompt` observable it enriches, the connector:

1. computes the promptprint similarity digest and stores it on the observable as the
   custom property ``x_promptprint_digest`` (a first-class, queryable attribute);
2. reads the digests already stored on other `ai-prompt` observables;
3. creates a `related-to` relationship to each one whose digest is similar enough
   (>= a configurable threshold).

Candidate selection is by **recency**: up to ``max_candidates`` most-recently-created
prompts. Near-duplicates outside that window are not found — a bounded, documented
recall limit (see the README "Design decisions").

The pure decision logic lives in ``enrichment.py`` and is unit tested. This file wires
it into OpenCTI via pycti and therefore needs a running OpenCTI to execute. The exact
pycti method surface can vary between OpenCTI releases; pin ``pycti`` to your platform
version (see the README).
"""

from __future__ import annotations

from pathlib import Path

import yaml
from enrichment import DIGEST_PROPERTY, compute_digest, extract_digest, find_similar
from pycti import OpenCTIConnectorHelper, get_config_variable


class PromptCorrelationConnector:
    def __init__(self) -> None:
        config_path = Path(__file__).parent.parent / "config.yml"
        config = (
            yaml.safe_load(config_path.open(encoding="utf-8"))
            if config_path.is_file()
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.threshold = float(
            get_config_variable(
                "PROMPT_CORRELATION_THRESHOLD",
                ["prompt_correlation", "threshold"],
                config,
                default=0.7,
            )
        )
        self.max_candidates = int(
            get_config_variable(
                "PROMPT_CORRELATION_MAX_CANDIDATES",
                ["prompt_correlation", "max_candidates"],
                config,
                default=500,
            )
        )
        self.max_edges = int(
            get_config_variable(
                "PROMPT_CORRELATION_MAX_EDGES",
                ["prompt_correlation", "max_edges"],
                config,
                default=25,
            )
        )

    def _candidate_digests(self, exclude_id: str):
        """Yield (id, stored_digest) for other ai-prompt observables.

        Selection is explicit and documented: the ``max_candidates`` most-recently
        created prompts (``orderBy=created_at`` descending). Recall is therefore bounded
        to that window — a near-duplicate older than the window is not found. This is a
        deliberate reference-connector simplification; LSH banding for unbounded recall
        is noted as future work in the README.
        """
        others = self.helper.api.stix_cyber_observable.list(
            types=["AI-Prompt"],
            first=self.max_candidates,
            orderBy="created_at",
            orderMode="desc",
        )
        for obs in others or []:
            if obs["id"] == exclude_id:
                continue
            yield obs["id"], extract_digest(obs)

    def _process_message(self, data: dict) -> str:
        observable = self.helper.api.stix_cyber_observable.read(id=data["entity_id"])
        if observable is None:
            return "skip: observable not found"
        if observable.get("entity_type") != "AI-Prompt":
            return f"skip: not an ai-prompt ({observable.get('entity_type')})"

        value = observable.get("observable_value") or observable.get("value")
        if not value:
            return "skip: empty prompt value"

        # 1. store the digest as a first-class custom property (idempotent: skip if set)
        if extract_digest(observable) is None:
            self.helper.api.stix_cyber_observable.update_field(
                id=observable["id"],
                input={"key": DIGEST_PROPERTY, "value": compute_digest(value)},
            )

        # 2. compare against digests stored on other prompts
        matches = find_similar(
            value, self._candidate_digests(observable["id"]), self.threshold, self.max_edges
        )

        # 3. link the similar ones. Confidence carries the digest similarity (0-100) so an
        #    analyst can tell a 0.72 near-match from a 0.99 duplicate. Every relationship
        #    description is prefixed "promptprint similarity" for rollback (see README).
        for candidate_id, score in matches:
            self.helper.api.stix_core_relationship.create(
                fromId=observable["id"],
                toId=candidate_id,
                relationship_type="related-to",
                description=f"promptprint similarity {score:.2f}",
                confidence=int(score * 100),
            )

        return f"stored digest; created {len(matches)} similarity relationship(s)"

    def start(self) -> None:
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    PromptCorrelationConnector().start()
