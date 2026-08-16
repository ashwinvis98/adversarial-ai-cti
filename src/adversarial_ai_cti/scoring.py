"""OpenCTI score (0-100) and STIX confidence (0-100) derivation.

- ``score`` is a severity base plus a small community-rating bonus.
- ``confidence`` is derived from the community rating and *damped* by rating volume,
  so a single 5-star vote does not read as high confidence. It is omitted entirely
  when there is no rating signal — thin data never presents as confident.
"""

from __future__ import annotations

SEVERITY_SCORE = {"critical": 85, "high": 65, "medium": 45, "low": 25}
_DEFAULT_BASE = 35


def calculate_score(severity: str | None, average_score: float | None) -> int:
    """0-100 score from severity level plus a small community-rating bonus."""
    base = SEVERITY_SCORE.get((severity or "").lower(), _DEFAULT_BASE)
    bonus = int((average_score or 0) * 3)  # average_score 0-5 -> bonus 0-15
    return min(100, base + bonus)


def calculate_confidence(
    average_score: float | None,
    total_ratings: int | None,
    saturation_k: int = 5,
) -> int | None:
    """0-100 confidence damped by rating volume, or ``None`` when no rating signal."""
    if not average_score or not total_ratings:
        return None
    fraction = min(1.0, total_ratings / max(1, saturation_k))
    return int(round((average_score / 5.0) * 100 * fraction))
