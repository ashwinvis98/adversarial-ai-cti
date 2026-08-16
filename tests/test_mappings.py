"""Tests for confident-only ATLAS/OWASP mapping.

Runnable with pytest or directly (`python tests/test_mappings.py`).
"""

from adversarial_ai_cti.mappings import map_to_atlas, map_to_owasp


def test_jailbreak_maps_to_atlas_jailbreak():
    ids = [a for a, _ in map_to_atlas(threats=["Jailbreak"])]
    assert "AML.T0054" in ids


def test_system_prompt_maps_to_leakage_not_only_injection():
    atlas = [a for a, _ in map_to_atlas(threats=["system prompt leakage"])]
    owasp = [o for o, _ in map_to_owasp(threats=["system prompt leakage"])]
    assert "AML.T0056" in atlas
    assert "LLM07" in owasp


def test_word_boundary_prevents_midword_false_positive():
    # "dan" must not match inside "abundant"; unrelated token yields no ATLAS mapping.
    assert map_to_atlas(threats=["abundant resources"]) == []


def test_category_fallback_only_when_no_keyword():
    # No keyword matches "weird stuff", so the category fallback applies.
    ids = [a for a, _ in map_to_atlas(threats=["weird stuff"], categories=["manipulation"])]
    assert ids == ["AML.T0051"]


def test_abuse_category_is_deliberately_unmapped_in_atlas():
    assert map_to_atlas(categories=["abuse"]) == []


def test_owasp_edition_pinned():
    from adversarial_ai_cti.mappings import OWASP_EDITION

    assert OWASP_EDITION == "2025"


def _run_all() -> None:
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")


if __name__ == "__main__":
    _run_all()
