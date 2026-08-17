"""Tests for confident-only ATLAS/OWASP mapping.

Runnable with pytest or directly (`python tests/test_mappings.py`).
"""

from adversarial_ai_cti.mappings import ATLAS_VERSION, map_to_atlas, map_to_owasp


def test_jailbreak_maps_to_atlas_jailbreak():
    ids = [a for a, _, _ in map_to_atlas(threats=["Jailbreak"])]
    assert "AML.T0054" in ids


def test_system_prompt_maps_to_leakage_not_only_injection():
    atlas = [a for a, _, _ in map_to_atlas(threats=["system prompt leakage"])]
    owasp = [o for o, _, _ in map_to_owasp(threats=["system prompt leakage"])]
    assert "AML.T0056" in atlas
    assert "LLM07" in owasp


def test_word_boundary_prevents_midword_false_positive():
    # "dan" must not match inside "abundant"; unrelated token yields no ATLAS mapping.
    assert map_to_atlas(threats=["abundant resources"]) == []


# --- surgical prefix fix: unrelated PREFIX collisions must not map ----------- #


def test_prefix_collisions_do_not_map():
    # These begin with an abbreviation-like keyword (dan/rag/worm/persona) but are
    # unrelated words. None should map to any technique.
    for token in ("dangerous", "dangerous_content", "dance", "dandelion",
                  "rage", "rage bait", "ragtime", "wormhole",
                  "personal", "personalize", "personal_data"):
        assert map_to_atlas(tags=[token]) == [], token
        assert map_to_owasp(tags=[token]) == [], token


# --- morphological variants of real keywords MUST still map ------------------ #


def test_morphological_variants_still_map():
    assert "LLM06" in [o for o, _, _ in map_to_owasp(tags=["agentic"])]
    assert "LLM06" in [o for o, _, _ in map_to_owasp(tags=["tools"])]
    assert "AML.T0051" in [a for a, _, _ in map_to_atlas(tags=["injections"])]
    assert "AML.T0068" in [a for a, _, _ in map_to_atlas(tags=["encoding schemes"])]


def test_exact_keyword_still_matches_as_whole_word():
    # the real signals themselves must still map
    assert "AML.T0054" in [a for a, _, _ in map_to_atlas(tags=["dan"])]
    assert "AML.T0054" in [a for a, _, _ in map_to_atlas(tags=["persona based attack"])]
    assert "LLM08" in [o for o, _, _ in map_to_owasp(tags=["rag"])]
    assert "AML.T0061" in [a for a, _, _ in map_to_atlas(tags=["worm"])]


# --- provenance -------------------------------------------------------------- #


def test_keyword_match_reports_keyword_method():
    method = {a: m for a, _, m in map_to_atlas(threats=["jailbreak"])}
    assert method["AML.T0054"] == "keyword"


def test_category_fallback_reports_fallback_method():
    # No keyword matches "weird stuff", so the category fallback applies.
    result = map_to_atlas(threats=["weird stuff"], categories=["manipulation"])
    assert result == [("AML.T0051", "LLM Prompt Injection", "category-fallback")]


def test_abuse_category_is_deliberately_unmapped_in_atlas():
    assert map_to_atlas(categories=["abuse"]) == []


def test_owasp_edition_pinned():
    from adversarial_ai_cti.mappings import OWASP_EDITION

    assert OWASP_EDITION == "2025"


def test_atlas_version_present():
    assert ATLAS_VERSION


def _run_all() -> None:
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)} passed")


if __name__ == "__main__":
    _run_all()
