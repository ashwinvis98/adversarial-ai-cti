"""Confident-only mapping from prompt taxonomy to MITRE ATLAS and OWASP LLM (2025).

Records rarely carry technique IDs, so free-text ``threats``/``categories``/``tags``
are mapped onto techniques by keyword matching.

**Matching semantics.** Keywords match on a leading word boundary (``\\bkeyword``), so a
keyword also matches its morphological variants — this is deliberate and wanted
(``injection`` → ``injections``, ``tool`` → ``tools``/``toolkit``, ``hallucinat`` →
``hallucination``, ``self-replicat`` → ``self-replicating``). It does **not** match a
keyword mid-word (``dan`` in ``abundant``).

The hazard this leaves is *prefix* collisions, where a short keyword is also the prefix
of an **unrelated** word (``dan`` in ``dangerous``/``dance``, ``rag`` in ``rage``,
``worm`` in ``wormhole``, ``persona`` in ``personal``). Those specific abbreviation-like
keywords are therefore matched as **whole words** (``\\bkeyword\\b``) via
``_EXACT_KEYWORDS``. Every other keyword keeps prefix semantics.

Each mapping is returned with a ``method`` marker (``"keyword"`` or
``"category-fallback"``) so a downstream distribution can report how much of it was
inferred versus fell back on the coarse category. Unmatched input is left unmapped
rather than guessed.

ATLAS technique IDs/names are public MITRE data. The 14 techniques below are a
hand-maintained subset pinned to the MITRE ATLAS ``2026.07`` release (see
``ATLAS_VERSION``; github.com/mitre-atlas/atlas-data, tag ``v2026.07``). Validate these
IDs/names against that release's bundle before publishing any technique distribution.
"""

from __future__ import annotations

import re

# MITRE ATLAS release these technique IDs/names are pinned to
# (github.com/mitre-atlas/atlas-data, tag v2026.07).
ATLAS_VERSION = "2026.07"

# Short, abbreviation-like keywords whose *prefix* collides with unrelated vocabulary.
# Matched as whole words so they don't sweep in unrelated tokens. Every other keyword
# keeps leading-boundary (prefix) semantics so morphological variants still match.
_EXACT_KEYWORDS = frozenset({"dan", "rag", "worm", "persona"})


def _matches(keyword: str, token: str) -> bool:
    """True when *keyword* matches *token* on a leading word boundary.

    Keywords in ``_EXACT_KEYWORDS`` require a trailing boundary too (whole-word match).
    """
    pattern = r"\b" + re.escape(keyword)
    if keyword in _EXACT_KEYWORDS:
        pattern += r"\b"
    return re.search(pattern, token) is not None


def _tokens(threats, categories, tags) -> list[str]:
    return [
        t.strip().lower()
        for t in (threats or []) + (tags or []) + (categories or [])
        if t and t.strip()
    ]


# --- MITRE ATLAS ------------------------------------------------------------- #

ATLAS_TECHNIQUES: dict[str, str] = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0052": "Phishing",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0056": "Extract LLM System Prompt",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0061": "LLM Prompt Self-Replication",
    "AML.T0062": "Discover LLM Hallucinations",
    "AML.T0065": "LLM Prompt Crafting",
    "AML.T0067": "LLM Trusted Output Components Manipulation",
    "AML.T0068": "LLM Prompt Obfuscation",
    "AML.T0069": "Discover LLM System Information",
    "AML.T0077": "LLM Response Rendering",
    "AML.T0092": "Manipulate User LLM Chat History",
    "AML.T0094": "Delay Execution of LLM Instructions",
}

_ATLAS_RULES: list[tuple[str, str]] = [
    ("jailbreak", "AML.T0054"),
    ("persona", "AML.T0054"),
    ("roleplay", "AML.T0054"),
    ("do anything now", "AML.T0054"),
    ("dan", "AML.T0054"),
    ("godmode", "AML.T0054"),
    ("prompt injection", "AML.T0051"),
    ("injection", "AML.T0051"),
    ("prompt crafting", "AML.T0065"),
    ("prompt leak", "AML.T0056"),
    ("system prompt", "AML.T0056"),
    ("system instruction", "AML.T0056"),
    ("obfuscation", "AML.T0068"),
    ("encoding", "AML.T0068"),
    ("unicode", "AML.T0068"),
    ("base64", "AML.T0068"),
    ("leetspeak", "AML.T0068"),
    ("self-replicat", "AML.T0061"),
    ("worm", "AML.T0061"),
    ("delay execution", "AML.T0094"),
    ("conditional trigger", "AML.T0094"),
    ("data leak", "AML.T0057"),
    ("data leakage", "AML.T0057"),
    ("exfiltration", "AML.T0057"),
    ("data extraction", "AML.T0057"),
    ("credential", "AML.T0057"),
    ("hallucinat", "AML.T0062"),
    ("system information", "AML.T0069"),
    ("reconnaissance", "AML.T0069"),
    ("markdown injection", "AML.T0067"),
    ("trusted output", "AML.T0067"),
    ("response rendering", "AML.T0077"),
    ("chat history", "AML.T0092"),
    ("phishing", "AML.T0052"),
    ("social engineering", "AML.T0052"),
]

_ATLAS_FALLBACK: dict[str, str] = {
    "manipulation": "AML.T0051",
    "patterns": "AML.T0068",
    "outputs": "AML.T0057",
    # "abuse" intentionally unmapped: too broad for a confident technique.
}


def map_to_atlas(threats=None, categories=None, tags=None) -> list[tuple[str, str, str]]:
    """Return de-duplicated ``(atlas_id, technique_name, method)`` tuples.

    ``method`` is ``"keyword"`` for a keyword-rule match or ``"category-fallback"`` when
    the coarse category fallback supplied it (only when no keyword matched).
    """
    tokens = _tokens(threats, categories, tags)
    matched: dict[str, str] = {}  # atlas_id -> method
    for token in tokens:
        for keyword, atlas_id in _ATLAS_RULES:
            if atlas_id not in matched and _matches(keyword, token):
                matched[atlas_id] = "keyword"
    if not matched:
        for cat in categories or []:
            atlas_id = _ATLAS_FALLBACK.get(cat.strip().lower())
            if atlas_id and atlas_id not in matched:
                matched[atlas_id] = "category-fallback"
    return [(a, ATLAS_TECHNIQUES[a], m) for a, m in matched.items()]


# --- OWASP Top 10 for LLM Applications (2025) -------------------------------- #

OWASP_EDITION = "2025"

OWASP_LLM: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

_OWASP_RULES: list[tuple[str, str]] = [
    ("system prompt", "LLM07"),
    ("prompt leak", "LLM07"),
    ("system instruction", "LLM07"),
    ("jailbreak", "LLM01"),
    ("prompt injection", "LLM01"),
    ("injection", "LLM01"),
    ("obfuscation", "LLM01"),
    ("persona", "LLM01"),
    ("data leak", "LLM02"),
    ("exfiltration", "LLM02"),
    ("credential", "LLM02"),
    ("sensitive", "LLM02"),
    ("pii", "LLM02"),
    ("code execution", "LLM05"),
    ("reverse shell", "LLM05"),
    ("markdown injection", "LLM05"),
    ("xss", "LLM05"),
    ("tool", "LLM06"),
    ("agent", "LLM06"),
    ("function call", "LLM06"),
    ("hallucinat", "LLM09"),
    ("misinformation", "LLM09"),
    ("poisoning", "LLM04"),
    ("backdoor", "LLM04"),
    ("embedding", "LLM08"),
    ("vector", "LLM08"),
    ("rag", "LLM08"),
    ("denial of service", "LLM10"),
    ("unbounded", "LLM10"),
]

_OWASP_FALLBACK: dict[str, str] = {
    "manipulation": "LLM01",
    "patterns": "LLM01",
    "outputs": "LLM02",
    "abuse": "LLM06",
}


def map_to_owasp(threats=None, categories=None, tags=None) -> list[tuple[str, str, str]]:
    """Return de-duplicated ``(owasp_id, title, method)`` tuples.

    ``method`` is ``"keyword"`` or ``"category-fallback"`` (see :func:`map_to_atlas`).
    """
    tokens = _tokens(threats, categories, tags)
    matched: dict[str, str] = {}  # owasp_id -> method
    for token in tokens:
        for keyword, owasp_id in _OWASP_RULES:
            if owasp_id not in matched and _matches(keyword, token):
                matched[owasp_id] = "keyword"
    if not matched:
        for cat in categories or []:
            owasp_id = _OWASP_FALLBACK.get(cat.strip().lower())
            if owasp_id and owasp_id not in matched:
                matched[owasp_id] = "category-fallback"
    return [(o, OWASP_LLM[o], m) for o, m in matched.items()]
