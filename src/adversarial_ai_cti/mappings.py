"""Confident-only mapping from prompt taxonomy to MITRE ATLAS and OWASP LLM (2025).

Records rarely carry technique IDs, so free-text ``threats``/``categories``/``tags``
are mapped onto techniques by **word-boundary** keyword matching. Word-boundary (not
naive substring) matching keeps prefix keywords working (``hallucinat`` ->
``hallucination``) while preventing short keywords from matching mid-word (``dan`` in
``abundant``, ``rag`` in ``storage``). Unmatched input is left unmapped rather than
guessed.

ATLAS technique IDs/names are public MITRE data. The OWASP list is pinned to the 2025
edition; update ``OWASP_LLM`` and this note together if OWASP revises it.
"""

from __future__ import annotations

import re


def _matches(keyword: str, token: str) -> bool:
    """True when *keyword* begins on a word boundary within *token*."""
    return re.search(r"\b" + re.escape(keyword), token) is not None


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


def map_to_atlas(threats=None, categories=None, tags=None) -> list[tuple[str, str]]:
    """Return a de-duplicated list of ``(atlas_id, technique_name)`` tuples."""
    tokens = _tokens(threats, categories, tags)
    matched: list[str] = []
    for token in tokens:
        for keyword, atlas_id in _ATLAS_RULES:
            if _matches(keyword, token) and atlas_id not in matched:
                matched.append(atlas_id)
    if not matched:
        for cat in categories or []:
            atlas_id = _ATLAS_FALLBACK.get(cat.strip().lower())
            if atlas_id and atlas_id not in matched:
                matched.append(atlas_id)
    return [(a, ATLAS_TECHNIQUES[a]) for a in matched]


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


def map_to_owasp(threats=None, categories=None, tags=None) -> list[tuple[str, str]]:
    """Return a de-duplicated list of ``(owasp_id, title)`` tuples."""
    tokens = _tokens(threats, categories, tags)
    matched: list[str] = []
    for token in tokens:
        for keyword, owasp_id in _OWASP_RULES:
            if _matches(keyword, token) and owasp_id not in matched:
                matched.append(owasp_id)
    if not matched:
        for cat in categories or []:
            owasp_id = _OWASP_FALLBACK.get(cat.strip().lower())
            if owasp_id and owasp_id not in matched:
                matched.append(owasp_id)
    return [(o, OWASP_LLM[o]) for o in matched]
