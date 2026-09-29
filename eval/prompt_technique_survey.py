"""Technique survey of successful prompt attacks from public competition corpora.

Produces the aggregate numbers behind the "what 20,000 real prompt attacks look like"
analysis: which techniques appear, how they map onto MITRE ATLAS and the OWASP LLM Top 10,
how the mix shifts as defences get harder, and what changed between 2023-era and 2025-era
target models.

--------------------------------------------------------------------------------
WHY THERE IS A SIGNATURE DETECTOR IN HERE
--------------------------------------------------------------------------------
`adversarial_ai_cti.mappings` maps *taxonomy labels* (`threats` / `categories` / `tags`)
onto ATLAS and OWASP. It does not read prompt text, by design — guessing a technique from
raw text is exactly the kind of inference that module refuses to make.

The HackAPrompt and Pliny corpora carry no taxonomy labels at all. Their columns are
level/challenge, target model, pass flag and the prompt itself. So to say anything about
technique distribution, the labels have to be derived from the text first.

This module therefore does two clearly separated things:

  1. A **text-signature detector** (`SIGNATURES` below) that looks for explicit, auditable
     evidence of a technique in the prompt and emits the corresponding taxonomy token.
     This is lexical. It is new code, written here rather than ported from anywhere, and
     every pattern is visible in this file for inspection.

  2. The **published mapper** in `adversarial_ai_cti.mappings`, unchanged, which turns those
     taxonomy tokens into ATLAS technique IDs and OWASP categories and reports whether each
     mapping came from a keyword rule or the coarse category fallback.

Keeping them apart matters for reading the output honestly. Step 2 is published, reviewed
code. Step 1 is a lexical heuristic with the failure modes of any lexical heuristic: it
under-counts anything phrased unusually, and it can be fooled by a prompt that merely
discusses a technique. Coverage is reported so the under-counting is visible.

--------------------------------------------------------------------------------
COUNTING UNITS
--------------------------------------------------------------------------------
Mapping is one-to-many: a single prompt can carry several techniques. Both units are
reported everywhere:

  * per prompt          - share of prompts in which a technique appears at least once
                          (columns sum to more than 100%)
  * per (prompt, tech)  - share of all technique detections (columns sum to 100%)

--------------------------------------------------------------------------------
DATA
--------------------------------------------------------------------------------
HackAPrompt (MIT, hackaprompt/hackaprompt-dataset) - successful submissions only
    (`correct == True`), deduplicated on the normalised prompt.
Pliny HackAPrompt (CC-BY-4.0, hackaprompt/Pliny_HackAPrompt_Dataset) - passed submissions
    only (`passed == True`), deduplicated on the normalised final user turn.

Both are gated on HuggingFace: accept their terms before running. No corpus is committed to
this repository and the script emits aggregate counts only, never prompt text.

Usage:
    python eval/prompt_technique_survey.py
    python eval/prompt_technique_survey.py --hackaprompt-parquet path/to.parquet \
                                           --pliny-glob "path/to/pliny/*.parquet"
    python eval/prompt_technique_survey.py --json out.json
"""

from __future__ import annotations

import argparse
import glob as globmod
import json
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from adversarial_ai_cti.mappings import (  # noqa: E402
    ATLAS_VERSION,
    OWASP_EDITION,
    map_to_atlas,
    map_to_owasp,
)

SEED = 42

# --------------------------------------------------------------------------- #
# Text signatures -> taxonomy tokens.
#
# Each entry is (taxonomy_token, compiled_pattern, human note). The token is deliberately
# one the published mapper already understands, so no new mapping vocabulary is invented
# here. Patterns are lower-cased substring/regex tests over the prompt text.
#
# These are intentionally conservative. A prompt has to show the technique fairly plainly
# to be counted, which trades recall for precision: better to under-report a technique than
# to inflate it with loose matches.
# --------------------------------------------------------------------------- #
SIGNATURES: list[tuple[str, re.Pattern[str], str]] = [
    ("system prompt", re.compile(
        r"\b(system prompt|system message|initial (?:prompt|instruction)|"
        r"your instructions|the instructions above|prompt above|"
        r"what were you told|reveal .{0,20}(?:prompt|instruction))"), 
     "asks for the hidden instructions"),
    ("prompt injection", re.compile(
        r"\b(ignore (?:the )?(?:previous|above|prior|all)|disregard (?:the )?(?:previous|above|prior|all)|"
        r"forget (?:the )?(?:previous|above|prior|all|everything)|"
        r"instead of (?:the|your) (?:above|previous)|override .{0,15}instruction)"),
     "explicit instruction override"),
    ("roleplay", re.compile(
        r"\b(you are now|pretend (?:to be|you)|act as|acting as|roleplay|role-play|"
        r"from now on you|imagine you are|you will play)"),
     "persona or role assignment"),
    ("dan", re.compile(r"\b(do anything now|\bdan\b mode|developer mode|godmode|god mode)"),
     "named jailbreak persona"),
    ("base64", re.compile(r"\b(base64|b64decode|atob\()"), "base64 encoding"),
    ("encoding", re.compile(
        r"\b(rot13|hex(?:adecimal)? encod|url ?encod|morse code|binary encod|caesar cipher)"),
     "other encoding schemes"),
    ("leetspeak", re.compile(r"\b(leet ?speak|l33t|1337)"), "leetspeak obfuscation"),
    ("unicode", re.compile(
        r"(zero[- ]width|\u200b|\u200c|\u200d|\ufeff|homoglyph|right[- ]to[- ]left override)"),
     "unicode trickery"),
    ("obfuscation", re.compile(
        r"\b(spell(?:ed|ing)? (?:it )?backwards?|reverse the (?:text|string|order)|"
        r"insert .{0,12}between each (?:letter|character)|split the word)"),
     "manual text obfuscation"),
    ("translation", re.compile(
        r"\b(translate (?:the|this|it|into|to)|in (?:french|spanish|german|chinese|russian|"
        r"japanese|hindi|arabic)\b)"),
     "language switching"),
    ("code execution", re.compile(
        r"\b(execute (?:the )?(?:following|this) code|run this (?:code|script|command)|"
        r"subprocess|os\.system|eval\()"),
     "asks for or supplies executable code"),
    ("data leak", re.compile(
        r"\b(exfiltrat|leak (?:the|all|any) (?:data|information)|send .{0,20}to (?:https?://|my server)|"
        r"list all (?:the )?(?:users|records|customers|emails))"),
     "data extraction or exfiltration"),
    ("hypothetical", re.compile(
        r"\b(hypothetical(?:ly)?|in a fictional|for a (?:story|novel|screenplay|movie)|"
        r"this is (?:just )?(?:a )?(?:test|fiction)|in a world where)"),
     "fictional or hypothetical framing"),
    ("authority", re.compile(
        r"\b(i am (?:your|the) (?:developer|creator|admin|administrator|engineer)|"
        r"as an? (?:authorised|authorized) |i have permission|my (?:boss|manager) (?:said|asked))"),
     "claimed authority or permission"),
    ("urgency", re.compile(
        r"\b(this is (?:an )?(?:urgent|emergency)|lives? (?:are|is) at (?:stake|risk)|"
        r"you must comply|if you do not|or (?:i|someone) will (?:die|be harmed))"),
     "pressure or emotional coercion"),
    ("output format", re.compile(
        r"\b(respond only with|output only|reply with (?:only|just)|"
        r"do not (?:include|add) (?:any )?(?:explanation|warning|disclaimer)|no preamble)"),
     "output shaping to strip guardrail text"),
]


def normalise(text: str) -> str:
    return " ".join((text or "").lower().split())


def detect(text: str) -> list[str]:
    """Return the taxonomy tokens whose signature appears in *text*."""
    low = (text or "").lower()
    return [token for token, pattern, _ in SIGNATURES if pattern.search(low)]


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

def _hf(path: str, **kw):
    from datasets import load_dataset
    return load_dataset(path, **kw)


def load_hackaprompt(parquet: str | None):
    """Successful, deduplicated HackAPrompt submissions -> [(text, level, model)]."""
    if parquet:
        import pandas as pd
        df = pd.read_parquet(parquet, columns=["user_input", "level", "model", "correct"])
        rows = df[df.correct.fillna(False)].itertuples(index=False)
        raw = [(r.user_input, int(r.level), str(r.model)) for r in rows if r.user_input]
    else:
        ds = _hf("hackaprompt/hackaprompt-dataset")
        split = ds[list(ds.keys())[0]]
        raw = [(r["user_input"], int(r["level"]), str(r["model"]))
               for r in split if r.get("correct") and r.get("user_input")]
    seen, out = set(), []
    for text, level, model in raw:
        key = normalise(text)
        if key and key not in seen:
            seen.add(key)
            out.append((text, level, model))
    return out


def _final_user_turn(messages) -> str | None:
    """Pliny stores the whole conversation; the attack is the last user turn."""
    try:
        items = list(messages)
    except TypeError:
        return None
    for m in reversed(items):
        if isinstance(m, dict) and m.get("role") == "user" and m.get("content"):
            return str(m["content"])
    for m in reversed(items):
        if isinstance(m, dict) and m.get("content"):
            return str(m["content"])
    return None


def load_pliny(pattern: str | None):
    """Passed, deduplicated Pliny submissions -> [(text, challenge, model)]."""
    raw = []
    if pattern:
        import pandas as pd
        for p in sorted(globmod.glob(pattern)):
            df = pd.read_parquet(p, columns=["challenge_slug", "model_id", "passed", "messages"])
            for r in df[df.passed.fillna(False)].itertuples(index=False):
                t = _final_user_turn(r.messages)
                if t:
                    raw.append((t, str(r.challenge_slug), str(r.model_id)))
    else:
        ds = _hf("hackaprompt/Pliny_HackAPrompt_Dataset")
        split = ds[list(ds.keys())[0]]
        for r in split:
            if not r.get("passed"):
                continue
            t = _final_user_turn(r.get("messages"))
            if t:
                raw.append((t, str(r.get("challenge_slug")), str(r.get("model_id"))))
    seen, out = set(), []
    for text, challenge, model in raw:
        key = normalise(text)
        if key and key not in seen:
            seen.add(key)
            out.append((text, challenge, model))
    return out


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #

def survey(rows: list[tuple[str, object, str]], label: str) -> dict:
    """rows = [(text, bucket, model)]. Returns aggregate counts only, never text."""
    n = len(rows)
    per_prompt_tokens: Counter[str] = Counter()
    pair_tokens = 0
    atlas_prompt: Counter[str] = Counter()
    atlas_pairs: Counter[str] = Counter()
    owasp_prompt: Counter[str] = Counter()
    owasp_pairs: Counter[str] = Counter()
    provenance: Counter[str] = Counter()
    by_bucket: dict[object, Counter[str]] = {}
    by_model: dict[str, Counter[str]] = {}
    bucket_totals: Counter[object] = Counter()
    model_totals: Counter[str] = Counter()
    # distinct prompts with >=1 signature, so a rate can never exceed 100%
    bucket_covered: Counter[object] = Counter()
    model_covered: Counter[str] = Counter()
    unmapped = 0
    no_signature = 0
    len_with: list[int] = []
    len_without: list[int] = []

    for text, bucket, model in rows:
        tokens = detect(text)
        bucket_totals[bucket] += 1
        model_totals[model] += 1
        if tokens:
            len_with.append(len(text))
        else:
            no_signature += 1
            len_without.append(len(text))
        for t in set(tokens):
            per_prompt_tokens[t] += 1
        pair_tokens += len(set(tokens))

        # published mapper, unchanged: taxonomy tokens in, techniques + provenance out
        a = map_to_atlas(threats=tokens)
        o = map_to_owasp(threats=tokens)
        if not a and not o:
            unmapped += 1
        for aid, _name, method in a:
            atlas_prompt[aid] += 1
            atlas_pairs[aid] += 1
            provenance[f"atlas:{method}"] += 1
        for oid, _title, method in o:
            owasp_prompt[oid] += 1
            owasp_pairs[oid] += 1
            provenance[f"owasp:{method}"] += 1

        by_bucket.setdefault(bucket, Counter()).update(set(tokens))
        by_model.setdefault(model, Counter()).update(set(tokens))
        if tokens:
            bucket_covered[bucket] += 1
            model_covered[model] += 1

    return {
        "label": label,
        "prompts": n,
        "prompts_with_no_signature": no_signature,
        "prompts_unmapped": unmapped,
        "technique_detections": pair_tokens,
        "signature_counts_per_prompt": dict(per_prompt_tokens),
        "atlas_per_prompt": dict(atlas_prompt),
        "atlas_pairs_total": sum(atlas_pairs.values()),
        "owasp_per_prompt": dict(owasp_prompt),
        "owasp_pairs_total": sum(owasp_pairs.values()),
        "mapping_provenance": dict(provenance),
        "by_bucket": {str(k): dict(v) for k, v in sorted(by_bucket.items(), key=lambda x: str(x[0]))},
        "by_bucket_totals": {str(k): bucket_totals[k] for k in by_bucket},
        "by_bucket_covered": {str(k): bucket_covered[k] for k in by_bucket},
        "by_model": {k: dict(v) for k, v in by_model.items()},
        "by_model_totals": dict(model_totals),
        "by_model_covered": dict(model_covered),
        "length_chars": {
            "with_signature_median": _median(len_with),
            "no_signature_median": _median(len_without),
        },
    }


def _median(xs: list[int]) -> int:
    if not xs:
        return 0
    xs = sorted(xs)
    return xs[len(xs) // 2]


def _pct(n: int, d: int) -> str:
    return f"{100.0 * n / d:5.1f}%" if d else "    -"


def report(s: dict) -> None:
    n = s["prompts"]
    print("=" * 78)
    print(f"{s['label']}  —  {n:,} unique successful prompts")
    print("=" * 78)
    cov = n - s["prompts_with_no_signature"]
    print(f"  at least one technique signature : {cov:,} ({_pct(cov, n).strip()})")
    print(f"  no signature detected            : {s['prompts_with_no_signature']:,}")
    print(f"  total technique detections       : {s['technique_detections']:,}")
    print(f"  mean techniques per prompt       : {s['technique_detections']/n:.2f}" if n else "")

    print("\n  --- technique signatures ---")
    print(f"  {'signature':18} {'prompts':>8} {'per prompt':>11} {'of detections':>14}")
    tot = s["technique_detections"]
    for t, c in sorted(s["signature_counts_per_prompt"].items(), key=lambda x: -x[1]):
        print(f"  {t:18} {c:>8,} {_pct(c, n):>11} {_pct(c, tot):>14}")

    print(f"\n  --- MITRE ATLAS (release {ATLAS_VERSION}) ---")
    print(f"  {'technique':12} {'prompts':>8} {'per prompt':>11}")
    for a, c in sorted(s["atlas_per_prompt"].items(), key=lambda x: -x[1]):
        print(f"  {a:12} {c:>8,} {_pct(c, n):>11}")

    print(f"\n  --- OWASP LLM Top 10 ({OWASP_EDITION}) ---")
    print(f"  {'category':12} {'prompts':>8} {'per prompt':>11}")
    for o, c in sorted(s["owasp_per_prompt"].items(), key=lambda x: -x[1]):
        print(f"  {o:12} {c:>8,} {_pct(c, n):>11}")

    print("\n  --- mapping provenance (how each technique was derived) ---")
    prov = s["mapping_provenance"]
    for scheme in ("atlas", "owasp"):
        kw = prov.get(f"{scheme}:keyword", 0)
        fb = prov.get(f"{scheme}:category-fallback", 0)
        tot2 = kw + fb
        print(f"  {scheme:6} keyword {kw:>7,} ({_pct(kw, tot2).strip()})   "
              f"category-fallback {fb:>7,} ({_pct(fb, tot2).strip()})")

    lc = s["length_chars"]
    print(f"\n  median prompt length: {lc['with_signature_median']:,} chars with a signature, "
          f"{lc['no_signature_median']:,} without")

    if len(s["by_bucket"]) > 1:
        print("\n  --- by level / challenge (n = successful prompts in that bucket) ---")
        print(f"  {'bucket':>22} {'n':>7} {'signature rate':>15}   top signatures")
        for b, c in s["by_bucket"].items():
            tot_b = s["by_bucket_totals"].get(b, 0)
            covered = s["by_bucket_covered"].get(b, 0)
            top = ", ".join(f"{k} {v}" for k, v in sorted(c.items(), key=lambda x: -x[1])[:3]) or "-"
            print(f"  {b:>22} {tot_b:>7,} {_pct(covered, tot_b):>15}   {top}")

    if len(s["by_model"]) > 1:
        print("\n  --- by target model ---")
        print(f"  {'model':>34} {'n':>7} {'sig rate':>9}   top signatures")
        for m, c in sorted(s["by_model"].items(), key=lambda x: -s["by_model_totals"].get(x[0], 0)):
            tot_m = s["by_model_totals"].get(m, 0)
            covered = s["by_model_covered"].get(m, 0)
            top = ", ".join(f"{k} {v}" for k, v in sorted(c.items(), key=lambda x: -x[1])[:3]) or "-"
            print(f"  {m[:34]:>34} {tot_m:>7,} {_pct(covered, tot_m):>9}   {top}")
    print()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--hackaprompt-parquet")
    ap.add_argument("--pliny-glob")
    ap.add_argument("--skip-pliny", action="store_true")
    ap.add_argument("--json")
    args = ap.parse_args()

    print(f"seed={SEED}  ATLAS={ATLAS_VERSION}  OWASP={OWASP_EDITION}")
    print(f"{len(SIGNATURES)} text signatures\n")

    out = {}
    hap = load_hackaprompt(args.hackaprompt_parquet)
    s1 = survey(hap, "HackAPrompt 2023 (MIT)")
    report(s1)
    out["hackaprompt"] = s1

    if not args.skip_pliny:
        pl = load_pliny(args.pliny_glob)
        s2 = survey(pl, "Pliny HackAPrompt 2025 (CC-BY-4.0)")
        report(s2)
        out["pliny"] = s2

        print("=" * 78)
        print("2023-era targets vs 2025-era targets — share of prompts carrying each signature")
        print("=" * 78)
        keys = sorted(set(s1["signature_counts_per_prompt"]) | set(s2["signature_counts_per_prompt"]))
        print(f"  {'signature':18} {'2023':>9} {'2025':>9}   shift")
        for k in keys:
            a = s1["signature_counts_per_prompt"].get(k, 0) / max(s1["prompts"], 1) * 100
            b = s2["signature_counts_per_prompt"].get(k, 0) / max(s2["prompts"], 1) * 100
            arrow = "up  " if b > a + 1 else ("down" if a > b + 1 else "flat")
            print(f"  {k:18} {a:8.1f}% {b:8.1f}%   {arrow} {b - a:+.1f}pp")
        print()

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
        print(f"json -> {args.json}")


if __name__ == "__main__":
    main()
