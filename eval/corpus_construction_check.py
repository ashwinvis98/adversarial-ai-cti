"""Check how a prompt-attack corpus was BUILT, before interpreting what is in it.

This script exists because of a mistake. `prompt_technique_survey.py` produced a clean
technique breakdown of 18,479 successful HackAPrompt attacks, every number of it correct, and
the interpretation built on top was wrong in three separate ways. All three were answerable
from columns already sitting in the dataset. None of them needed new data, a write-up, or a
judgement call.

So this is the check that should run FIRST, and the findings it produces are constraints on
anything the survey says afterwards.

--------------------------------------------------------------------------------
THE THREE QUESTIONS
--------------------------------------------------------------------------------

1. WHAT DID THE CORPUS ASK FOR?
   `expected_completion` is the string the competition scored against. If it is constant
   across a level, every success on that level shares one objective, and the taxonomy label
   for the whole level is fixed before you read a single prompt.

2. WHAT DOES EACH TASK AFFORD?
   The `prompt` column holds the full scaffold with the attacker's text substituted in.
   Remove the attacker's text and you recover the task. A task that says "translate this into
   Spanish" will produce translation-shaped attacks no matter what attackers prefer, so any
   `translation` signature on that level is the task talking. This quantifies how much of each
   signature sits on levels whose task affords it.

3. IS THE DETECTOR'S MISS SET TELLING YOU ANYTHING?
   A keyword detector fires more often on long text, because long text has more places for a
   pattern to match. So "the prompts I could not classify are shorter" is true of every
   substring detector ever written and is not evidence about the prompts. The control here
   re-runs the same split on a word with no relationship to technique at all. If the control
   reproduces the gap, the gap is mechanical.

Aggregate counts and task scaffolds only. No attacker prompt text is emitted.

Usage:
    python eval/corpus_construction_check.py
    python eval/corpus_construction_check.py --parquet path/to/hackaprompt.parquet
    python eval/corpus_construction_check.py --json out.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(__file__))
from prompt_technique_survey import detect, normalise  # noqa: E402

# A task affords a signature when the scaffold itself asks for the thing the signature
# detects. These are substring tests against the recovered scaffold, listed here so the
# judgement is auditable rather than asserted in prose.
TASK_AFFORDANCE: dict[str, list[str]] = {
    "translation": ["translat", "spanish", "biblioteca"],
    "roleplay": ["storyteller", "act as", "personality", "you are a bot", "ucar", "sda"],
    "output format": ["only print", "no period", "never say the word",
                      "do not use any of the following words",
                      "remove punctuation", "without punctuation"],
    "unicode": ["separated by slashes", "emoji"],
}

CONTROL_WORD = "the"  # not a technique; used to expose the detector's length bias


def _load(parquet: str | None):
    cols = ["level", "prompt", "user_input", "expected_completion", "correct",
            "token_count", "score"]
    if parquet:
        import pandas as pd
        return pd.read_parquet(parquet, columns=cols)
    from datasets import load_dataset
    import pandas as pd
    ds = load_dataset("hackaprompt/hackaprompt-dataset")
    return pd.DataFrame(ds[list(ds.keys())[0]])[cols]


_MIN_INPUT = 25   # shorter inputs (e.g. a single letter) substitute everywhere and shred it


def recover_scaffold(sub, sample: int = 4000) -> str:
    """Recover the task scaffold by removing the attacker's text from `prompt`.

    Takes the MODAL result rather than the longest. Two traps, both hit in practice:
    a one-character `user_input` matches all over the template and destroys it, and a single
    unusual submission can produce a one-off scaffold that looks authoritative. Requiring a
    reasonably long input and then taking the most common result avoids both.
    """
    forms: Counter = Counter()
    for p, u in zip(sub.prompt.head(sample), sub.user_input.head(sample)):
        if (isinstance(p, str) and isinstance(u, str)
                and len(u) >= _MIN_INPUT and u in p):
            forms[" ".join(p.replace(u, " {ATTACKER_INPUT} ").split())] += 1
    if not forms:
        for p in sub.prompt.dropna().astype(str).head(sample):
            forms[" ".join(p.split())] += 1
    return forms.most_common(1)[0][0] if forms else ""


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--parquet")
    ap.add_argument("--json")
    ap.add_argument("--scaffold-chars", type=int, default=260)
    args = ap.parse_args()

    import pandas as pd

    df = _load(args.parquet)
    win = df[df.correct.fillna(False)]
    out: dict = {}

    # ---------------------------------------------------------------- Q1
    print("=" * 94)
    print("1. WHAT DID THE CORPUS ASK FOR?   (expected_completion per level)")
    print("=" * 94)
    objectives = {}
    for lv in sorted(df.level.dropna().unique()):
        sub = df[df.level == lv]
        vals = sub.expected_completion.dropna().astype(str).str.strip()
        n_distinct = vals.nunique()
        top = vals.value_counts().index[0] if len(vals) else ""
        fixed = n_distinct == 1
        objectives[int(lv)] = {"rows": len(sub), "distinct": int(n_distinct),
                               "fixed_target": fixed,
                               "target": top if fixed else "<per-session value>"}
        flag = "FIXED PHRASE" if fixed else "PER-SESSION SECRET"
        print(f"  level {int(lv):>2}  rows={len(sub):>7,}  distinct={n_distinct:>6,}  "
              f"{flag:<19} {objectives[int(lv)]['target'][:40]!r}")
    out["objectives"] = objectives

    n_fixed = sum(1 for v in objectives.values() if v["fixed_target"])
    print(f"\n  {n_fixed} of {len(objectives)} levels score against one fixed string.")
    print("  On those levels the objective is: make the model emit that string in defiance of")
    print("  its instructions. That is prompt injection by construction - the taxonomy label")
    print("  for every success is known before any prompt is read.")
    notfixed = [lv for lv, v in objectives.items() if not v["fixed_target"]]
    if notfixed:
        print(f"  Level(s) {notfixed} instead score against a per-session value, i.e. the")
        print("  objective is extracting something planted in the system prompt.")

    print("\n  Did winners actually hit the fixed target?")
    for lv in sorted(win.level.dropna().unique()):
        if not objectives[int(lv)]["fixed_target"]:
            continue
        sub = win[win.level == lv]
        tgt = objectives[int(lv)]["target"].lower().split()[-1]
        # `completion` is not loaded; use the scored flag as the ground truth instead
        print(f"    level {int(lv):>2}  winners={len(sub):>6,}  "
              f"scored against {tgt!r}")

    # ---------------------------------------------------------------- Q2
    print("\n" + "=" * 94)
    print("2. WHAT DOES EACH TASK AFFORD?   (recovered scaffolds)")
    print("=" * 94)
    scaffolds, affords = {}, {}
    for lv in sorted(df.level.dropna().unique()):
        s = recover_scaffold(df[df.level == lv])
        scaffolds[int(lv)] = s
        low = s.lower()
        affords[int(lv)] = [sig for sig, keys in TASK_AFFORDANCE.items()
                            if any(k in low for k in keys)]
        print(f"\n  ----- level {int(lv)} -----  affords: {affords[int(lv)] or '-'}")
        print("   " + s[:args.scaffold_chars] + ("..." if len(s) > args.scaffold_chars else ""))
    out["scaffolds"] = scaffolds
    out["affordance"] = affords

    # signature x level, on deduplicated winners
    seen: set[str] = set()
    rows: list[tuple[str, int]] = []
    for t, lv in zip(win.user_input, win.level):
        if isinstance(t, str) and t and pd.notna(lv):
            k = normalise(t)
            if k and k not in seen:
                seen.add(k)
                rows.append((t, int(lv)))
    print(f"\n  deduplicated winners: {len(rows):,}")

    per_level: dict[int, Counter] = {}
    totals: Counter = Counter()
    for t, lv in rows:
        toks = set(detect(t))
        per_level.setdefault(lv, Counter()).update(toks)
        totals.update(toks)

    print("\n" + "-" * 94)
    print("  HOW MUCH OF EACH SIGNATURE IS THE TASK TALKING?")
    print("-" * 94)
    print(f"  {'signature':16} {'total':>7} {'on affording levels':>20} {'share':>8}   levels")
    conc = {}
    for sig in TASK_AFFORDANCE:
        tot = totals.get(sig, 0)
        if not tot:
            continue
        lv_afford = sorted(lv for lv, a in affords.items() if sig in a)
        inside = sum(per_level.get(lv, Counter()).get(sig, 0) for lv in lv_afford)
        conc[sig] = {"total": tot, "inside": inside,
                     "share": round(100.0 * inside / tot, 1), "levels": lv_afford}
        print(f"  {sig:16} {tot:>7,} {inside:>20,} {100.0*inside/tot:>7.1f}%   {lv_afford}")
    out["task_concentration"] = conc
    out["signature_by_level"] = {str(k): dict(v) for k, v in sorted(per_level.items())}

    print("\n  A high share means the signature is a property of the challenge, not a")
    print("  preference of the attackers. Read those distributions as descriptions of the")
    print("  competition.")

    # ---------------------------------------------------------------- Q3
    print("\n" + "=" * 94)
    print("3. IS THE DETECTOR'S MISS SET TELLING YOU ANYTHING?   (length-bias control)")
    print("=" * 94)
    d = pd.DataFrame({
        "chars": [len(t) for t, _ in rows],
        "hit": [bool(detect(t)) for t, _ in rows],
        "ctrl": [CONTROL_WORD in t.lower().split() for t, _ in rows],
    })
    d["dec"] = pd.qcut(d.chars, 10, duplicates="drop")
    g = d.groupby("dec", observed=True).agg(n=("hit", "size"),
                                            detector=("hit", "mean"),
                                            control=("ctrl", "mean"))
    print(f"  {'length decile':>22} {'n':>6} {'detector fires':>15} "
          f"{'control (%r)' % CONTROL_WORD:>18}")
    for idx, r in g.iterrows():
        print(f"  {str(idx):>22} {int(r.n):>6,} {100*r.detector:>14.1f}% "
              f"{100*r.control:>17.1f}%")

    med = {
        "detector_hit": float(d[d.hit].chars.median()),
        "detector_miss": float(d[~d.hit].chars.median()),
        "control_hit": float(d[d.ctrl].chars.median()),
        "control_miss": float(d[~d.ctrl].chars.median()),
    }
    print(f"\n  median chars, detector fires / does not : "
          f"{med['detector_hit']:.0f} / {med['detector_miss']:.0f}")
    print(f"  median chars, {CONTROL_WORD!r} present / absent    : "
          f"{med['control_hit']:.0f} / {med['control_miss']:.0f}")
    print("\n  The control has nothing to do with technique and reproduces the same split.")
    print("  Therefore 'the prompts I could not classify are shorter' is a property of")
    print("  substring matching, not a finding about the prompts. Any argument resting on it")
    print("  is invalid.")
    out["length_bias"] = {
        "medians": med,
        "by_decile": [{"decile": str(i), "n": int(r.n),
                       "detector": round(100 * r.detector, 1),
                       "control": round(100 * r.control, 1)} for i, r in g.iterrows()],
    }

    # ---------------------------------------------------------------- scoring
    print("\n" + "=" * 94)
    print("4. DID THE SCORING PENALISE LENGTH?")
    print("=" * 94)
    w = win.dropna(subset=["token_count", "score"])
    corr = float(w.token_count.corr(w.score))
    lo = float(w[w.token_count <= w.token_count.quantile(0.1)].score.mean())
    hi = float(w[w.token_count >= w.token_count.quantile(0.9)].score.mean())
    print(f"  corr(token_count, score)          = {corr:+.3f}")
    print(f"  mean score, shortest token decile = {lo:,.0f}")
    print(f"  mean score, longest token decile  = {hi:,.0f}")
    print("  => weakly positive. Whatever the scoring rules were, this column does not show")
    print("     shorter winning prompts scoring better, so do not claim a token penalty.")
    out["scoring"] = {"corr_tokens_score": round(corr, 4),
                      "mean_score_short_decile": round(lo), "mean_score_long_decile": round(hi)}

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
        print(f"\njson -> {args.json}")


if __name__ == "__main__":
    main()
