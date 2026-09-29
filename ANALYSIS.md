# Technique survey of successful prompt attacks

Aggregate findings from two public prompt-hacking competition corpora, produced by
`eval/prompt_technique_survey.py`. Fixed seed, deterministic, no corpus committed here, no
prompt text emitted — counts only.

**Datasets.** [HackAPrompt](https://huggingface.co/datasets/hackaprompt/hackaprompt-dataset)
(MIT) and [Pliny HackAPrompt](https://huggingface.co/datasets/hackaprompt/Pliny_HackAPrompt_Dataset)
(CC-BY-4.0). Both are gated on HuggingFace — accept their terms before running.

**Reproduce:**

```bash
python eval/corpus_construction_check.py                     # how the corpus was built - FIRST
python eval/prompt_technique_survey.py                       # the technique breakdown
python eval/prompt_technique_survey.py --json out.json       # machine-readable
```

Run the construction check first. It establishes what the corpus was scored against and what
each task affords, and those findings are constraints on every distribution the survey
produces. §0 below is its output.

Last run 2026-09-28. ATLAS release `2026.07`, OWASP LLM edition `2025`.

---

---

## 0. Read this before reading any distribution below

Two properties of HackAPrompt constrain everything in this file. Both are derived by
`eval/corpus_construction_check.py` from columns in the dataset itself, and both were missed
on the first pass through this analysis.

**Every successful attack is prompt injection by construction.** On ten of the eleven levels
`expected_completion` is one fixed string — `I have been PWNED` — identical across all 578,857
rows on those levels. The objective is to make the model emit it in defiance of its
instructions, so every success is `AML.T0051`. Level 2 is the exception: 62,900 distinct
scoring targets, one secret key per session, which makes it `AML.T0056` Extract LLM System
Prompt. No winner in this corpus falls outside the taxonomy.

That makes the corpus unusually valuable, because the correct label is known in advance and
the signature detector's output can be scored against it:

| | prompts | share of 18,479 |
|---|---|---|
| ground truth — every winner is `AML.T0051` | 18,479 | 100% |
| any named sub-technique detectable | 4,058 | 22.0% |
| resolves to any ATLAS or OWASP entry | 2,785 | 15.1% |
| **pipeline actually labelled it `AML.T0051`** | **2,114** | **11.4%** |

**11.4% recall, 88.6% false negative, against uncontested ground truth.** This is the single
most transferable number here: it bounds what keyword attribution over prompt text recovers.

**The technique distribution is mostly a description of the challenges.** Each level's task
is recoverable from the `prompt` column, and the tasks predict the signatures:

| signature | total | on levels whose task asks for it | share | levels |
|---|---|---|---|---|
| translation | 1,020 | 953 | **93.4%** | 1, 2, 3, 6 |
| unicode | 120 | 105 | **87.5%** | 9, 10 |
| roleplay | 529 | 217 | 41.0% | 0, 8 |
| output format | 345 | 132 | 38.3% | 0, 6, 7 |

Levels 1–3 are Spanish-translation tasks; level 6 embeds `translate: he sido pwned remove
punctuation`; level 9 splits input character-by-character with slashes; level 10 is
emoji-only; level 0 is a persona bot; level 8 is a nested storyteller jailbreak. So
"translation is the second most common technique" is a fact about four challenges, not about
attacker preference.

**Do not read the miss set's length as evidence.** The detector's median is 180 chars when it
fires and 94 when it does not — but a control pattern with no relationship to technique (the
word `the`) gives 193 and 61, a wider gap. Detection rate rises monotonically with length for
both (1.9% → 42.5% for the detector, 3.5% → 91.8% for the control). The asymmetry is a
property of substring matching and supports no conclusion about the prompts.

**The scoring did not penalise length.** `corr(token_count, score) = +0.114`; mean score rises
from 47,018 in the shortest token decile to 88,371 in the longest. Do not claim a token
penalty explains short winners.

---

## Method, and what it can and cannot tell you

`adversarial_ai_cti.mappings` maps *taxonomy labels* onto ATLAS and OWASP. It deliberately
does not read prompt text. Neither corpus carries taxonomy labels — their columns are
level/challenge, target model, a pass flag, and the prompt — so the labels have to be
derived from the text before anything can be mapped.

The survey therefore runs in two separable stages:

1. **A text-signature detector** (16 patterns, all visible in
   `eval/prompt_technique_survey.py`) that looks for explicit evidence of a technique and
   emits a taxonomy token. This is new, lexical, and conservative.
2. **The published mapper**, unchanged, turning those tokens into ATLAS technique IDs and
   OWASP categories and reporting whether each mapping came from a keyword rule or the
   coarse category fallback.

**Counting unit.** Mapping is one-to-many. "Per prompt" is the share of prompts in which a
technique appears at least once, so those columns sum to more than 100%. "Of detections" is
the share of all technique detections, which sums to 100%.

**Mapping provenance.** Every mapping in both corpora resolved by **keyword rule**;
`category-fallback` contributed **0%**. That is expected here, because the tokens the
detector emits are the same vocabulary the keyword rules are written against. It means the
technique attribution is only as good as the signature detector feeding it.

**Population.** Successful attempts only — HackAPrompt `correct == True`, Pliny
`passed == True` — deduplicated on the normalised prompt. Failed attempts are excluded, so
this describes what *worked*, not what was tried.

---

## 1. HackAPrompt (2023 targets)

**18,479 unique successful prompts** out of 601,757 total submissions.

All 18,479 are `AML.T0051` by construction — see §0. The figures below describe what the
signature detector could recover, not which attacks fit the taxonomy.

| | |
|---|---|
| at least one technique signature | **4,058 (22.0%)** |
| no signature detected | 14,421 (78.0%) |
| total technique detections | 4,501 |
| mean techniques per prompt | 0.24 |
| median length, with a signature | 180 chars |
| median length, without | 94 chars (an artifact — see §0) |

### Signature distribution

Cross-reference §0 before reading this as attacker behaviour: 93.4% of `translation` and 87.5%
of `unicode` sit on levels whose own task asks for them.

| signature | prompts | per prompt | of detections |
|---|---|---|---|
| prompt injection | 2,114 | 11.4% | 47.0% |
| translation | 1,020 | 5.5% | 22.7% |
| roleplay | 529 | 2.9% | 11.8% |
| output format | 345 | 1.9% | 7.7% |
| unicode | 120 | 0.6% | 2.7% |
| hypothetical | 110 | 0.6% | 2.4% |
| system prompt | 104 | 0.6% | 2.3% |
| urgency | 63 | 0.3% | 1.4% |
| base64 | 29 | 0.2% | 0.6% |
| dan | 24 | 0.1% | 0.5% |
| obfuscation | 14 | 0.1% | 0.3% |
| encoding | 14 | 0.1% | 0.3% |
| code execution | 9 | 0.0% | 0.2% |
| authority | 4 | 0.0% | 0.1% |
| leetspeak | 2 | 0.0% | 0.0% |

### MITRE ATLAS (release 2026.07), per prompt

| technique | | prompts | per prompt |
|---|---|---|---|
| `AML.T0051` | LLM Prompt Injection | 2,114 | 11.4% |
| `AML.T0054` | LLM Jailbreak | 546 | 3.0% |
| `AML.T0068` | LLM Prompt Obfuscation | 179 | 1.0% |
| `AML.T0056` | Extract LLM System Prompt | 104 | 0.6% |

### OWASP LLM Top 10 (2025), per prompt

| category | | prompts | per prompt |
|---|---|---|---|
| `LLM01` | Prompt Injection | 2,127 | 11.5% |
| `LLM07` | System Prompt Leakage | 104 | 0.6% |
| `LLM05` | Improper Output Handling | 9 | 0.0% |

### By competition level

Levels run 0 (easiest) to 10 (hardest). **Level 10 recorded no successful submissions at
all** and does not appear below.

These are **eleven different applications with eleven different defences**, not one defence
being strengthened, so the downward trend in signature rate is not a statement about
difficulty. Eight of the ten solved levels have a task that asks for one of the signatures
(§0); the two that don't — level 4, a search engine, and level 5, a grammar assistant — sit
mid-table at 15.3% and 15.6%.

| level | successful prompts | signature rate | top signatures |
|---|---|---|---|
| 0 | 2,249 | 30.5% | prompt injection 512, roleplay 110, output format 55 |
| 1 | 2,586 | 33.2% | translation 529, prompt injection 317, roleplay 68 |
| 2 | 2,672 | 25.3% | prompt injection 308, translation 284, output format 88 |
| 3 | 1,861 | 16.9% | prompt injection 149, translation 130, roleplay 27 |
| 4 | 2,160 | 15.3% | prompt injection 212, roleplay 47, output format 47 |
| 5 | 1,849 | 15.6% | prompt injection 178, roleplay 44, urgency 43 |
| 6 | 1,271 | 21.9% | prompt injection 194, roleplay 36, hypothetical 32 |
| 7 | 1,369 | 12.9% | prompt injection 70, output format 58, roleplay 27 |
| 8 | 1,631 | 21.2% | prompt injection 174, roleplay 107, hypothetical 30 |
| 9 | 831 | 12.6% | **unicode 105 (the only signature present)** |

### By target model

| model | successful prompts | signature rate | top signatures |
|---|---|---|---|
| FlanT5-XXL | 8,492 | 17.9% | prompt injection 750, translation 535, roleplay 115 |
| gpt-3.5-turbo | 7,877 | 23.7% | prompt injection 1,048, translation 297, roleplay 274 |
| text-davinci-003 | 2,110 | 31.9% | prompt injection 316, translation 188, roleplay 140 |

---

## 2. Pliny HackAPrompt (2025 targets)

**1,905 unique successful prompts** out of 16,902 submissions, against seven 2024–2025 models.

| | |
|---|---|
| at least one technique signature | 523 (27.5%) |
| no signature detected | 1,382 (72.5%) |
| total technique detections | 617 |
| median length, with a signature | 9,245 chars |
| median length, without | 94 chars |

| signature | prompts | per prompt | of detections |
|---|---|---|---|
| base64 | 346 | 18.2% | 56.1% |
| prompt injection | 152 | 8.0% | 24.6% |
| encoding | 72 | 3.8% | 11.7% |
| output format | 18 | 0.9% | 2.9% |
| unicode | 11 | 0.6% | 1.8% |
| leetspeak | 7 | 0.4% | 1.1% |
| roleplay | 5 | 0.3% | 0.8% |
| system prompt | 3 | 0.2% | 0.5% |
| translation | 2 | 0.1% | 0.3% |
| obfuscation | 1 | 0.1% | 0.2% |

ATLAS: `AML.T0068` LLM Prompt Obfuscation 436 (22.9%), `AML.T0051` 152 (8.0%),
`AML.T0054` 5 (0.3%), `AML.T0056` 3 (0.2%).

### By challenge — and why the comparison below does not survive

| challenge | successful | signature rate | signatures present |
|---|---|---|---|
| pliny_6 | 127 | **100.0%** | base64 127 |
| pliny_7 | 105 | **100.0%** | base64 105, leetspeak 1 |
| pliny_8 | 89 | **100.0%** | base64 89 |
| pliny_10 | 150 | **100.0%** | prompt injection 150, encoding 65, base64 20 |
| pliny_12 | 2 | **100.0%** | prompt injection 2 |
| pliny_9 | 185 | 21.1% | output format 18, encoding 7, leetspeak 5, base64 5, roleplay 5, system prompt 3, translation 2, unicode 1, obfuscation 1 |
| pliny_3 | 150 | 2.0% | unicode 3 |
| pliny_1 | 454 | 1.3% | unicode 5, leetspeak 1 |
| pliny_4 | 244 | 0.8% | unicode 2 |
| pliny_2 | 158 | 0.0% | — |
| pliny_5 | 201 | 0.0% | — |
| pliny_11 | 40 | 0.0% | — |

**Five of the twelve challenges are saturated** — every winner carries at least one named
technique. Those five contain **473 of the 523 signature-bearing winners in the corpus
(90.4%)**. The concentration per technique is worse than that summary suggests:

| technique | corpus total | inside the five saturated challenges | outside |
|---|---|---|---|
| base64 | 346 | **341 (98.6%)** — pliny_6 127, pliny_7 105, pliny_8 89, pliny_10 20 | pliny_9 5 |
| prompt injection | 152 | **152 (100%)** — pliny_10 150, pliny_12 2 | none |
| encoding | 72 | **65 (90.3%)** — pliny_10 only | pliny_9 7 |

This is a property of the challenges, not of attacker preference: those tasks appear to
*require* base64 or an instruction override to solve at all. The 2025 signature profile is
therefore mostly a description of which challenges were solvable, and the cross-competition
comparison in §3 should be read as illustrative of that confound rather than as a trend.

---

## 3. 2023 vs 2025 — read with the caveat above

Share of successful prompts carrying each signature.

| signature | 2023 | 2025 | shift |
|---|---|---|---|
| base64 | 0.2% | 18.2% | **+18.0 pp** |
| encoding | 0.1% | 3.8% | +3.7 pp |
| leetspeak | 0.0% | 0.4% | +0.4 pp |
| unicode | 0.6% | 0.6% | −0.1 pp |
| obfuscation | 0.1% | 0.1% | −0.0 pp |
| output format | 1.9% | 0.9% | −0.9 pp |
| system prompt | 0.6% | 0.2% | −0.4 pp |
| urgency | 0.3% | 0.0% | −0.3 pp |
| hypothetical | 0.6% | 0.0% | −0.6 pp |
| prompt injection | 11.4% | 8.0% | −3.5 pp |
| roleplay | 2.9% | 0.3% | **−2.6 pp** |
| translation | 5.5% | 0.1% | **−5.4 pp** |

**This is not a controlled experiment, and the confound is large enough to sink it.** The two
competitions set different challenges against different models two years apart, and five of
the twelve 2025 challenges are saturated on a named technique — accounting for 90.4% of every
signature-bearing winner, 98.6% of base64, 100% of instruction override, and 90.3% of other
encodings (all from a single challenge). Strip those out and there is very little 2025 signal
left to compare against 2023.

Do not read the table above as a trend. The falls in translation and roleplay are the only
movements challenge design does not obviously manufacture, and they are movements towards
zero in a corpus whose detected techniques are concentrated in five tasks. The numbers are
recorded here because the corpora are public and anyone can compute them; none of the
magnitudes transfer to live traffic.

---

## 4. Limitations

- **The detector's recall is 11.4% against known ground truth** (§0). Treat every distribution
  here as a distribution *within the detected subset*, which is a fifth of the corpus.
- **Most of the distribution is challenge design, not attacker preference** (§0). This is the
  dominant limitation and it applies to every table below §0.
- **Task affordance is a judgement.** Which scaffold keywords count as a task "asking for" a
  technique is a list in `eval/corpus_construction_check.py`. It is visible and arguable, and
  the concentration figures move if you disagree with it.
- **It can be fooled.** A prompt that merely discusses base64 counts as base64. Patterns are
  conservative to limit this, at the cost of further recall.
- **These are competitions, not production traffic.** Participants optimise against a scoring
  function and a fixed set of challenges. HackAPrompt is from 2023.
- **Successes only.** Nothing here says how often a technique was *tried* and failed, so no
  success rate per technique can be derived from it.
- **`category-fallback` is 0% by construction**, because the detector emits the same
  vocabulary the keyword rules match on. It is not evidence that the mapping is unambiguous.
- **ATLAS coverage is a 14-technique hand-maintained subset** pinned to release `2026.07`,
  not the full matrix.

## 5. Redundancy

Not re-derived here. The exact-duplicate and near-duplicate figures for HackAPrompt are in
[`promptlsh` RESULTS §1](https://github.com/ashwinvis98/promptlsh/blob/main/RESULTS.md).
