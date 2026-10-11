# Analysis plan — expanded evaluation (610 samples, profile v2)

Fixed **before the run** (written 2026-10-07, committed on its own before `run_expanded.ps1`
is executed). If something here has to change, it changes in a new commit *before* the run, not
after the results are seen.

## 1. Set

| group | folder | n | label |
|---|---|---|---|
| malicious | `samples/malware` | 313 | `malicious` (manifest `docs/samples_manifest.csv`) |
| benign (paper) | `samples/benign` | 30 | `benign`, with the paper's verified labels |
| benign (paper) | `../sample/cws_benign_crx` | 11 | `benign`, with the paper's verified labels |
| benign (new) | `samples/benign_ext` | 256 | `docs/samples_manifest_benign_ext.csv`: 248 `benign`, 8 `grey` |

Total 313 + 30 + 11 + 256 = **610**. The first 354 are the *development set* (the detectors and
weights were designed and tuned on them; the paper's evaluation set). The 256 are the *new set*,
never used for any design decision.

One run per sample: profile `v2` (`extanalyze-sandbox:v2` = `extprobe-sandbox:v2`, image id of
FREEZE.md §2), `--timeout 180`, scored with `rescore.py --scoring auto` (v2 rules). Detectors,
weights and stimuli are those of tag `v2.0-freeze`, unchanged.

## 2. Labels

- Development 354: **verified labels** (`apply_verified_labels.py`; 46 hand-reviewed verdicts,
  other samples keep the original label), as in the paper. Verified `grey` and `unknown_verify`
  are separated from the main metrics; `benign_mislabel` counts as benign (same rule as
  `save_metrics.py`).
- New 256: **presumed-benign labels** from the manifest (a presumption, not a verdict: popular,
  well-rated, official store, not reviewed by hand; the paper must say so). `grey` = store
  description contains "coupon", "cash back" or "cashback" (CRITERIA.md decision 3).
- Only `run_status == complete` samples count, as in the paper; the number of non-complete
  samples per group is reported next to every table.

## 3. Main metrics

At **threshold 40** (the flag threshold): AUC (trapezoid over thresholds 0–100, same code as
`save_metrics.py`), **TP / FP / FN / TN**, **precision, recall, FPR**. Positive = malicious.
`grey` is reported **separately** (count, how many reach 40) and never enters the main metrics.

## 4. Required tables (`eval/expanded/results.md`)

- **(a) All** complete samples: verified labels for the 354, presumed labels for the 256.
- **(b) Development 354**: verified labels (main) and, for comparison with the paper, raw labels.
  Also the paper numbers and the A/B run B on the same samples are quoted for reference; the run
  is a fresh one, so small differences from `eval/ab/B` are reported, not hidden.
- **(c) New 256**: only **FPR** (and FP / TN) at 40, because the set has no malicious sample;
  precision, recall and AUC are *not* computed for it. Grey reported separately. FPR with a 95 %
  Wilson interval.
- Per detector: how many complete samples of each group each detector fires on.

## 5. False-positive analysis on the new benign set

For every `benign` sample of the new set with risk ≥ 40:

1. **Detector(s) that fired** (the six `summary.csv` signals plus `affiliate_hijack`, recomputed
   read-only from the trace with `worker/risk.py`), and the score decomposition (static, dynamic).
2. **Cause group**, one of: *first-party domain* (the undeclared host belongs to the
   extension's own vendor/product), *analytics / telemetry* (known analytics, crash-reporting
   or tag-manager hosts), *adblock / privacy tool* (CWS category `make_chrome_yours/privacy`, or
   a blocker/VPN/privacy function), *other*. The script proposes a group mechanically, in this
   priority order: analytics → first-party → adblock/privacy → other; the author reads each
   flagged trace and may correct a group; the table reports the **final** groups and says how
   many were corrected. No group is created after the results are seen other than these four.
3. **CWS category** (from the manifest): FP count, benign count and FPR per category.

The same table is written for the 11 + 30 paper-benign FPs for reference only.

## 6. Commitments

- **No change** to any detector, weight, stimulus, threshold or sandbox image after seeing the
  results. A defect found in the results is documented as a limitation or fixed under a new tag
  *with a new run*, and the old numbers stay in the repository.
- No sample is dropped or replaced because of its result. Samples that do not complete are
  reported as such (3 attempts each, `eval/expanded/runner.log`).
- Everything reported comes from `eval/expanded_analysis.py` on the committed rule set; numbers
  are not computed by hand.
- Limits to state in the paper: new labels are presumptions; top-32-per-category popularity
  bias; the 354 are the development set; 0 malicious samples in the new set means no recall
  claim beyond the 313.
