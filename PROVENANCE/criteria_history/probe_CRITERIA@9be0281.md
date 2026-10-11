# v3.1-probe trial: criteria (committed BEFORE any trial run)

**Exploratory experiment.** It does not replace, re-score or re-run any primary result (development, held-out test,
malware test, in-the-wild). `score_v3.py`, `SCORING_v3.md` and every file of `FREEZE_v3.md` are unchanged; the trial
image `extprobe-sandbox:v3.1-probe` is built FROM the frozen v3 image and adds the explorer, the trace split and the
egress guard (`DESIGN.md`, steps 1–2). Ids are never printed or committed; the selected id lists live outside the
repository (`..\itw\probe\selected_{a,b,c}.txt`) and are fixed by the SHA-256 below.

## Samples (`select_trial.py`, seed 2026)

The T2 label of set A is weak (only 1 of 41 T2 ids is in the id list of the Socket VPN report), so the trial does
not rest on it.

| set | definition | n | SHA-256 of the sorted id list |
|---|---|---|---|
| (a) | set A packages (`..\itw\A`), **not in `itw\labeling\mapping.csv`**, complete v3 trace, the manifest declares a popup or an options page, and **no `score_v3` detector fired** on the v3 trace; `random.Random(2026).sample` of 60 (all if fewer) | **43** (only 43 eligible: 215 packages, 190 outside the dossiers) | `a0c65dcddd4f0e80968040129e0319ecf2110afc0cd9d5663e28d59370b7b3a3` |
| (b) | 50 of the 192 benign extensions of the held-out test set, `random.Random(2026).sample` over the sorted ids | **50** | `eafe3f11f1c1a6e11153f35e7e15990ea59320c046d0b87811006a8db8ac7d8a` |
| (c) | T2 samples of set A whose id is in the saved Socket report page, not in the dossiers — **case study only** | **1** | `1d3ffd30da6355f57c011d3f13cc9dcb07cd931b2ae5c16f7fe275ea720311a2` |

(a) selects extensions that v3 found silent: the question is whether clicking elicits anything at all, not a
detection rate. The (b) extensions' test result is already published from the frozen run; re-running them here is
for the comparison only.

## Run

- `run_probe.ps1` (checks: clean tree, frozen files = `FREEZE_v3.md`, image tags / ids, package checksums against
  `docs/samples_manifest_itw_A.csv` and `docs/samples_manifest_benign_test.csv`), **once**, image
  `extprobe-sandbox:v3.1-probe` with `NET_ADMIN`, 2 workers, timeout 240 s.
- The **same `.crx` files** as the v3 runs: set A as downloaded on 2026-10-10 (`..\itw\A`); test packages in
  `samples\benign_test`. The 24-hour rule of the in-the-wild criteria does not apply: this trial is not an
  in-the-wild measurement; the gap since the v3 run is reported.
- A run that fails for an infrastructure reason (no trace, Docker error) is re-run, at most 3 attempts. No other
  re-run, no sample dropped or added.

## Measures (fixed now; `analysis.py` implements exactly these)

Each v3.1-probe run gives two views of the same browser session: `events.json` (the v3 part, scored by `score_v3`)
and the filtered view of `score_v31.py` (v3 part + probe behaviour not directly caused by a click).

- **Main — elicitation yield**: samples with at least one new behaviour after the explorer / samples with a complete
  run; new behaviour = a proxy configuration (an executed `proxy.settings.set`, or a snapshot showing a fixed / PAC
  proxy of the extension), a declarativeNetRequest dynamic / session rule change, or an extension-initiated request
  (service worker, or content script outside the extension's own pages) to a host absent from the `events.json`
  part of the same run. **Storage changes are reported separately**, not in the yield. Wilson 95 %; (a) and (b)
  separately; (c) described.
- Secondary: samples whose flag at 40 changes between `score_v3(events.json)` and `score_v31` (both directions);
  (b) benign newly flagged; pages opened / declared; `login_gate`; extra time per sample (median, p90); egress
  blocks and rejected packets, and the pcap check (packets after a block, must be 0).
- Consistency: `score_v3(events.json)` of the trial vs the existing v3 trace of the same package
  (`eval\v3\in_the_wild\traces_A`, `eval\v3\test\traces_v3`): equal / higher / lower counts (the runs are days
  apart: servers may have changed).

## Not done

No label is changed; no sample of the dossiers is read or run; no result of this trial is merged into a primary
table. If a proxy configuration is seen and the gate could not block it (gate log `ok = false`), the set() was not
executed; such cases are counted and reported.
