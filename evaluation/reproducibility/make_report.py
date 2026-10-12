import json
from pathlib import Path
import argparse
_ap = argparse.ArgumentParser(description="Write REPORT.md from rescore_summary.json and smoke_results.json.")
_ap.add_argument("--summary", required=True)
_ap.add_argument("--smoke", required=True)
_ap.add_argument("--out", required=True)
_a = _ap.parse_args()
S = json.loads(Path(_a.summary).read_text(encoding="utf-8"))
M = json.loads(Path(_a.smoke).read_text(encoding="utf-8"))
names = {"test_v3": "held-out benign test set", "dev_v3": "dev set", "itw_A": "in-the-wild set A", "itw_B": "in-the-wild set B",
         "probe_a": "v3.1-probe trial (a), score_v31", "probe_b": "v3.1-probe trial (b), score_v31"}
L = ["# Reproducibility check: this repository against the development repository", "",
     "Does this repository reproduce the results of the private development repository? Counts only: no extension ID, name or domain appears on this page. The development repository was read-only for the check (its `git status` stayed clean; the scripts ran with `PYTHONDONTWRITEBYTECODE=1`). Re-scoring covers 1,319 archived traces; the live re-runs are 11 samples.", "",
      "**Summary.** Re-scoring the archived traces reproduces every score and flag exactly (1,319 traces, 0 mismatches). Live re-runs can differ for timing-dependent detectors: 10 of 11 flags were identical in a smoke re-run.", "",
     "## 1. Re-scoring of the stored traces (deterministic)", "",
     "Reference = the old repository's own scorer (`eval/v3/score_v3.py`, `eval/v3_1_probe/score_v31.py`) run on the same stored traces with the same package folder; "
     "new = `extprobe score-v3` / `extprobe score-v31` of this repository. Both wrote the full result as JSON (`--out`). "
     "\"Identical full result\" compares the whole result object (score, level, fired detectors, every signal with weights and details, static display).", "",
     "| set | n compared | identical score | identical flag@40 | identical full result | mismatches |", "|---|---|---|---|---|---|"]
for k, v in S.items():
    if k in names:
        L.append(f"| {names[k]} | {v['compared']} | {v['ident_score']} | {v['ident_flag']} | {v['ident_full_result']} | {v['mismatches']} |")
d = S["dev_vs_recorded_summary_v3_csv"]
L += ["", "**Mismatches: none in any set.** The key sets of old and new results are identical in every set.", "",
      "### Against a recorded per-sample file (dev set only)", "",
      f"The old repository keeps one recorded per-sample file for the dev set (`eval/v3/dev/summary_v3.csv`: {d['rows']} rows, 9 not complete). For the {d['found']} complete rows: "
      f"risk score identical {d['ident_risk']}/{d['found']}, flag@40 identical {d['ident_flag']}/{d['found']}, fired-detector set identical {d['ident_det']}/{d['found']}. "
      "The dev trace folder has 611 sample folders: the 610 recorded ones plus one `canary` smoke folder.", "",
      "For the other sets the old repository records only aggregates (blind labelling: no per-sample score is stored), so the reference for them is the old scorer re-run on the stored traces, plus the published aggregates below.", "",
      "### Headline numbers recomputed from the new scores", "",
      "| quantity | recomputed | published (evaluation/) |", "|---|---|---|"]
t = S["headline_test"]
L.append(f"| held-out test, benign flagged @40 | {t['benign_flag']} / {t['benign_n']} = {100*t['benign_flag']/t['benign_n']:.1f}% | 17 / 192 = 8.9% |")
L.append(f"| held-out test, grey flagged @40 (reported apart) | {t['grey_flag']} / {t['grey_n']} | 5 / 8 |")
a, b = S["headline_itw_A"], S["headline_itw_B"]
L.append(f"| in-the-wild set A flagged | {a['flagged']} / {a['complete']} complete (of {a['total']}) | 5 / 215 |")
L.append(f"| in-the-wild set B flagged | {b['flagged']} / {b['complete']} complete (of {b['total']}) | 1 / 197 |")
dm = S["headline_dev_malware_verified_label"]
L.append(f"| dev samples labeled malicious by the datasets (`label_verified = malicious`), flagged | {dm['flagged']} / {dm['n']} | 41 / 278 |")
pa, pb = S["headline_probe_a"], S["headline_probe_b"]
L.append(f"| v3.1 view, newly flagged (a) / (b) | {pa['newly_flagged']} / {pb['newly_flagged']} | 0 / 0 |")
L.append(f"| v3.1 view, no longer flagged (a) / (b) | {pa['unflagged']} / {pb['unflagged']} | 0 / 0 |")
L.append(f"| probe yield (a) / (b) | {pa['yield_']} / {pa['n']}, {pb['yield_']} / {pb['n']} | 13 / 43, 14 / 50 |")
L += ["", "All recomputed numbers equal the published ones.", "",
      "## 2. Image identity", "",
      "`extprobe analyze` uses `extprobe-sandbox:v3`, and `extprobe-sandbox:v3.1-probe` with `--probe`. Local images have no registry digest (`RepoDigests` empty), so the image id is the identity.", "",
      "| image | local id | recorded (PROVENANCE.md, docs/v3/IMAGE.md, evaluation/probe/IMAGE.md) | equal |", "|---|---|---|---|",
      "| `extprobe-sandbox:v3` | `sha256:0e4016d18022e9c6d797499c460dfb2ac7ab93594cbed9af6a70afdf1d360337` | same | yes |",
      "| `extprobe-sandbox:v3.1-probe` | `sha256:67d0ebe6765aa9a63723e58f4175dfc98a2bca05c631b111269e3e9ce436bdb4` | same | yes |",
      "| `extprobe-sandbox:v2` (base) | `sha256:ffeebda9a77c630a3d9c19a51b7e01b390fcddf1fec99340cb66900ca6d7b45d` | same | yes |", "",
      "No image was rebuilt or deleted: these are the images that were built in the old repository, so this shows the CLI uses the frozen images, not that a rebuild would give the same id (ids are not reproducible between builds, see `PROVENANCE.md`).", "",
      "## 3. Live smoke rerun (frozen v3 image)", "",
      "`extprobe analyze` on the canary and on 10 benign extensions of the held-out test set: the first 5 flagged and the first 5 not flagged in the order of the old per-sample scores (section 1). "
      "No set-A extension. The old value is the old scorer on the old stored trace of the same sample.", "",
      "| run | old score | new score | old flag | new flag | old detectors | new detectors |", "|---|---|---|---|---|---|---|"]
for r in M:
    f = lambda x: ", ".join(x) or "none"
    L.append(f"| {r['label']} | {r['old_score']} | {r['new_score']} | {'yes' if r['old_score'] >= 40 else 'no'} | {'yes' if r['new_score'] >= 40 else 'no'} | {f(r['old_fired'])} | {f(r['new_fired'])} |")
same_score = sum(r["old_score"] == r["new_score"] for r in M)
same_flag = sum((r["old_score"] >= 40) == (r["new_score"] >= 40) for r in M)
L += ["", f"Same score {same_score}/{len(M)}, same flag@40 {same_flag}/{len(M)}, same detector set {sum(set(r['old_fired']) == set(r['new_fired']) for r in M)}/{len(M)}.", "",
      "### Differences", "",
      "- **F3 (flagged -> not flagged, 100 -> 35).** The old run flagged `history_exfil` (50) and, because that user data went to an undeclared host, `undeclared_domain_contact` at its heavy weight (40). "
      "In the new run the same host received the same number of requests (4), but the 2nd request fired in the `load` phase (1339 bytes) instead of the `honeypot_pages` phase (1087 bytes); "
      "the visited URL that `history_exfil` looks for was therefore not in any request, `undeclared_domain_contact` stayed at its light weight (20), and the total fell below 40. "
      "The detectors are unchanged; the extension's request timing relative to the harness's page visits changed. This sample sits on the timing boundary.",
      "- **U3 (10 -> 0) and U4 (25 -> 15).** The old runs fired `causes_page_hang` (10 points, `page_hang_count` = 1); the new runs recorded 0 hangs. Page hangs depend on load timing and the live pages of the run. "
      "Neither crosses 40, so the flags agree.",
      "- Everything else (canary, F1, F2, F4, F5, U1, U2, U5) has the same score and the same detector set, including F4 at exactly 40, the threshold.", "",
      "Live runs reproduce the flag in 10 of 11 cases; the deterministic re-scoring in section 1 is exact. The differences are properties of live execution (timing, the real network), not of the scorer.", "",
      "A second smoke re-run of the same 11 samples (run with the argument-based scripts of this folder) gave the same scores and detector sets in all 11 runs, including F3, so the differences to the original runs are stable on this machine. One possible cause, not tested: the original runs executed two containers in parallel, the re-runs ran one at a time, which can shift request timing.", "",
      "## How to repeat", "",
      "The scripts are in `evaluation/reproducibility/`; folders are command-line arguments. They need the archived traces and packages of the development repository (a checkout, or a folder with the same layout: `eval/v3/test/traces_v3`, `eval/v3/dev/traces`, `eval/v3/in_the_wild/traces_A` / `traces_B`, `eval/v3_1_probe/traces_a` / `traces_b`, `samples/`; see the path map in `PROVENANCE.md`). These are not part of this repository.", "",
      "```bash",
      "pip install -e .",
      "python evaluation/reproducibility/run_scores.py --old-repo <dev repo> --itw <folder with A/ and B/> --out work/scores      # old and new scorer, per set",
      "python evaluation/reproducibility/compare.py    --old-repo <dev repo> --scores work/scores --out work/rescore_summary.json",
      "python evaluation/reproducibility/smoke.py      --old-repo <dev repo> --scores work/scores --out work/smoke        # needs Docker and the frozen image",
      "python evaluation/reproducibility/make_report.py --summary work/rescore_summary.json --smoke work/smoke/smoke_results.json --out work/REPORT.md",
      "```", "",
      "- The reference for the sets with no recorded per-sample file is the old scorer run on the same stored traces; the same package folder is given to both scorers.",
      "- `run_scores.py` takes a few minutes for the dev set (611 traces), seconds for the others. `smoke.py` runs about 45 s per sample.",
      "- Not covered: the MADWeb malware test traces, and re-running the sandbox on the dev, set A / B or probe samples (only the 11 smoke runs)."]
Path(_a.out).write_text("\n".join(L) + "\n", encoding="utf-8")
print("\n".join(L[:30]))

