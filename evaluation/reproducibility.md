# Reproducibility check: this repository against the development repository

Does this repository reproduce the results of the private development repository? Counts only: no extension ID, name or domain appears on this page. The development repository was read-only for the check (its `git status` stayed clean; the scripts ran with `PYTHONDONTWRITEBYTECODE=1`). Re-scoring covers 1,319 archived traces; the live re-runs are 11 samples.

**Summary.** Re-scoring the archived traces reproduces every score and flag exactly (1,319 traces, 0 mismatches). Live re-runs can differ for timing-dependent detectors: 10 of 11 flags were identical in a smoke re-run.

## 1. Re-scoring of the stored traces (deterministic)

Reference = the old repository's own scorer (`eval/v3/score_v3.py`, `eval/v3_1_probe/score_v31.py`) run on the same stored traces with the same package folder; new = `extprobe score-v3` / `extprobe score-v31` of this repository. Both wrote the full result as JSON (`--out`). "Identical full result" compares the whole result object (score, level, fired detectors, every signal with weights and details, static display).

| set | n compared | identical score | identical flag@40 | identical full result | mismatches |
|---|---|---|---|---|---|
| held-out benign test set | 200 | 200 | 200 | 200 | 0 |
| dev set | 611 | 611 | 611 | 611 | 0 |
| in-the-wild set A | 215 | 215 | 215 | 215 | 0 |
| in-the-wild set B | 200 | 200 | 200 | 200 | 0 |
| v3.1-probe trial (a), score_v31 | 43 | 43 | 43 | 43 | 0 |
| v3.1-probe trial (b), score_v31 | 50 | 50 | 50 | 50 | 0 |

**Mismatches: none in any set.** The key sets of old and new results are identical in every set.

### Against a recorded per-sample file (dev set only)

The old repository keeps one recorded per-sample file for the dev set (`eval/v3/dev/summary_v3.csv`: 610 rows, 9 not complete). For the 601 complete rows: risk score identical 601/601, flag@40 identical 601/601, fired-detector set identical 601/601. The dev trace folder has 611 sample folders: the 610 recorded ones plus one `canary` smoke folder.

For the other sets the old repository records only aggregates (blind labelling: no per-sample score is stored), so the reference for them is the old scorer re-run on the stored traces, plus the published aggregates below.

### Headline numbers recomputed from the new scores

| quantity | recomputed | published (evaluation/) |
|---|---|---|
| held-out test, benign flagged @40 | 17 / 192 = 8.9% | 17 / 192 = 8.9% |
| held-out test, grey flagged @40 (reported apart) | 5 / 8 | 5 / 8 |
| in-the-wild set A flagged | 5 / 215 complete (of 215) | 5 / 215 |
| in-the-wild set B flagged | 1 / 197 complete (of 200) | 1 / 197 |
| dev samples labeled malicious by the datasets (`label_verified = malicious`), flagged | 41 / 278 | 41 / 278 |
| v3.1 view, newly flagged (a) / (b) | 0 / 0 | 0 / 0 |
| v3.1 view, no longer flagged (a) / (b) | 0 / 0 | 0 / 0 |
| probe yield (a) / (b) | 13 / 43, 14 / 50 | 13 / 43, 14 / 50 |

All recomputed numbers equal the published ones.

## 2. Image identity

`extprobe analyze` uses `extprobe-sandbox:v3`, and `extprobe-sandbox:v3.1-probe` with `--probe`. Local images have no registry digest (`RepoDigests` empty), so the image id is the identity.

| image | local id | recorded (PROVENANCE.md, docs/v3/IMAGE.md, evaluation/probe/IMAGE.md) | equal |
|---|---|---|---|
| `extprobe-sandbox:v3` | `sha256:0e4016d18022e9c6d797499c460dfb2ac7ab93594cbed9af6a70afdf1d360337` | same | yes |
| `extprobe-sandbox:v3.1-probe` | `sha256:67d0ebe6765aa9a63723e58f4175dfc98a2bca05c631b111269e3e9ce436bdb4` | same | yes |
| `extprobe-sandbox:v2` (base) | `sha256:ffeebda9a77c630a3d9c19a51b7e01b390fcddf1fec99340cb66900ca6d7b45d` | same | yes |

No image was rebuilt or deleted: these are the images that were built in the old repository, so this shows the CLI uses the frozen images, not that a rebuild would give the same id (ids are not reproducible between builds, see `PROVENANCE.md`).

## 3. Live smoke rerun (frozen v3 image)

`extprobe analyze` on the canary and on 10 benign extensions of the held-out test set: the first 5 flagged and the first 5 not flagged in the order of the old per-sample scores (section 1). No set-A extension. The old value is the old scorer on the old stored trace of the same sample.

| run | old score | new score | old flag | new flag | old detectors | new detectors |
|---|---|---|---|---|---|---|
| canary | 100 | 100 | yes | yes | credential_exfil, local_harvest, unsolicited_tab | credential_exfil, local_harvest, unsolicited_tab |
| F1 | 65 | 65 | yes | yes | undeclared_domain_contact, unsolicited_tab, script_injection, page_api_hooking | undeclared_domain_contact, unsolicited_tab, script_injection, page_api_hooking |
| F2 | 45 | 45 | yes | yes | unsolicited_tab, script_injection, page_api_hooking | unsolicited_tab, script_injection, page_api_hooking |
| F3 | 100 | 35 | yes | no | history_exfil, undeclared_domain_contact, unsolicited_tab | undeclared_domain_contact, unsolicited_tab |
| F4 | 40 | 40 | yes | yes | undeclared_domain_contact | undeclared_domain_contact |
| F5 | 100 | 100 | yes | yes | history_exfil, undeclared_domain_contact, unsolicited_tab, script_injection | history_exfil, undeclared_domain_contact, unsolicited_tab, script_injection |
| U1 | 0 | 0 | no | no | none | none |
| U2 | 30 | 30 | no | no | undeclared_domain_contact, unsolicited_tab | undeclared_domain_contact, unsolicited_tab |
| U3 | 10 | 0 | no | no | causes_page_hang | none |
| U4 | 25 | 15 | no | no | undeclared_domain_contact, causes_page_hang | undeclared_domain_contact |
| U5 | 0 | 0 | no | no | none | none |

Same score 8/11, same flag@40 10/11, same detector set 8/11.

### Differences

- **F3 (flagged -> not flagged, 100 -> 35).** The old run flagged `history_exfil` (50) and, because that user data went to an undeclared host, `undeclared_domain_contact` at its heavy weight (40). In the new run the same host received the same number of requests (4), but the 2nd request fired in the `load` phase (1339 bytes) instead of the `honeypot_pages` phase (1087 bytes); the visited URL that `history_exfil` looks for was therefore not in any request, `undeclared_domain_contact` stayed at its light weight (20), and the total fell below 40. The detectors are unchanged; the extension's request timing relative to the harness's page visits changed. This sample sits on the timing boundary.
- **U3 (10 -> 0) and U4 (25 -> 15).** The old runs fired `causes_page_hang` (10 points, `page_hang_count` = 1); the new runs recorded 0 hangs. Page hangs depend on load timing and the live pages of the run. Neither crosses 40, so the flags agree.
- Everything else (canary, F1, F2, F4, F5, U1, U2, U5) has the same score and the same detector set, including F4 at exactly 40, the threshold.

Live runs reproduce the flag in 10 of 11 cases; the deterministic re-scoring in section 1 is exact. The differences are properties of live execution (timing, the real network), not of the scorer.

A second smoke re-run of the same 11 samples (run with the argument-based scripts of this folder) gave the same scores and detector sets in all 11 runs, including F3, so the differences to the original runs are stable on this machine. One possible cause, not tested: the original runs executed two containers in parallel, the re-runs ran one at a time, which can shift request timing.

### Linux (GitHub Codespaces)

The same 11 runs were repeated on a Linux host. Environment: GitHub Codespaces (x86_64), Docker 29.8.2 with docker-in-docker, image extprobe-local:v3 built from source with docker/build.py, container started by extprobe analyze with the release flags (--cap-add FOWNER, --cap-add SYS_CHROOT, Playwright's seccomp profile; the Chromium sandbox stays enabled).

| run | original | Windows re-run | Linux re-run | Linux = Windows (flag and detectors)? |
|---|---|---|---|---|
| F1 | FLAG 65 | FLAG 65 | FLAG 65 | yes |
| F2 | FLAG 45 | FLAG 45 | FLAG 45 | yes |
| F3 | FLAG 100 | no 35 | no 35 | yes |
| F4 | FLAG 40 | FLAG 40 | FLAG 40 | yes |
| F5 | FLAG 100 | FLAG 100 | FLAG 100 | yes |
| U1 | no 0 | no 0 | no 0 | yes |
| U2 | no 30 | no 30 | no 30 | yes |
| U3 | no 10 | no 0 | no 0 | yes |
| U4 | no 25 | no 15 | no 15 | yes |
| U5 | no 0 | no 0 | no 0 | yes |
| canary | FLAG 100 | FLAG 100 | FLAG 100 | yes |

Summary (11 runs, all with exit code 0): same flag as the Windows re-run 11/11, same detectors 11/11, same score 11/11; same flag as the original run 10/11, same detectors 8/11 (the differences are F3, U3 and U4 described above).

Platform and image build do not change the results here: the differences from the original run are shared by both re-runs.

## How to repeat

The scripts are in `evaluation/reproducibility/`; folders are command-line arguments. They need the archived traces and packages of the development repository (a checkout, or a folder with the same layout: `eval/v3/test/traces_v3`, `eval/v3/dev/traces`, `eval/v3/in_the_wild/traces_A` / `traces_B`, `eval/v3_1_probe/traces_a` / `traces_b`, `samples/`; see the path map in `PROVENANCE.md`). These are not part of this repository.

```bash
pip install -e .
python evaluation/reproducibility/run_scores.py --old-repo <dev repo> --itw <folder with A/ and B/> --out work/scores      # old and new scorer, per set
python evaluation/reproducibility/compare.py    --old-repo <dev repo> --scores work/scores --out work/rescore_summary.json
python evaluation/reproducibility/smoke.py      --old-repo <dev repo> --scores work/scores --out work/smoke        # needs Docker and the frozen image
python evaluation/reproducibility/make_report.py --summary work/rescore_summary.json --smoke work/smoke/smoke_results.json --out work/REPORT.md
```

- The reference for the sets with no recorded per-sample file is the old scorer run on the same stored traces; the same package folder is given to both scorers.
- `run_scores.py` takes a few minutes for the dev set (611 traces), seconds for the others. `smoke.py` runs about 45 s per sample.
- **Linux smoke re-run** (GitHub Codespaces or any Linux x86-64 host with Docker; the container cannot see `/tmp` under docker-in-docker, so output stays inside the repository):

```bash
python docker/build.py                                                   # image extprobe-local:v3
bash evaluation/reproducibility/linux_smoke_run.sh BUNDLE_DIR            # BUNDLE_DIR/expected.csv + BUNDLE_DIR/samples/F1.crx ... U5.crx; canary needs no file
python evaluation/reproducibility/linux_smoke_compare.py BUNDLE_DIR/expected.csv extprobe-out/linux_smoke/results.csv
```

  Output goes to `extprobe-out/linux_smoke/` (`OUT`, `IMAGE`, `PYTHON` and `LABELS` can be set; see the header of the script). **The 10 `.crx` files are not distributed** (no packages are published): obtain the same packages separately. The sha256 of every package of the held-out benign set is in `evaluation/manifests/samples_manifest_benign_test.csv`; the mapping from the labels F1-F5 and U1-U5 to those packages (`expected.csv`, which also holds the expected scores) is not published and is available from the authors. Without the packages, `LABELS=canary` still checks the canary.
- Not covered: the MADWeb malware test traces, and re-running the sandbox on the dev, set A / B or probe samples (only the 11 smoke runs).
