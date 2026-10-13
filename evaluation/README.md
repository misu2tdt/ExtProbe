# evaluation/

Records of the evaluations. **Most scripts here are the analysis code as it was run** (they read recorded traces and private inputs that are
not in this repository); only the items marked *runs here* work from the repository alone.

| directory | content |
|---|---|
| `manifests/` | sample lists (ids + SHA-256); the in-the-wild set A list is not published |
| `v2/` | paper-number pipeline of the v2 profile. `precomputed/` = the four result files (`summary.csv` with benign extensions anonymised, `metrics_summary.json`, `pr_roc_points_{raw,verified}.csv`). `check_paper_numbers.py --precomputed` *runs here*; the other scripts need the recorded traces in `data/v2_results/` (override: `EXTPROBE_V2_RESULTS`) |
| `v2/ab/`, `v2/baseline/`, `v2/expanded/`, `v2/benign_ext/`, `v2/ablation_stimulus/`, `v2/sensitivity/` | v2 results and selection records |
| `v3/` | v3 criteria, selection, labels, audit, dev / test / malware-test / in-the-wild results (`results.md`), operating points. `as_run/` = frozen scripts of the held-out test run, byte-identical, **not runnable in this layout** |
| `v3/in_the_wild/` | criteria + amendments, labeling guide, aggregate results and blind-labelling summary (`labeling.md`; `ratings.csv` = anonymous per-dossier labels of the two raters (dossier code, flagged yes/no, rater A, rater B, final); `compute_kappa.py --ratings ratings.csv` gives 24/26 and kappa 0.862); `as_run/` = download / dossier / run scripts |
| `probe/` | v3.1-probe: `CRITERIA.md` (+ amendments), `DESIGN.md`, `IMAGE.md`, `results.md`, `posthoc.md`; `run_probe.py` runs the probe image; `as_run/` = trial scripts; `provenance_counts.md` + `provenance_counts.py` = requests per attribution pattern on the canary/demo fixture (100 of 100 correct, 9 patterns); `popup_recount.md` + `popup_recount.py` = recount of declared popups on the 610 development traces (291 / 140 / 145; supersedes the earlier counts quoted in `DESIGN.md`) |
| `v3/operating_points/paired_v2_v3.md` + `paired_v2_v3.py` = v2@81 and v3@40 on the 278 development samples with both runs (2x2 table, McNemar exact); `v3/dev_silence/` | `results.md` + `count_silence.py`: how many of the 278 completed malicious-labeled development runs have no extension-initiated request (151, 54.3%), an install-time tab or uninstall URL (219, 78.8%), or both (123, 44.2%); the script takes the traces folder as an argument |
| `reproducibility.md`, `reproducibility/` | does this repository reproduce the development repository's results? Re-scoring of 1,319 archived traces (0 mismatches), image id match, 11-run live smoke re-run; the scripts take folders as arguments |
| `provenance_benchmark/` | controlled benchmark of the request-attribution mechanism (synthetic, ground truth by construction) |
| `malware_test/` | runner script of the MADWeb test as it was run |

Environment variables: `EXTPROBE_V2_RESULTS` (recorded v2 traces, default `data/v2_results`), `EXTPROBE_VERDICTS_LOCAL`
(manual verdicts that name benign extensions, default `data/verdicts_local.json`, available on request).

## Label terminology

Terms such as "verified-malicious", "malicious-confirmed", "confirmed malicious" and the column `label_verified` come from the provenance categories of the source datasets (human-reviewed versus news-sourced) and from the label review recorded in `v3/labels/`. They do **not** mean that ExtProbe or the authors verified malicious behavior. Historical files keep their original wording.
