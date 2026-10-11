# v3 freeze (tag `v3.0-freeze`)

**This configuration is fixed before the held-out test set is run.** Nothing below changes after the
first test trace exists. The test set (`eval/v3/test_set/`, 200 extensions, `TEST_SET_CRITERIA.md`) is run
once, with `run_v3_test.ps1`, on exactly this configuration, and its results are reported whatever they
are. `run_v3_test.ps1` refuses to start unless HEAD is the tag `v3.0-freeze` and every file or tree in the
table below has the recorded id.

## Image

| | id |
|---|---|
| `extprobe-sandbox:v3` | `sha256:0e4016d18022e9c6d797499c460dfb2ac7ab93594cbed9af6a70afdf1d360337` (`eval/v3/IMAGE.md`, round 3) |
| base `extprobe-sandbox:v2` / `extanalyze-sandbox:v2` (v2 profile, unchanged) | `sha256:ffeebda9a77c630a3d9c19a51b7e01b390fcddf1fec99340cb66900ca6d7b45d` (`FREEZE.md`) |

## Scoring

- `eval/v3/score_v3.py`: last changed in `9b86c0c` (scoring amendment 1). Rules and weights:
  `eval/v3/SCORING_v3.md`, pre-registered in `a11d3f6`, amendment 1 in `9b86c0c`, both before the dev run.
  Weights were not changed after the dev run or after any later analysis.
- `sandbox_v3/` (all v3 sensors and the profile): last changed in `2513c16` (round 3), before the dev run.
- **Flag threshold: score ≥ 40** (levels: ≥ 90 CRITICAL, ≥ 70 HIGH, ≥ 40 MEDIUM, ≥ 15 LOW). Static score is
  displayed and not added.
- score = min(100, sum of the weights of the signals that fired):

| detector | fires when | weight |
|---|---|---|
| `credential_exfil` | honeypot marker in an extension-initiated request | 80 |
| `history_exfil` | visited URL or title (path ≠ `/`, title ≥ 8 chars) in an extension-initiated request to another registrable domain | 50 |
| `affiliate_hijack` | v2 rule; Amazon `tag` only on `amazon.*` | 40 |
| `undeclared_domain_contact` with user data | undeclared host receives a visited URL / title, a honeypot marker or a persistent UUID | 40 |
| `local_harvest` | honeypot marker in the extension's storage | 30 |
| `undeclared_domain_contact` without user data | 15, +5 per extra host, at most 20 | 15–20 |
| `unsolicited_tab` | tab opened by the extension (not the harness, no web-page opener) | 15 |
| `script_injection` | cross-origin SCRIPT / IFRAME created by the extension | 15 |
| `page_api_hooking` | `fetch` / XHR / `WebSocket` replaced or non-native on a harness page | 15 |
| `beaconing` | v2 rule on extension-initiated requests | 5 (+5 if the host is undeclared) |
| `causes_page_hang` | v2 rule | 10 |

- v2 side of the comparison: `worker/risk.py` at `v2.0-freeze` on traces of the v2 profile (image above),
  threshold 40, exactly what `eval/rescore.py` computes. Unchanged.

## Test set

- 200 extensions: `eval/v3/test_set/selected_test.csv`, SHA-256 of the sorted ids
  `3201b45404855f937a7170ec1c61c87b02ec76b07cfd5af014fb7b014c7a7045`; 192 benign + 8 grey, labels from the
  store listing of 2026-10-08, fixed before the download; 200 / 200 downloaded
  (`docs/samples_manifest_benign_test.csv`). Selection: `eval/v3/test_set/README.md`.
- Analysis: `eval/v3/test_analysis.py` (fixed here): FPR @40 with Wilson 95 %, grey apart, by category,
  weighted by the development mix (supplementary), thresholds 15–60, score distribution, FP list.
- A trace that fails for an infrastructure reason (no trace, Docker error) is re-run by the same script, up to
  3 attempts. No other re-run, no sample dropped, no label or rule changed after seeing results.

## Frozen files (git ids at the commit that is tagged; checked by `run_v3_test.ps1`)

| path | git id | role |
|---|---|---|
| `eval/v3/score_v3.py` | `9cfbecfeb9d4d2af62cd8cf606ae6c3d362eb4d7` | v3 scoring |
| `eval/v3/SCORING_v3.md` | `e599c966414b594fa9e5dbbf5dd7803fb293987c` | rules, weights, amendment 1 |
| `eval/v3/IMAGE.md` | `16bc6c0f46c5bdbba358a8bb4a3d8fb4c6c50d63` | image id |
| `sandbox_v3` | `29872ca2bf39b19510137d559841154af0bed499` | v3 profile (tree) |
| `eval/v3/run_v3.py` | `b9f88808d1e7eddac458c2fa1693f1f41e1436e1` | v3 runner |
| `eval/v3/test_analysis.py` | `7a283db2fb9ab848650835118b5af25fb0eb9369` | test analysis |
| `run_v3_test.ps1` | `a89fc158c31edd4abc00ba15adf87bf0bd5f7372` | test runner |
| `eval/v3/test_set/selected_test.csv` | `4f1d12254e6ba73ebe43af749ad66cab425929e1` | selected ids and labels |
| `eval/v3/test_set/selected_test.sha256` | `3392a007ea8be60f30106b13dc2bbbf60980c405` | id-list hash |
| `docs/samples_manifest_benign_test.csv` | `0b1e8f00507d0d159214324fa00169814147c7e1` | file hashes |
| `worker` | `a137edd913fe47f8677bf8d3cb480915f083c995` | v2 scoring (tree, = `v2.0-freeze`) |
| `sandbox` | `b0c8c670ce1b643b1b5f122ec28186b73a92ffb4` | v2 profile (tree, = `v2.0-freeze`) |
| `eval/batch_run.py` | `7482442b5930f936cd1a0b521037d2e4aafa3d2b` | v2 runner |

## Reference: development run (not the test)

`eval/v3/dev/results.md`: v3 FPR @40 on the 246 new benign dev samples 16.7 % (v2 51.2 %); recall on the
verified malware 14.7 %. `eval/v3/audit/report.md` and `eval/v3/explore/report.md` explain why recall is
limited; neither changed the rules above.

## Commands

```
git tag v3.0-freeze                         # after this file is committed
powershell -ExecutionPolicy Bypass -File run_v3_test.ps1 -DryRun
powershell -ExecutionPolicy Bypass -File run_v3_test.ps1
```
