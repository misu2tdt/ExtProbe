# PROVENANCE

This repository is the public release of work that was developed in a private repository with full history. The history is **not**
published; this file records what a reader needs to check that the criteria were fixed before the runs, and which files and images
were used. Dates are git author dates on the author's machine (the local clock is only trusted for the order of commits).

* Check the frozen files: `python -m extprobe verify-freeze` (sha256 of content, list in `PROVENANCE/frozen_files.tsv`).
* Text of every version of the criteria documents: `PROVENANCE/criteria_history/` (one file per commit).
* Differences between published files and the private originals: `PROVENANCE/modifications.tsv` (sha256 of both forms and the reason).

## 1. Tags and freezes

| tag / freeze | commit | date | what it fixes |
|---|---|---|---|
| `v1.0-soict` | `2fee798` | 2026-09-20 21:41 | paper submission snapshot |
| `v2.0-freeze` | `92dd5c1` | 2026-10-03 00:35 | v2 detectors, weights, A/B design, images (`docs/provenance/FREEZE_v2.md`) |
| `v2.1-extprobe` | `7f5e666` | 2026-10-07 02:20 | rename to ExtProbe, no behaviour change |
| `v3.0-freeze` | `ad38274` | 2026-10-08 19:45 | v3 image id, scoring commit, file blobs, threshold 40, detectors and weights, held-out test-set hash (`docs/v3/FREEZE_v3.md`) |

## 2. Criteria and amendments (written before the runs they govern)

The sha256 is of the document text at that commit in the private repository.

### 2.1 v3 in-the-wild evaluation (`evaluation/v3/in_the_wild/CRITERIA.md`)

| commit | date | sha256 of the text | subject |
|---|---|---|---|
| `82bb873` | 2026-10-10 14:09 | `dbfda004d3bab7f9b7aa107e30f1973f08b32f1d62d92a3a0f6fa4e9f57227ec` | v3 in-the-wild evaluation: criteria (Sentry-recent set A, CWS-random set B), before any officia (published copy differs from the original: one set-A id replaced by `<set-A-id>`; original sha256 shown) |
| `e8cf49e` | 2026-10-10 14:17 | `8349fa1dae3cdca8a86b2fca7b849de9275a8e82789c68693724db3214bcd3af` | v3 in-the-wild criteria, amendment 1: blind dossiers, audit cap of 60 flagged in set A, deadlin (published copy differs from the original: one set-A id replaced by `<set-A-id>`; original sha256 shown) |
| `7fdded9` | 2026-10-10 15:18 | `b10e7576734e1b4382072207d1f7e1177ac6d54d335a405ec36cdc3c6476f940` | v3 in-the-wild criteria, amendment 2: label undisclosed-collection (added after the download, b (published copy differs from the original: one set-A id replaced by `<set-A-id>`; original sha256 shown) |
| `a7b76ac` | 2026-10-10 15:26 | `45688eddc1e05d70bd6247e58b3e751740572f1b4ef903e6790626867de0e9ab` | v3 in-the-wild criteria, amendment 2 clarification: cookies, credentials and page content sent  **text inserted inside the earlier text, nothing deleted** (see below) (published copy differs from the original: one set-A id replaced by `<set-A-id>`; original sha256 shown) |
| `6bc7e62` | 2026-10-10 18:26 | `91a27a3b88683e06fe4aece965a09c0f75c657867487e38c4ff72b9635d87ba6` | v3 in-the-wild criteria, amendment 3: T2 / Sentry-only tiers for set A (written after the run,  (published copy differs from the original: one set-A id replaced by `<set-A-id>`; original sha256 shown) |

**Exception.** Commit `a7b76ac` is not purely append-only: it **inserted 3 lines in the middle of amendment 2** (no line was deleted), 8 minutes
after `7fdded9` and before any run ("before any run" in its message). All other steps only append to the end of the previous text.
Amendment 3 (`6bc7e62`) was written **after the run**, before any trace or score was read (its commit message says so); it adds the
T2 / Sentry-only tiers.
One extension id of set A that appeared in Appendix B of the criteria is replaced by `<set-A-id>` in the published copies (original sha256 above).

### 2.2 v3.1-probe trial (`evaluation/probe/CRITERIA.md`)

| commit | date | sha256 of the text | subject |
|---|---|---|---|
| `9be0281` | 2026-10-11 02:29 | `fbea34b550359904a88cdbe2eb9d319f45f20646b478705406737af5797d69d0` | v3.1-probe step 3: trial criteria and selection (committed before any trial run) |
| `2420e08` | 2026-10-11 11:47 | `83aef90f751728e0731c2d4fbecab1694e2b03f2664c9b7d6f8bb56d644b3c77` | v3.1-probe CRITERIA amendment 1 (before any official run): proxy guard image without NET_ADMIN, |
| `2e01043` | 2026-10-11 13:25 | `2c239295c0eb4b90e8c8503f593b03e55f345a16226ef3e4d2bcf7eaf27bc0e8` | v3.1-probe review 2 item 5: image sha256:67d0ebe6... recorded in IMAGE.md; CRITERIA amendment 2 |
| `bc696c6` | 2026-10-11 13:32 | `e03eaa7ae042b0efcad256bc2ccef3ea7d826fbe0b019082ac50f297923d0218` | v3.1-probe CRITERIA amendment 3 (before any official run): beaconing unstable near its threshol |

Each version only appends to the previous one. Amendments 1-3 were committed before the official run; the results were committed later
(section 3).

### 2.3 Other criteria documents

SCORING_v3 (`docs/v3/SCORING_v3.md`):

| commit | date | sha256 | subject |
|---|---|---|---|
| `a11d3f6` | 2026-10-08 03:02 | `251b0ca6f4f895208de7f8c98c82e13cc20d2aff1d0a7314f89a0c5946945356` | v3 scoring rules and weights (SCORING_v3.md), fixed before the dev run |
| `9b86c0c` | 2026-10-08 10:19 | `cbef8f8325e1d6b946adf2dd0068698a81ef7f9cffb5f4a23fd50b1d22f6f611` | v3 scoring amendment 1 (before the dev run): SW requests = CDP SW records only; tab <-> SW call |

Single-commit documents:

| document | commit | date | sha256 |
|---|---|---|---|
| v3 held-out benign test set criteria | `3b18114` | 2026-10-08 10:27 | `6d206076a4fb67f55cf652ad00e069c34c5643baba5833a54f26936b08f9e22a` |
| v3 MADWeb malware test criteria | `a059d36` | 2026-10-10 02:06 | `7afd4583789ca782386d6570a8a0ac9b97de877d7679bfed2d72c31d17cb54e9` |
| v3 dev audit criteria | `65f5bd0` | 2026-10-08 14:32 | `b871b3d127df0aec5d53d90675bce81a0060dcca7912f1c468bd8831a1e81d6d` |
| v2 expanded evaluation analysis plan | `09c69e4` | 2026-10-07 14:51 | `6bc39037c9677c5c7a41d4a6e1b2267bc56d16bb2ebfa2780a1d6bb7fd692ec2` |
| v2 benign-set expansion criteria (version 6798dae) | `6798dae` | 2026-10-07 13:49 | `759daec9f715144f47e51d7f103c326e0170f15433913b852ced9f5e3287be6c` |
| v2 benign-set expansion criteria (version 06443ed) | `06443ed` | 2026-10-07 14:13 | `09092c385df21520498cdbb5941e5743d12ef86eb862bb0869bf536d8e12e4b2` |
| v3 held-out test selection (`evaluation/v3/test_set/selected_test.sha256`, seed 2027) | `2b5bc18` | 2026-10-08 18:47 | `d496dcf9fbf9c9e6e5b02be6eac6592828c036d672c50620463a13cc38118ccc` |

Note on the v2 benign-set expansion criteria: its second version (`06443ed`, the recorded decisions, 2026-10-07 14:13) is **not** append-only (28 lines added and 10 lines of the first version (`6798dae`, 13:49) changed or removed); both were committed before any download of that set (per their commit messages).

## 3. Results (committed after the criteria)

| result | commit | date |
|---|---|---|
| v3 dev results, operating points, held-out test results | `5329b63` | 2026-10-10 12:34 |
| v3 dev audit report | `9e4f2da` | 2026-10-08 14:52 |
| MADWeb malware test results | `64eed1e` | 2026-10-10 15:18 |
| in-the-wild results (aggregates only) | `b6214b2` | 2026-10-10 18:30 |
| v3.1-probe trial `results.md` (unchanged output of `analysis.py`) | `4886e2d` | 2026-10-11 17:55 |
| v3.1-probe post-hoc analysis, erratum | `46cd529`, `03cabd9` | 2026-10-11 17:59, 18:42 |
| v2 expanded evaluation results | `4ebe024` | 2026-10-07 21:36 |

`evaluation/probe/posthoc.md` is post-hoc and was not registered in advance.

## 4. Images

Local docker image ids are **not reproducible** between builds (layer contents include the build context, `apt-get` packages are not
pinned). What pins the builds: the base-image digests, `sandbox/base/requirements.v2.txt` (playwright 1.63.0, websockets 12.0) and the sha256
of every file in `PROVENANCE/frozen_files.tsv`. A rebuilt image will have a different id.

| image | id used for the evaluations | built from |
|---|---|---|
| `extprobe-sandbox:v3.1-probe` | `sha256:67d0ebe6765aa9a63723e58f4175dfc98a2bca05c631b111269e3e9ce436bdb4` | `extprobe-sandbox:v3` + `sandbox/probe/` + managed policy `ProxyMode=direct` |
| `extprobe-sandbox:v3` | `sha256:0e4016d18022e9c6d797499c460dfb2ac7ab93594cbed9af6a70afdf1d360337` | `extprobe-sandbox:v2` + `sandbox/v3/` |
| `extprobe-sandbox:v2` (earlier tag `extanalyze-sandbox:v2`) | `sha256:ffeebda9a77c630a3d9c19a51b7e01b390fcddf1fec99340cb66900ca6d7b45d` | `mcr.microsoft.com/playwright/python:v1.63.0-jammy@sha256:47a65aee64780daa8bad02b37e0ef14902851a3aa7ad0153234f784eb12422b0` (Chrome for Testing 153.0.8010.12) |
| corpus profile (paper) | `sha256:31f312f7e0d2a406030cab12f25ca469367c4a3de12bfcb2177ef7496b2bab64` | `mcr.microsoft.com/playwright/python:v1.40.0-jammy@sha256:5656288def8576b31903becabac255b19bc01ee961ddb499de3418d52f55ed2a` (Chromium 120); its Dockerfile is not carried |
| superseded probe images (never used for the official trial) | `sha256:8348c13a1c220775ae0fccada1173994227562794cd3824cfab91d22b38e5b3d` (iptables egress gate), `sha256:2ae86e6e0042ac66de2a6deeaef77641189e682f7163212db2f03ec58b24e7c8` (before the second review) | |

## 5. What is not published, and what was changed for publication

* **In-the-wild set A** (215 extensions): no per-extension data. `evaluation/v3/in_the_wild/set_A_summary.md` gives the count, the sha256 of the
  sorted id list, and the distribution of reasons and tiers; the list is available on request. The trial lists of v3.1-probe are subsets of
  set A; `evaluation/probe/CRITERIA.md` holds their sha256. 4 rows of the held-out candidate listing that coincide with set A are redacted.
* **Benign extensions that were flagged (false positives)**: names and ids are replaced by pseudonyms (`benign-ext-NNN`, `benign-corpus-NN`,
  `mislabel-NN`) in result tables and in the precomputed `summary.csv`; contacted hosts in those table rows are redacted; the manual verdicts
  that name them are kept in a private file read by `evaluation/v2/apply_verified_labels.py` when present. The metrics are unaffected
  (`check_paper_numbers.py --precomputed`).
* **Recorded traces** (354 for the v2 paper numbers) are not in the repository (release asset).
* **Sample files** are not published.
* **Not carried**: the v2 service (API, Celery worker, compose stack), the corpus-profile Dockerfile, `eval/batch_run.py` and other v2 runners,
  exploration and post-hoc v2 scripts, v3 smoke / exploration / feasibility material, `eval/baseline_extanalysis/comparison.md` (pending review).
  Frozen files that are not carried are listed as `NOT CARRIED` in `PROVENANCE/frozen_files.tsv`.
* **Scripts that need private inputs** (ids, packages, dossiers, git history) are kept byte-identical in `as_run/` folders as records and are not
  runnable in this layout.
