# In-the-wild evaluation of ExtProbe v3: criteria, committed BEFORE any official sample is downloaded

Nothing here has been downloaded or run for the official sets. A feasibility check (60 IDs, 30 + 30, files kept outside
the repository, not reused) preceded this file; it fixed the numbers quoted as context below, not any result.

## 1. Purpose

Describe how the FROZEN v3 behaves on **live** extensions whose label is uncertain. This is **not a recall
measurement**: a Sentry entry only says "suspected" (the Sentry repository warns of false positives, and its `reason`
is a removal category, not a behaviour finding). The figures are flag rates, plus a manual audit of what the flags
turn out to be. No claim of recall, precision or FPR on a labelled population is made from these sets.

## 2. Configuration

- Image `extprobe-sandbox:v3` at the freeze (`eval/v3/FREEZE_v3.md`, tag `v3.0-freeze`), `score_v3.py` as frozen,
  flag = score >= 40. **Profile v3 only** (no v2).
- Each set is run **exactly once**, within **24 hours** of its download. Infrastructure failures (no trace, Docker
  error) are retried by the runner, up to 3 attempts, as in the benign and MADWeb runs; nothing else is re-run, no sample is
  dropped after seeing results, no rule or label changes after the run.
- For every sample the SHA-256 of the downloaded `.crx` and the UTC time of the download are recorded in a committed
  manifest (IDs, hashes, times, version; no package).
- Runner and checks follow `run_malware_test.ps1` (the 13 frozen files/trees must equal `FREEZE_v3.md` at HEAD and at
  the tag; clean working tree; image id; sample checksums).

## 3. Set A: Sentry-recent

- Snapshot: `toborrm9/malicious_extension_sentry` at commit `b3d832c66fccd26f72bbed81678ee87887cbae4e`, file
  `malicious_extensions_detailed.csv` (SHA-256 `c560a18ad879aeaca38758116acae1b41e6de096eadb7d89d6d8c07824cad2a0`,
  7044 rows).
- Population: rows with `store` = Google Chrome (or Chrome) and `insert_date_fmt` from 2026-08-26 to 2026-10-09
  inclusive (the 45 days counted back from the snapshot day). Context from the feasibility check: 1102 rows in the
  window, of which 1099 Chrome; 329 of the 386 `Malware` rows share one insert date (2026-09-03).
- Steps, in this order:
  1. Download each ID with `clients2.google.com/service/update2/crx?response=redirect&prodversion=153.0&acceptformat=crx2,crx3&x=id%3D<ID>%26uc`. Keep the IDs that return a package. Feasibility: 13 of 30 (43 %).
  2. Keep `manifest_version` = 3 (feasibility: 13 of 13).
  3. Remove IDs that are also in the dev malware (313), dev benign (297), held-out benign test (200) or MADWeb (517)
     sets, by extension ID (feasibility: 4 IDs, see Appendix).
  4. At most **40 samples per `insert_date`**: sort the date's IDs ascending, shuffle with `random.Random(2026)`,
     take the first 40.
  5. If more than **300** remain, sort ascending and take `random.Random(2026).sample(ids, 300)`.
- Per sample the manifest records the Sentry `reason`, `source`, `insert_date`, and whether the Chrome Web Store page
  is alive at download time (a `/detail/<name>/<id>` page with "Add to Chrome"; dead = the `empty-title` page or no
  button). Alive or dead is a descriptor, not a label.

## 4. Set B: CWS-random

- Population: the Chrome Web Store sitemap (`/sitemap`, 44 shards). Snapshot: shards listed with `lastmod`
  2026-10-09; 374 508 unique IDs, SHA-256 of the sorted ID list (one per line, `\n`) =
  `5c896d5dff3a4f6221b52adb142a41fc3155fe0f2bc696bee6bf49064cb5521d`. The official draw uses this list; the ID list is
  not committed, only its hash and the selected IDs.
- Exclusions before drawing: every ID in the **whole** Sentry CSV above (not only the 45 days; feasibility: 2850 sitemap
  IDs, about 0.8 %), and every ID in the dev / test / MADWeb sets.
- Draw: sort the remaining IDs ascending, shuffle once with `random.Random(2026)`, and walk the list: download each
  ID; keep it if a package is returned and `manifest_version` = 3; stop at **200** kept samples. All attempts are logged
  (denominator for the download rate and the MV3 rate; feasibility: 30 of 30 downloadable, 29 of 30 MV3, 17 of 30
  without a background).

## 5. Primary measures

- **Set A**: flag rate = flagged / complete runs, with a Wilson 95 % interval, overall and per Sentry `reason`.
- **Set B**: flag rate with a Wilson 95 % interval, and the distribution of harmful / grey / benign / undetermined
  (section 7) among the flagged samples.
- Runs that are not `complete` (failed to load, partial) are listed separately with the reason from
  `run_status.reason`, and a sensitivity row counts them as not flagged.
- **Samples without a background** (no `background` key in the manifest) are reported as their own row in both sets,
  because the harness can see only install-time and page-triggered behaviour from them (about 57 % of the feasibility
  CWS sample).
- Score distribution, detector fire counts and v3 flag rate by manifest background type (service worker / none) are
  reported as descriptive tables.

## 6. Predictions, registered before the run

1. **Search Hijacking** (search provider or new-tab override declared in the manifest) will have a low flag rate: the
   harness performs no search, so the behaviour is not exercised. This is a known blind spot, not a finding to be
   explained away afterwards.
2. **Policy Violation** and **Bundling Unwanted Software** may show no runtime behaviour at all, because their removal
   reasons need not involve a runtime action.
3. `Malware`-reason samples are expected to be flagged more often than the other reasons, but far below 100 %
   (the MADWeb and dev results show that a large part of the malware is silent in a 45-second run).
4. Set B is expected to flag at a rate in the range of the benign held-out set (8.9 % at 40) or higher; a lower rate
   would indicate that live extensions differ from the benign test set in category mix, not that v3 improved.

## 7. Manual audit

- Scope: **every flagged sample in A and B**, plus **20 unflagged samples of Set A** drawn with `random.Random(2026)`
  (sorted IDs, stratified by nothing).
- Two annotators label independently from the trace, the code and the store listing / privacy policy, then report
  Cohen's kappa on the four classes and reconcile. Annotators see the extension's trace and code, not the v3 score
  order of other samples; the 20 unflagged samples are mixed with the flagged ones in a random order, without the flag.
- **harmful**: a behaviour seen in the trace **and** confirmed in the code, **and not disclosed** in the store listing
  or privacy policy: sending browsing history, cookies or page content to a third party; injecting code, affiliate links
  or ads; downloading and executing remote code; hijacking search or the new tab without disclosure.
- **grey**: data collection that is disclosed, or an analytics SDK.
- **benign**: none of the above behaviours.
- **undetermined**: not enough evidence (for example behaviour in the trace but code obfuscated and no disclosure
  found either way).
- VirusTotal verdicts and a later removal from the Chrome Web Store are **supporting evidence only**; they never decide
  a label alone.

## 8. Ethics and handling

- Extension names are anonymised in any paper (IDs shown only as short hashes or labels).
- Samples confirmed harmful are reported to Google (Chrome Web Store) before submission.
- No `.crx` is redistributed; packages and unpacked folders stay outside the repository; only IDs, hashes,
  aggregate tables and anonymised findings are committed.
- Static reading of packages is done in memory or in a temporary folder outside the repository, deleted afterwards.

## Appendix A. Benign dev/test IDs that are in Sentry (45-day window)

Four IDs of the benign dev / test sets are listed by Sentry in the window. They are removed from Set A (rule 3.3) and
kept in their original benign sets; a sensitivity analysis recomputes the benign FPR with them excluded. Labels are
**not** changed.

| set | ID | Sentry reason | Sentry date |
|---|---|---|---|
| dev benign (new) | `<sentry-id>` | Spyware | 2026-09-29 |
| dev benign (new) | `<sentry-id>` | Policy Violation | 2026-09-18 |
| dev benign (new) | `<sentry-id>` | Adware | 2026-10-05 |
| test benign | `<sentry-id>` | Policy Violation | 2026-09-30 |

## Appendix B. Unresolved observation from the feasibility check

One Sentry ID (`<set-A-id>`) was downloadable as an MV3 package although its store page did not
show "Add to Chrome". The cause is **not known** (page rendering, region, or a listing state not recognised by the
check). The alive/dead descriptor in 3 is a heuristic for this reason; such cases are recorded as "package served,
page not alive" and are not interpreted.

## Amendment 1 (2026-10-10, before any official sample is downloaded)

Adds blind labelling, a cap on audit volume and deadlines. Sections 1-8 and both registered predictions in section 6 stand
unchanged.

### A1.1 Blind labelling

- Each sample to be audited (section 7) gets an **automatically generated dossier** containing raw evidence only:
  - requests initiated by the extension: host, method, whether the body or query contains a visited URL, a cookie or an
    identifier (yes/no with the matched field name), and the initiator;
  - tabs opened by the extension (URL chain);
  - DOM nodes injected by the extension (tag, source);
  - replaced page APIs (`fetch`, XHR, `WebSocket`);
  - `runtime.setUninstallURL` and other recorded extension API calls;
  - code excerpts relevant to the above, **at most 80 lines per excerpt**;
  - the link to the Chrome Web Store listing and to the privacy policy, as found in the listing.
- A dossier contains **no score, no detector name, no flag**, and no field that reveals whether the sample was flagged.
- Dossier codes are random, drawn with `random.Random(2026)` over the sorted audit list; flagged and unflagged samples
  (the 20 unflagged of Set A, section 7) are **mixed** in that order.
- The mapping code -> extension ID / flag is kept **outside the repository** and is not opened by the annotators until
  both have finished labelling and the labels are reconciled.

### A1.2 Audit volume

- **Set A**: if more than **60** samples are flagged, **60** of them are audited, chosen with `random.Random(2026)` over
  the sorted flagged IDs (the 20 unflagged samples are added as before). The shares of harmful and of grey among the
  audited flagged samples are reported with a Wilson 95 % interval, and are **not** extrapolated beyond that
  interval. With 60 or fewer flagged samples, all are audited.
- **Set B**: **every** flagged sample is audited.

### A1.3 Deadlines

- Independent labels from both annotators: **2026-10-13**.
- Reconciled labels and kappa: **2026-10-14**.

## Amendment 2 (2026-10-10; added AFTER the samples were downloaded, BEFORE any sandbox run)

Timing, stated plainly: the final sets A and B were downloaded on 2026-10-10 (`docs/samples_manifest_itw_A.csv`,
`_B.csv`). This amendment is written after that download and **before any sandbox run on these sets**. No trace, score,
flag or other behavioural data of any sample of A or B has been seen: the only things looked at were download results,
manifest fields (`manifest_version`, background type) and the state of the store page. (The 4 trial packages of
`run_itw.ps1 -Trial` were spare packages outside A and B; only their exit codes and run statuses were printed.)
The amendment mirrors `eval/expanded/posthoc/LABELING_CRITERIA.md`, Amendment 1.

### A2.1 New label: undisclosed-collection

- **undisclosed-collection**: the **developer's own server** receives browsing activity (URLs, page titles),
  input / usage telemetry tied to a **persistent identifier**, or **account identifiers** (for example an e-mail
  address), and this is **not declared** in the Chrome Web Store privacy-practices section or in the privacy policy.
  (Same definition as `LABELING_CRITERIA.md`, Amendment 1.)
- It is distinct from `harmful`, which in section 7 requires a **third party** as recipient (or injection, remote code
  execution, undisclosed search / new-tab hijack). Collection sent to the developer's own server without disclosure was
  not covered by the original four labels.
- Clarification (before any run): cookies, passwords / session tokens and page content (forms, e-mail, messages) that are
  sent out are **harmful** whether the recipient is a third party or the developer's own server; `undisclosed-collection`
  applies only to page URLs / titles, telemetry tied to a persistent identifier, and account identifiers.

### A2.2 Label order and reporting

- Order of precedence when more than one applies: **harmful > undisclosed-collection > grey > benign > undetermined**.
- The audit results of A and B are reported **both ways**:
  (i) undisclosed-collection counted as harmful;
  (ii) undisclosed-collection **not** counted as harmful.
  Both versions are given in the same table; neither is chosen after the fact as "the" result.
- Cohen's kappa is computed on the five-class labelling; blind dossiers (A1.1) are unchanged.

## Amendment 3 (2026-10-11; written after the run, BEFORE any trace or score is read)

Timing, stated plainly: the sandbox run of A and B has finished (exit 0, no incomplete sample). At the time of writing
**no trace, score, flag or run status of any sample has been read**; the only things known are the exit status and the counts
"215 / 200 samples, 0 incomplete" printed by the runner. This amendment adds a label tier for Set A and fixes how it is
obtained.

### A3.1 Tiers of Set A

- **T2 (vendor-reported)**: the sample is named (by extension ID or name) in a report published **between 2026-08-01 and
  2026-10-10** by a security vendor or researcher that **analyses the behaviour** of the extension(s): for example Socket,
  Secure Annex, OX Security, LayerX, Koi, Palant, Kaspersky, or a news article (BleepingComputer and similar) that
  explicitly cites such a vendor report. A news item that only repeats a list without an analysis is **not** T2.
- **Sentry-only**: every other sample of Set A (the Sentry entry is the only evidence of suspicion).
- A report dated before 2026-08-01 does not make a sample T2, even if it names the extension.
- The tier is a descriptor of the external evidence, not a label; it does not change the labelling of section 7.

### A3.2 Blind lookup

- The lookup uses **only** the extension ID, the extension name and web sources (the Sentry `source` field of the
  manifest and web search). It does not use any run result, so it cannot depend on the flag.
- Result: `eval/v3/in_the_wild/label_tiers_A.csv` (ID, tier, source URL), committed after the lookup.

### A3.3 Reporting

- The flag rate (score >= 40, Wilson 95 %) of **T2 alone** is reported next to that of Sentry-only samples and of all of
  Set A.
- Results are published as aggregates; per-sample flags are kept outside the repository until the labels are reconciled.

## Amendment 4 (2026-10-12, before any labeling)

Raters: the two human raters are replaced by two LLM agents from different vendors (Rater A: Claude, fresh session;
Rater B: Gemini via Antigravity or GPT via Codex). Each agent runs in a fresh session, receives only a copy of the
dossiers (no mapping.csv), LABELING_GUIDE.md and a fixed prompt (verbatim in labeling_llm/PROMPT.md). Model name, version
and run date are recorded. Cohen's kappa between the two agents is reported. Disagreements are adjudicated by one
author, with a written reason; the adjudicator does not see mapping.csv before adjudication is complete. Final label =
agreed label or adjudicated label.
