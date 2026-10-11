# Sources used for the label tiers

Accessed 2026-10-10. Only metadata was fetched (blobless `git clone --no-checkout`, then `git show <commit>:<path>` for the listed files). No `.crx` was downloaded; the MADWeb zips were fetched as git blobs into a temporary folder outside the repo and only their file list (zip central directory) was read, nothing was extracted. The raw metadata files are **not** committed (licences below; the sizes are large); `build_labels.py --src` documents the layout needed to regenerate.

| source | pinned commit (date) | licence | files read | records |
|---|---|---|---|---|
| GherardoFiori/MaliciousBrowserExtensions | `5384c566d0b9d91bbcbd8fd3d775e385be194cff` (2026-09-12) | MIT (c) 2026 buio | `database.csv` (`database.json` has the same five fields), `README.md`, `LICENSE`, `count.json` | 991 rows (README badge: 993). Columns: `extension_id, source_url, date_reported, date_added, crx_sha256`. `source_url` empty for 190 of our 313. |
| anonymousSubmitterSudo/malicious_v2_v3_extensions | `74e65e775144eba5888ad719becf9b9893bf063a` (2022-06-29, as git reports) | none (no licence file) | `README.md`, file list of `part_1..6.zip` | 517 extension IDs; each has a `v2` and a `v3` folder (`<id>_<date>_<hash>_v2/v3`), 1034 folders. README text: "517 malicious extensions (517 v2 + 517 v3 equivalent) -- anonymous submission". The link to the MADWeb 2024 paper (arXiv 2404.08310) comes from the task brief; the repository itself does not name the paper. |
| The-Privacy-Commons-Institute/chrome-mal-ids | `77ca4552c0705139d9a2b1ddd9109b29c9e1e597` (2026-10-08) | CC BY 4.0 | `README.md`, `SCHEMA.md`, `TPCI-V.md`, `STATS.md`, `LICENSE.md`, `data/current-list-meta.csv` | 7716 records. |
| toborrm9/malicious_extension_sentry | `b3d832c66fccd26f72bbed81678ee87887cbae4e` (2026-10-09) | MIT (c) 2025-2026 toborrm9 | `README.md`, `LICENSE.md`, `CHANGELOG.md`, `malicious_extensions_detailed.csv`, `findings/boostkey.html` (+ the PDF, not readable here) | 7044 rows. Columns: `extension_id, name, reason, source, insert_date_fmt, blocklist, store, version, sha256`. |

Attribution required by CC BY 4.0 (chrome-mal-ids): "Extension IOC data sourced from **chrome-mal-ids** by The Privacy Commons Institute, https://github.com/The-Privacy-Commons-Institute/chrome-mal-ids, licensed under CC BY 4.0." The repo's output (`labels_tiers.csv`) carries derived fields from it (`tpci_method`, `tpci_behavioral`, `tpci_confirm_mal`, `tpci_threat_type`), with changes: reduced to the IDs of our samples and combined with other sources.

## Facts about the sources that shaped the tiers

- **GF** is a news-driven collection ("IDs retrieved from news articles ... automatically done using n8n"). It is the origin of all 313 samples (all 313 IDs present, the `crx_sha256` equals the sha256 of our files for 313 / 313). Its `source_url` points to a news article (THN 104, LayerX 10, others few) or is empty (190). It gives no behavioural verification.
- **TPCI** (SCHEMA.md, README "Data quality"): records with `CONTRIB-METHOD` other than `Delta_Import` / `csv_import` (e.g. `Google_Search`, `AI_Enrichment`, `Manual`) are "individually reviewed by a human before commit"; `Delta_Import`, `csv_import`, `PDF_Import` are third-party bulk imports. `TPCI-BEHAVIORAL` is Stage 5A **static** analysis (TPCI-V: "Stage 5B dynamic ... not yet implemented"); `malicious` = risk >= 100 or any critical finding. `below-threshold` "is not a safety verification". All 286 of our IDs found in TPCI have `CONFIRM-MAL` = 1 (researcher-confirmed); none has 2 or 3 (Google-confirmed).
- **TPCI and Sentry overlap by construction**: 138 of our TPCI records name the Sentry repository as `SOURCE`, 101 name a community GitHub issue (`chartingshow/crypto-firewall`). They are not independent confirmations for those IDs.
- **Sentry** `reason` is a removal category (Malware, Policy Violation, Adware, Bundling Unwanted Software, In store but Suspicious, ...), not a behaviour finding, and the repo says false positives may occur. It is used as a secondary signal only. Its per-record `source` is a URL of the report that lists the ID, or `Store Monitoring`.
- **MADWeb**: 0 of the 313 malware, 0 of the 497 benign (dev 297, test 200) are in its 517 IDs (ID match).

## Source classes used for T2 / T3

`VENDOR` (publishers of technical analysis; T2 if cited): layerxsecurity.com, koi.ai, socket.dev, secureannex.com, palant.info, obsidiansecurity.com, esentire.com, blog.pulsedive.com, unit42.paloaltonetworks.com, raw.githubusercontent.com/PaloAltoNetworks (timely-threat-intel IOC files), security.com, socradar.io, ox.security, dti.domaintools.com, cyberhaven.com, isc.sans.edu, gitlab-com.gitlab.io, 7ai.com.
`NEWS`: thehackernews.com, bleepingcomputer.com, therecord.media, gbhackers.com, cyberinsider.com.
Everything else (GitHub IOC lists and issues, x.com, rhisac.org, malext.io, web.archive.org, arstechnica.com) is not counted as a vendor technical report. The classification is by publisher type; the articles were **not** opened and not checked to contain the ID or a technical analysis. Counts per domain: `report.md`, section 7.

## Not accessible / not done

- The BoostKey PDF in Sentry `findings/` is CID-encoded and no PDF tooling is installed; its text was not read. The only Sentry record citing it is not among the 313.
- Articles cited by the sources were not fetched (so GF vs Sentry/TPCI disagreement on the report behind the 101-sample cluster is not resolved).
- No MADWeb manifest was read (not needed: IDs are in the folder names).
