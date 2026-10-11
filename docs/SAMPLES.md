# Evaluation samples

**The extension files are not in this repository** and are not covered by its license. The repository carries the lists
(`evaluation/manifests/`): one row per sample, no file content.

## Development corpus (354 samples) - `evaluation/manifests/samples_manifest.csv`

| set | label (raw) | count |
|---|---|---|
| malicious (publicly disclosed campaigns) | malicious | 313 |
| benign | benign | 41 |

| column | meaning |
|---|---|
| `ext_id` | identifier used in the results: the 32-letter Chrome extension id when the file name has one, otherwise the file name reduced to letters and digits |
| `file`, `location` | file name and the directory the evaluation scripts read it from |
| `label_raw` | label of the source collection: `malicious` or `benign` |
| `label_verified` | label after manual review (mapping in `evaluation/v2/label_mapping.md`): `malicious`, `benign`, `benign_mislabel` (listed as malicious but found benign), `grey` (adware / PUP, excluded from the verified metrics), `unknown_verify` (could not be verified, excluded) |
| `source` | folder the sample came from in the authors' collection, verbatim |
| `sha256` | SHA-256 of the file as used for the paper |

Verified label counts: malicious 283, benign 38, benign_mislabel 21, grey 10, unknown_verify 2.

## Other sets

`samples_manifest_malware_test.csv` (public MADWeb 2024 data set), `samples_manifest_benign_ext.csv` and
`samples_manifest_benign_test.csv` (Chrome Web Store benign sets), `samples_manifest_itw_B.csv` (random Chrome Web Store sample of
the in-the-wild evaluation). The list of in-the-wild set A is not published (see `evaluation/v3/in_the_wild/set_A_summary.md`).

**Safety:** these include real malware. Never open a sample outside the sandbox container and never push the files to a repository.
