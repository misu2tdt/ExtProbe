# In-the-wild audit: blind labelling (aggregates only)

Aggregates only, plus `ratings.csv` (anonymous dossier codes `L-001`..`L-026` with the flag and the labels of rater A, rater B and the final label; no extension ID, name or domain, no code-to-sample mapping, no rater sheets and no free-text reasons). `python evaluation/v3/in_the_wild/compute_kappa.py --ratings evaluation/v3/in_the_wild/ratings.csv` reproduces section 2. The mapping and the rater sheets stay in the private development repository. Plan: `CRITERIA.md`, Amendments 2 and 4. Flag = score >= 40 (v3 as frozen, one run per set). Wilson 95% intervals (the `wilson` function of `evaluation/v3/audit/summarize.py`).

## 1. Protocol

- 26 blind dossiers: the 6 flagged samples (5 of set A, 1 of set B) and 20 unflagged samples of set A drawn at random (`CRITERIA.md`, A1.2). The 20 are a sample of the unflagged packages, not all of them; nothing here is extrapolated to the whole set.
- Two LLM raters from different vendors, each in a fresh session: Claude Opus 5.5 (rater A) and GPT Sol 5.6 (rater B). Each received only the dossiers, `LABELING_GUIDE.md` and a fixed prompt; neither had the mapping from dossier codes to extensions. Run date 2026-10-12.
- Disagreements were adjudicated by one author, with a written reason, after a manual check of the store listing and privacy policy. The adjudicator did not have the mapping before the adjudication was complete.
- The protocol was pre-registered as Amendment 4 of `CRITERIA.md` (old-repository commit `94199d2`) before any label existed (see `PROVENANCE.md`).
- Five classes: harmful, undisclosed-collection, grey, benign, undetermined.

## 2. Agreement

Exact agreement 24 / 26 = 92.3%; expected by chance 0.444; **Cohen's kappa = 0.862** (five classes, unweighted). Two disagreements, both adjudicated.

## 3. Final labels (26 dossiers)

| label | n |
|---|---|
| harmful | 0 |
| undisclosed-collection | 3 |
| grey | 8 |
| benign | 15 |
| undetermined | 0 |

## 4. Final labels against the flag

| group | n | harmful | undisclosed-collection | grey | benign |
|---|---|---|---|---|---|
| flagged (set A 5 + set B 1) | 6 | 0 | 1 | 5 | 0 |
| not flagged (random sample of set A) | 20 | 0 | 2 | 3 | 15 |

- **Flagged samples labelled benign: 0 / 6 = 0.0% (0.0%-39.0%).**
- **Unflagged samples labelled undisclosed-collection: 2 / 20 = 10.0% (2.8%-30.1%).**

These are shares inside the audited groups. They are not recall or precision of the whole set, and the labels are LLM labels with a manual check on disagreements, not a behavioral verification.

## 5. The two unflagged undisclosed-collection samples (patterns only)

Both are missed because the identifier rules of `score_v3` do not cover the pattern:

- (a) a persistent identifier that is not a UUID v4 sent to a host the manifest declares;
- (b) an identifier carried in the URL of an install or uninstall tab (tab URLs are not extension requests, so the persistent-identifier and user-data rules do not look at them).

## 6. Case study (pattern only)

One flagged sample, labelled undisclosed-collection, sends the full URL of each visited page to the developer's own server (the service worker, in requests made while the harness visited its pages; no page titles were seen in the requests) while its store listing declares no data collection. It was flagged by `history_exfil` (50 points).
