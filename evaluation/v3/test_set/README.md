# Held-out benign test set (profile v3): how it was built

Criteria: `../TEST_SET_CRITERIA.md` (committed before any v3 dev result) and, for everything it
says "identical to", `../../benign_ext/CRITERIA.md`. This file records how those were applied
and the one place where the procedure had to be extended. Nothing in this folder runs the
sandbox; the test set is run once, after tag `v3.0-freeze`.

## Files

| file | content |
|---|---|
| `build_test_list.py` | full category listing, exclusions, stratified seeded selection, labels |
| `candidates_listing_test.csv` | listed entries whose store card shows ≥ 100,000 users (the full listing is local) |
| `detail_page_users.json` | user counts read from detail pages for entries whose card hides them |
| `selected_test.csv`, `selected_test.sha256` | the selected ids with labels; SHA-256 of the sorted id list |
| `SELECTION.md` | exclusion waterfall and per-category table (generated) |
| `download_test.py`, `download_report.csv` | download and checks; one row per selected id |
| `../../../docs/samples_manifest_benign_test.csv` | accepted files with SHA-256 and download date |

`.crx` files go to `samples/benign_test/` (gitignored, never committed).
`py eval/verify_samples.py --benign-test` checks the folder against the manifest.

## What is the same as the development set

Same store, same 18 leaf categories, same fields, same inclusion rules (users ≥ 100,000 as
shown by the store, rating ≥ 4.0 unrounded, manifest_version 3 per the listing, no
`enterprise.*` API), same detail-page fallback for hidden user counts, same grey rule (the
store description contains "coupon", "cash back" or "cashback" → `grey`, else `benign`; labels
come from the listing and are fixed before any download or run), same download endpoint and checks
(`eval/benign_ext/download_benign.py`, imported), and no replacement of a file that fails.

## Exclusions

Every extension id in: the 313 malware, the 41 older benign files (ids from the `.crx` headers),
the 256 development extensions (all listing-eligible ids of `eval/benign_ext/candidates_listing.csv`,
whether their download succeeded or not, and the accepted manifest).

## The extension of the pool

The development listing read the top 32 entries of each category page and all 256 qualifying
extensions are in the development set. A fresh top-32 listing (2026-10-08) adds only 12
unseen eligible extensions, far below the minimum of 150. As the criteria allow, the pool was
extended "with the same listing procedure": the same category pages and the same data request
the page itself issues (`zTyKYc`, declared in the page's `AF_dataServiceRequests` as
`[[null,[[3,<category>,null,null,2,[32]]]]]`), with page size 32 replaced by 1000 and the
continuation token followed until the category ends (the token goes into the size array:
`[size, token]`). `robots.txt` does not disallow it; requests are 2 s apart.

Why a deeper fixed list was not enough: a category has thousands of entries (the whole listing is
about 200,000 rows) and the store's order is by users only for the first ~30; entries with
≥ 100,000 users appear all the way down, so any fixed depth truncates the pool. A check at depth
1000 found such entries in the last 100 ranks of six categories.

Date of listing: see `SELECTION.md` (the `fetched` column of the listing).

## Stratified selection

Target 200, minimum 150, seed 2027, at most 25 % of the target (50) per category.
Quota of a category = largest-remainder share of the target in proportion to the **development
set's category counts** (so the test set mirrors the development mix, which makes the two false
positive rates comparable). A category with fewer eligible extensions than its quota gives all
of them, and the shortfall is re-distributed by the same proportions to the categories that
still have room. Inside a category: `random.Random(2027).sample` over the eligible ids sorted
ascending. "Stratified by the same categories" leaves the allocation rule open; this one is
the reading chosen here, before any download.

## Limits to state in the paper

- The 100,000-user floor leaves several categories without any unseen eligible extension
  (see `SELECTION.md`); the test set cannot reproduce the development mix there.
- Labels are presumed (store listing), not verified by hand, as for the development set.
- Users are the store's rounded bucket, taken on the listing date.
