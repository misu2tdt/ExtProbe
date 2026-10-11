# Selection criteria for the expanded benign set

Fixed **before any .crx is downloaded** (2026-10-07). Applied mechanically by
`select_list.py` to `candidates_listing.csv`; nothing is picked by hand. If a rule has to
change, it is changed here in a new commit before the download, not afterwards.

## 1. Source

The public Chrome Web Store category pages,
`https://chromewebstore.google.com/category/extensions/<category>`, read by `build_list.py`
on the fetch date recorded in the CSV.

- 18 leaf categories, read from the page itself: productivity/{communication, workflow,
  tools, education, developer}, lifestyle/{shopping, news, entertainment, games, social,
  art, well_being, travel, household, fun}, make_chrome_yours/{accessibility,
  functionality, privacy}.
- Each category page lists its **top 32 extensions ordered by number of users**, with id,
  name, rating (unrounded), number of ratings, number of users, category and manifest.
  So at most 18 × 32 = 576 candidates. Fields were cross-checked against the detail pages.
- The site's robots.txt does not disallow `/category/` or the detail pages used; requests
  are 2 s apart with a descriptive User-Agent. The store's card hides the user count of
  some entries; for those the count is read from the detail page, and if it is not shown
  there either, the entry is excluded (users cannot be verified).
- The store rounds users to steps (6,000,000; 4,000,000; …), so ties are common.

## 2. Inclusion rules (all required)

1. Listed on the store on the fetch date.
2. **≥ 100,000 users** (as shown by the store).
3. **Rating ≥ 4.0**, using the unrounded value from the listing (the page rounds 3.99 to
   "4.0"; 3.99 does not qualify).
4. **manifest_version = 3** (from the listing; checked again on the downloaded file —
   a file that is not MV3 is dropped, not replaced; see the decisions above).
5. Not already in the 354 evaluation samples, compared by **extension id**. The ids of the
   existing files are computed from their .crx headers (`existing_ids.txt`), because the
   30 + 11 benign files are named by product, not id.
6. Not an enterprise / policy-install extension: the manifest uses an `enterprise.*` API.
7. Downloadable through the public update endpoint (below); otherwise dropped, not replaced.

## Decisions of 2026-10-07 (author) — they override anything below that says otherwise

1. **Option A: use exactly the 256 extensions that pass the rules** in `candidates_listing.csv`
   (commit 6798dae). The target of 300 is not pursued: no deeper listing, no relaxed rule.
   The set is fixed by that file; the store's ranking drifts, and when the descriptions were
   added (below) 2 of the 256 were no longer in a category's top 32 — they stay in.
2. **The 13 entries whose user count the store does not show are excluded** (not included on
   the strength of their rank).
3. **Grey label:** an extension is `grey` when its store listing description contains
   "coupon", "cash back" or "cashback" (case-insensitive); all others are `benign`. The
   description is the store's short description, stored in `candidates_listing.csv`
   (`description`, with `description_source`).
4. **No replacement:** a file that fails to download (3 attempts: the first plus 2 retries) or
   fails the checks (not MV3, id in the header differs from the listing id, not a valid
   .crx) is recorded with its reason and is **not** replaced by another extension.
5. Download mechanics: the update endpoint is asked with `prodversion=150.0.7871.187` (the
   Chrome version used for the earlier `cws_benign_crx` set), so that extensions whose
   minimum Chrome version is above 131 are served at their current version.

## 3. Order and quota

- "Category" = the 18 leaf categories above. No category may exceed **25% of the target**
  (75 of 300).
- Inside a category: **users descending**, then number of ratings descending, then
  extension id ascending (a deterministic tie-break; no manual choice).
- Categories are served **round-robin** in the order the store lists them, one candidate
  per round, until the target is reached or every category is exhausted. A category
  with few qualifying extensions simply runs out (the others continue). This is "descending
  users within each category until enough".
- Target 300; minimum accepted 150. **Superseded by decision 1: all 256 qualifying extensions
  are used, and a candidate that fails is not replaced.**

## 4. Labels

- Default label **benign**. This is a *presumption*, not a verdict: the extensions are
  popular, well-rated and from the official store, but unlike the 46 verified labels of
  the paper they have **not** been reviewed by hand. The paper should say so.
- Label **grey** for coupon / cashback extensions by the description rule of decision 3,
  kept like Honey, Rakuten and Capital One Shopping in the earlier set (reported separately
  from benign).

## 5. Download and checks

- `https://clients2.google.com/service/update2/crx?response=redirect&acceptformat=crx2,crx3&prodversion=150.0.7871.187&x=id%3D<id>%26installsource%3Dondemand%26uc`,
  one file per 2 s (failures: 2 retries, then the reason is recorded), into `samples/benign_ext/` (gitignored; **the files are never committed**).
- After download: CRX header magic, unpack `manifest.json`, confirm MV3 and the id derived
  from the header equals the requested id, SHA-256, name and version from the manifest.
- `docs/samples_manifest_benign_ext.csv` (committed): ext_id, name, version, users,
  rating, category, label, download date, SHA-256, source URL.

## 6. Known limits (to state in the paper)

- Top-32-per-category sampling: biased to popular extensions, which is the intent
  ("benign" = widely used) but excludes long-tail extensions, where many false positives
  of the detectors may also live.
- The 100,000-user floor leaves lifestyle/household, news and well_being almost empty.
- Users are the store's rounded bucket; ratings and users change over time (fetch date
  recorded).
- Presumed-benign labels, not manually verified.
