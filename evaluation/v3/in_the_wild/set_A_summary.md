# In-the-wild set A: aggregate description (per-extension data are NOT published)

The per-extension list of set A (extension ids, Sentry reason / date / source, label tiers, per-sample scores) is **not** in this
repository: the labels are partly weak (tier T2 is assigned by name, `id_listing_verified = no` for all of them) and the
extensions may still be live in the Chrome Web Store. It is available on request. What is published:

- number of extensions: **215**
- SHA-256 of the sorted id list (one id per line, trailing newline): `1ccde6c8fe9a6d66744f8654fce091ddeff0d87cd511e5ec914ece302e94130a`
  (the same convention as the trial lists of `evaluation/probe/CRITERIA.md`)
- Sentry removal reasons: Search Hijacking 115, Malware 44, Policy Violation 32, Adware 23, Potentially Unwanted Software 1
- label tiers: Sentry-only 174, T2 41
- packages downloaded between 2026-10-10T07:18:32Z and 2026-10-10T07:45:24Z (UTC)
- results: `results.md` (aggregates only); criteria and amendments: `CRITERIA.md`; labeling guide: `LABELING_GUIDE.md`
