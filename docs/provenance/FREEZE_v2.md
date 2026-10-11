> **Historical document (v2 freeze, 2026-10-03).** Paths, git tags (`v2.0-freeze`) and commands refer to the original private
> repository; they are kept for the record. See `PROVENANCE.md` for this repository.

# FREEZE — what the A/B evaluation runs with

**Status: FROZEN on 2026-10-03** — tag `v2.0-freeze` (branch `saner-prep`). Code frozen at
commit `53732c4b0d37ff35edbeda8a7586f61eac9cc157`; this file is committed on top of it and the tag points to that
commit. From here until the A/B evaluation is finished, **no detector, weight or stimulus
changes** (sandbox phases, honey pages, `worker/risk.py` rules and weights). Bug fixes
that would change a measurement wait until after A/B, or restart A/B under a new tag.

Decisions: `affiliate_hijack` weight **40** (author, 2026-10-02, §4); product test page in
v2 `target_matched` by default, with a retailer fallback for all-hosts extensions
(author, 2026-10-03, §3).

Values are copied from the code; if they ever disagree, the code wins and this file is wrong.

> Note added 2026-10-07 (after the freeze, A/B finished): the tool was renamed ExtAnalyze →
> ExtProbe (tag `v2.1-extprobe`) with no change to detectors, weights, stimuli or images;
> the images below also carry the tags `extprobe-sandbox:*`. The text below is left as frozen.
>
> Note added 2026-10-07: `eval/ab_compare.py` now writes the `--ab` folder in the header of
> `eval/ab/comparison.md` relative to the repository (`eval/ab`) instead of the absolute path
> of the author's machine, to keep personal paths out of the published results. No logic
> changed: regenerating `comparison.md` changes only that header line (every number is
> identical). `run_ab.ps1` therefore no longer counts `eval/ab_compare.py` as a frozen path.

## 1. A/B design

| run | sandbox profile | scoring | traces |
|---|---|---|---|
| A | corpus | `rescore.py --scoring auto` (= corpus rules for corpus traces) | its own (`eval/ab/A`) |
| B | v2 | `rescore.py --scoring auto` (v2 rules) | its own (`eval/ab/B`) |
| A′ | — | `rescore.py eval/ab/B --scoring legacy` (corpus rules) | **B's traces**, not re-run |

What each step isolates:
- **A → A′**: same scoring rules, different sandbox — the new browser (Playwright 1.63 /
  Chrome for Testing 153) **and** the v2 stimuli (product test page, retailer fallback,
  longer target_matched budget) together. These two cannot be separated without another run.
- **A′ → B**: same traces, different rules — the detectors only (beaconing on
  extension-initiated requests, affiliate_hijack).

Paper reference: `eval/results` (the published corpus run). Regression guard:
`python eval/check_paper_numbers.py` 12/12 (verified AUC 0.6955, TP 196 / FP 11 / FN 84 /
TN 38 at 40; raw AUC 0.4854, TP 199 / FP 14 / FN 111 / TN 17; `summary.csv`
byte-identical). A is a fresh corpus run, so it may differ from the paper where the live
web changed; the comparison table reports both. Comparison: `python eval/ab_compare.py`
(writes `eval/ab/comparison.md`).

## 2. Sandbox profiles

| | corpus | v2 |
|---|---|---|
| Dockerfile | `sandbox/Dockerfile` | `sandbox/Dockerfile.v2` |
| base image | `mcr.microsoft.com/playwright/python:v1.40.0-jammy@sha256:5656288def8576b31903becabac255b19bc01ee961ddb499de3418d52f55ed2a` | `mcr.microsoft.com/playwright/python:v1.63.0-jammy@sha256:47a65aee64780daa8bad02b37e0ef14902851a3aa7ad0153234f784eb12422b0` |
| Playwright / browser | 1.40.0 / Chromium 120.0.6099.28 | 1.63.0 / Chrome for Testing 153.0.8010.12 |
| Python deps | `requirements.txt` (playwright==1.40.0, websockets==12.0) | `requirements.v2.txt` (playwright==1.63.0, websockets==12.0) |
| image tag | `extanalyze-sandbox:corpus` (also `:latest`) | `extanalyze-sandbox:v2` |
| local image id at freeze | `sha256:31f312f7e0d2a406030cab12f25ca469367c4a3de12bfcb2177ef7496b2bab64` | `sha256:ffeebda9a77c630a3d9c19a51b7e01b390fcddf1fec99340cb66900ca6d7b45d` |
| env | `SANDBOX_PROFILE=corpus` | `SANDBOX_PROFILE=v2`, `SANDBOX_CHROMIUM_SANDBOX=1` (Chromium's own sandbox when not root), `SANDBOX_CDP_DRAIN_ON_CLOSE=1` (close browser before stopping the CDP sensor), `SANDBOX_RECORD_PW_SW=1` (SW request cross-check), **`SANDBOX_PRODUCT_PROBE=1`** (§3), **`PHASE_BUDGET_TARGET_MATCHED=60`** |

Local image ids depend on the build; reproducibility rests on the base digests + the
frozen commit. Build both images from the frozen commit before the runs and record
`docker image inspect --format {{.Id}}` next to the results.

Container limits (worker, `eval/batch_run.py`, `python -m extanalyze`): `--memory 3g
--pids-limit 512 --cap-drop ALL` + `NET_RAW, CHOWN, SETUID, SETGID, KILL`,
`--security-opt no-new-privileges`, unpacked extension on a 1 GB tmpfs. Analysis budget
`--timeout 180` s.

## 3. Run protocol

Phases and budgets (`sandbox/analyze.py`):

| phase | budget | what happens |
|---|---|---|
| load | 15 s | browser starts with the extension; first tab |
| honeypot_pages | 60 s | visits `http://localhost:8888/fake_bank.html`, `…/fake_gmail.html`, `https://example.com` (honeypot credentials in forms) |
| target_matched | corpus 40 s, **v2 60 s** | at up to **`MAX_TARGET_HOSTS = 2`** concrete hosts from `content_scripts.matches` (`<all_urls>`/wildcard-only hosts skipped), served with route.fulfill: `honey_pages/universal.html`. **v2 additionally**, see below |
| extension_pages | 30 s | opens the extension's own pages |
| delayed_observation | 15 s | waits (3 s sleep inside the budget) for delayed behaviour |

`DWELL_MS = 3000` per page, `PER_PAGE_TIMEOUT_MS = 6000`. Start-up: launch timeout 30 s,
first-page probe 10 s, 3 attempts (backoff 2 s, 5 s); preflight fails fast on
`minimum_chrome_version` newer than the browser or missing referenced files.

**v2 target_matched (`SANDBOX_PRODUCT_PROBE=1`, `phases/actions.py::_phase_target_matched_product`):**
- Per concrete target host, one tab: `universal.html` at `/` with the same dwell and
  scroll/focus stimulus as the corpus profile, **then** the unbranded product test page
  (`honey_pages/product_test.html`: "Test product page", links `/dp/TEST000x` and
  `/item/<id>.html`, no logo or brand) at `/shop-test`, a 3 s dwell, and the link probe:
  record all hrefs, follow one `/dp/` and one `/item/` link (`events["target_page_probe"]`).
  The route serves by path: `/shop-test`, `/dp/*`, `/item/*` → product page; anything else
  → `universal.html`.
- **Retailer fallback:** an extension with no concrete target but content scripts on all
  hosts (`<all_urls>`, `*://*/*`, …; 85 of the 354 corpus samples) gets only the product
  page (no `universal.html`), at **`amazon.com` and `aliexpress.com`** — exactly
  `MAX_TARGET_HOSTS` hosts. Reason: affiliate rewriters commonly act only on retailer
  domains (SP3b: the 5 rewriters in the corpus targeted Amazon and AliExpress), and a
  neutral test host would not trigger them. **Limitations:** only these two retailers;
  rewriters keyed on other shops (eBay, Walmart, Booking, …) are not exercised; the page
  is unbranded and is not a real product page, so extensions that check the page content
  may stay silent; the fallback is an extra stimulus that A does not have (part of A → A′).
- Verified 2026-10-03 with the v2 defaults (no `SANDBOX_TARGET_PAGE`): affiliate_hijack fires
  on all 5 corpus link rewriters (goikoil… 40, nigamac… 41, jmlgkea… 55, loiofaa… 67,
  mcaglpc… 82) and on none of honey (retailer fallback), rakuten, capitaloneshopping (their
  own manifest targets); target_matched took 23–34 s of its 60 s budget.

Measurement-only options (unset in A and B): `SANDBOX_TARGET_PAGE=product_test.html`
(serves the test page for every path at the targets; `<all_urls>`-only extensions get it
at `shop.bench.test`), `SANDBOX_TARGET_HOST=<host>`.

## 4. Scoring (`worker/risk.py`)

`risk = round(min(max(s_eff, d) + 0.3·min(s_eff, d), 100))`, with `s_eff = min(s, 35)` when
`d < 15` (static alone cannot reach MEDIUM), else `s_eff = s`.
Levels: ≥ 90 CRITICAL, ≥ 70 HIGH, ≥ 40 MEDIUM (= flag threshold), ≥ 15 LOW, else MINIMAL.

**Static `s`** (manifest only, cap 100): hosts in `host_permissions`/`content_scripts` not
explained by the name/description, not known infrastructure and not containing
amazon/google/facebook: 25 + min(5·n, 15);
overprivileged (≥ 4 dangerous permissions): +20; dangerous permissions: min(3·n, 15);
content scripts on all sites: +15. Dangerous permissions: webRequest, webRequestBlocking,
declarativeNetRequest, downloads, scripting, management, cookies, history, tabs,
clipboardRead, clipboardWrite, debugger, proxy, `<all_urls>` (in host_permissions).

**Dynamic `d`** (cap 100):

| signal | weight | fires when | profile |
|---|---|---|---|
| credential_exfil | 80 | a honeypot marker (`HONEYPOT`, `sk-HONEYPOT`, `ghp_HONEYPOT`, `AKIAHONEYPOT`, `HONEYPOT-PASSWORD`, `HONEYPOT-OTP`, `HONEYPOT-ACCT`, `honeyuser`) appears in a request's URL, body or interesting headers (authorization, cookie, x-api-key, x-auth-token), verbatim or under one layer of URL-encoding / base64 / hex (runs ≥ 16 chars); `honeypot_exfil_encoding` records which | both (corpus: 0/354 encoded-only) |
| local_harvest | 30 | a marker is found in the extension's own storage | both |
| undeclared_domain_contact | 30 if any from the service worker, else 15; +5 per extra host; cap 40 | a host contacted by the extension (origin service_worker, or `request_provenance[host]` True = content script) that the manifest does not declare (exact or `*.` wildcard; `<all_urls>`/match-all declares nothing), excluding harness hosts (localhost, 127.0.0.1, example.com, www.example.com, `*.invalid`) and the known-infrastructure list (`KNOWN_INFRA_HOSTS`) | both |
| beaconing | 8, +12 if the host is undeclared | ≥ **4** timestamped requests to one host with mean interval ≥ **0.5 s** and coefficient of variation ≤ **0.25** | corpus: all requests (page + SW); **v2: extension-initiated requests only** (same rule as undeclared). Corpus sensitivity: `eval/sensitivity/beaconing_provenance.md` |
| script_injection | 15 | a `<script>`/`<iframe>` with a cross-origin `src` (not inline, not harness) added to a page, except on the extension's own pages and on vendor welcome pages it opened | both |
| unsolicited_tab | 15 | a tab opened outside the harness phases (honeypot_pages, extension_pages), not about:blank, not the extension's own `chrome-extension://<id>/` page | both |
| affiliate_hijack | **40** (`AFFILIATE_HIJACK_WEIGHT`; author's decision 2026-10-02) | see §5 | **v2 only** |
| page hang | 10 | `page_hang_count > 0` (runtime indicator, not a detector) | both |

Why affiliate_hijack = 40 (decided by the author, 2026-10-02): the behaviour is highly
specific — rewriting a shopping link to add or replace an affiliate code has no benign
explanation without user action, and it fired on 0 clean samples, coupon extensions
included; it is prohibited by name in the Chrome Web Store affiliate ads policy (2025);
40 makes it MEDIUM on its own (the flag threshold), not HIGH, keeping it below
credential_exfil (80). Sensitivity 30 vs 40 on the v2 traces
(`eval/sensitivity/affiliate_weight.md`): 5/18 traces fire, all malicious, 0 benign/grey;
40 moves 2 of them (the Amazon `tag=` rewriters, 30/31 → 40/41) across the threshold.

## 5. affiliate_hijack (v2 only)

Fires when a URL to a shopping page the sandbox served (`target_matched` host) is changed:
(a) a listed parameter is added; (b) the value of a listed parameter already in the served
URL is replaced ([Chrome Web Store affiliate ads policy update, 2025](https://developer.chrome.com/blog/cws-policy-update-affiliate-ads-2025));
(c) the URL is rewritten to / navigates through a listed redirect domain. Evidence: served
vs. current link hrefs on the test page, followed links, navigations / new tabs, network
requests. Not for unchanged values, `utm_*` or unlisted parameters. Needs the product test
page (§3) to have anything to observe.

| network | parameters | source (checked 2026-10-02) |
|---|---|---|
| Amazon Associates | `tag` | https://affiliate-program.amazon.com/help/node/topic/GP38PJ6EUR6PFBEC |
| eBay Partner Network | `campid`, `mkcid`, `mkrid` | https://developer.ebay.com/api-docs/buy/static/ref-epn-link.html |
| Rakuten Advertising | `ranMID` | https://pubhelp.rakutenadvertising.com/hc/en-us/articles/6890984802189-Tracking-Links-and-Landing-Page-URLs (checked by hand by the author, page updated 2026-09-09) |
| Awin | `awc` | https://help.awin.com/developers/docs/parameter-guidance |
| CJ Affiliate | `cjevent` | https://docs.cj.com/docs/click-events |
| Impact | `irclickid` | https://help.impact.com/brand/what-would-you-like-to-learn-about/platform-features/tracking/set-up-tracking/determine-your-programs-itp-compliance |

Dropped for lack of a public official source: `ascsubtag`, `aff_short_key`, `aff_platform`,
`aff_trace_key`, `sscid`, `ranEAID`, `ranSiteID`.

Redirect domains (and subdomains): `s.click.aliexpress.com`, `amzn.to`, `rover.ebay.com`,
`click.linksynergy.com`, `awin1.com`, `shareasale.com`, `anrdoezrs.net`, `dpbolvw.net`,
`jdoqocy.com`, `kqzyfj.com`, `tkqlhce.com`.

## 6. MITRE ATT&CK labels (findings only, not scored)

credential_exfil T1041 · local_harvest T1074.001 · script_injection T1059.007 ·
beaconing T1071.001 · undeclared_domain_contact T1071 · unsolicited_tab and
affiliate_hijack: no matching ATT&CK Enterprise technique.

## 7. Scoring modes

`eval/rescore.py [RESULTS] --scoring auto` (default): each trace by its own profile's rules
→ `summary.csv`. `--scoring legacy`: every trace with the corpus rules (`risk.legacy_view`:
v2-only rules off) → `summary_legacy.csv`. Tests: `tests/detectors/cases/scoring_v2_*.json`,
`tests/eval/test_rescore_scoring.py`.

## 8. Checks at tagging

- `python eval/check_paper_numbers.py` → 12/12
- `python -m pytest` → all pass (detector cases, sensor encoding, rescore modes)
- smoke test 13/13 on both images: `docker run --rm --entrypoint python3 extanalyze-sandbox:<p> /sandbox/smoke_test.py`
- done at freeze (2026-10-03): all three pass; affiliate weight 40, product-page decision,
  image ids, code commit and date filled in above.
