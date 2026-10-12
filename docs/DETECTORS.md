> **Note.** This page describes the v2 detectors and weights. Profile v3 (this repository's default) keeps the same detector code
> (`scoring/risk.py`) but scores with `docs/v3/SCORING_v3.md` (`scoring/v3/score_v3.py`).

# Detectors, MITRE labels and the affiliate_hijack definition

<!-- Moved from README.md on 2026-10-07 (README rewrite); content unchanged. -->

## Reading the result

`GET /jobs/<job_id>` returns `risk_score` (0-100), `risk_level`, and the full
`behavioral_report` (produced by `scoring/risk.py`). To make sense of it:

- **`risk_score`/`risk_level`**: combines a *static* score (manifest permissions/
  hosts alone) and a *dynamic* score (observed runtime behavior) — dynamic-first,
  so broad permissions alone (e.g. an ad blocker) cannot reach MEDIUM+ without
  corroborating runtime evidence. Levels: `risk_score` ≥ 90 `CRITICAL`, ≥ 70
  `HIGH`, ≥ 40 `MEDIUM`, ≥ 15 `LOW`, else `MINIMAL`.
  The reports and the CLI show three levels instead: score ≥ 40 (legacy `MEDIUM`, `HIGH`, `CRITICAL`) = "Flagged for review", 15-39 (legacy `LOW`) = "Review suggested", below 15 (legacy `MINIMAL`) = "No notable behavior observed".
- **`behavioral_report.indicators`**: 11 booleans — 4 static (`overprivileged`,
  `has_suspicious_host`, `broad_injection`, `causes_page_hang`) and 7 **dynamic
  detectors** (`affiliate_hijack` only on v2 traces), each backed by a MITRE ATT&CK
  technique where one applies (`behavioral_report.findings`):

  | Indicator | What it means | MITRE |
  |---|---|---|
  | `credential_exfil` | Honeypot decoy credential seen in outgoing traffic (URL, body or header; verbatim or under one encoding layer — URL-encode, base64, hex — recorded in `honeypot_exfil_encoding`) | T1041 |
  | `local_harvest` | Honeypot decoy found staged in the extension's own storage | T1074.001 |
  | `script_injection` | Cross-origin `<script>`/`<iframe>` injected into a page | T1059.007 |
  | `beaconing` | Statistically regular request interval to one host (possible C2) | T1071.001 |
  | `undeclared_domain_contact` | Extension contacted a host not declared in its manifest | T1071 |
  | `unsolicited_tab` | Extension opened a tab the harness didn't ask for | (no ATT&CK technique fits browser-tab abuse — deliberately left unmapped) |
  | `affiliate_hijack` | **v2 traces only.** Extension changed a shopping-page URL the sandbox served to earn affiliate commission (definition below) | (no technique in the repo's ATT&CK table fits commission fraud — left unmapped) |

  **`affiliate_hijack` definition (frozen).** Enabled only when the trace's
  `startup.profile` is `"v2"`; corpus traces and traces without a profile keep it off,
  so the paper's corpus scores are unchanged. It fires when a URL to a shopping page the
  sandbox served (a `target_matched` host) is changed from the original in one of three ways:
  (a) a parameter from the fixed list below is added; (b) the **value** of a listed
  parameter the served URL already had is replaced — per the
  [Chrome Web Store affiliate ads policy update (2025)](https://developer.chrome.com/blog/cws-policy-update-affiliate-ads-2025),
  which allows affiliate links, codes or cookies only with disclosure, user action and a
  direct user benefit; (c) the URL is rewritten to / navigates through a fixed list of
  affiliate redirect domains — `s.click.aliexpress.com`, `amzn.to`, `rover.ebay.com`,
  `click.linksynergy.com`, `awin1.com`, `shareasale.com`, `anrdoezrs.net`, `dpbolvw.net`,
  `jdoqocy.com`, `kqzyfj.com`, `tkqlhce.com`. Evidence: link hrefs on the test page before
  (as served) and after the extension ran, the URL reached by following them, same-tab
  navigations / new tabs, and network requests. It does not fire for a parameter kept
  with its original value, for `utm_*`, or for any parameter outside the list.

  Parameters, each with its official source (checked 2026-10-02; not derived from the corpus):

  | Network | Parameters | Source |
  |---|---|---|
  | Amazon Associates | `tag` | [Associates help: simple text link](https://affiliate-program.amazon.com/help/node/topic/GP38PJ6EUR6PFBEC) |
  | eBay Partner Network | `campid`, `mkcid`, `mkrid` | [Creating an EPN tracking link](https://developer.ebay.com/api-docs/buy/static/ref-epn-link.html) |
  | Rakuten Advertising | `ranMID` | [Tracking links and landing page URLs](https://pubhelp.rakutenadvertising.com/hc/en-us/articles/6890984802189-Tracking-Links-and-Landing-Page-URLs) — checked by hand by the author (page updated 2026-09-09: shows `ranMID`, e.g. `?utm_content=sytedemo&ranMID=13275`, and `click.linksynergy.com`) |
  | Awin | `awc` | [Parameter guidance](https://help.awin.com/developers/docs/parameter-guidance) |
  | CJ Affiliate | `cjevent` | [CJ's click events](https://docs.cj.com/docs/click-events) |
  | Impact | `irclickid` | [Determine your program's ITP compliance](https://help.impact.com/brand/what-would-you-like-to-learn-about/platform-features/tracking/set-up-tracking/determine-your-programs-itp-compliance) |

  Dropped for lack of a public official source: Amazon `ascsubtag`; AliExpress
  `aff_short_key`, `aff_platform`, `aff_trace_key` (the AliExpress Portals help is behind a
  login — AliExpress rewriting is still caught through `s.click.aliexpress.com`);
  ShareASale `sscid` (its help article now redirects to the Awin home page); Rakuten
  `ranEAID`, `ranSiteID` (not confirmed on an official page read directly).
  Weight: `AFFILIATE_HIJACK_WEIGHT = 40` in `scoring/risk.py`, the single place it is set
  (author's decision, 2026-10-02): highly specific behaviour with no benign explanation and
  0 hits on clean samples including coupon extensions; prohibited by name in the CWS
  affiliate policy (2025); 40 = MEDIUM, kept below credential_exfil (80). Sensitivity 30 vs
  40: `evaluation/v2/sensitivity/affiliate_weight.md`. Reports show a "CWS policy violation" banner
  when it fires (display only).

  A `MEDIUM+` verdict generally means at least one dynamic detector fired, not
  just "this extension asked for broad permissions." Full detector logic, weights,
  and the exact scoring formula are documented in `scoring/risk.py`'s module
  docstring.

To debug the sandbox directly, without the API/worker/queue:

```bash
