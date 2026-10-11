# ExtProbe v3 scoring (Tier 2) — rules and weights, fixed before any dev run

Status: **pre-registered**. This file is committed before `eval/v3/score_v3.py` is run on the
610-sample dev set. Weights and rules below may only change in a later commit that says why,
and any change after the dev run is reported as post-hoc.

Scope: traces of the v3 profile (`schema_version` `1.1+v3`, image in `eval/v3/IMAGE.md`).
`worker/risk.py` is not modified; `score_v3.py` imports a few of its helpers and lists
(declared-host matching, infra / harness host lists, beaconing, affiliate, local harvest).
v2 and corpus scores are unchanged.

## Extension-initiated requests (the base set for T2-2, T2-3, T2-7, beaconing)

A request counts as extension-initiated if any of the following holds:
- it is a service-worker request (`network_requests[].origin == "service_worker"`);
- it is a CDP page request whose outermost caller is an extension frame
  (`page_request_initiators[].attributed == "extension"`, T1-1);
- it is a Playwright page request joined to such a record (`initiator_ext is True`).

`page_via_extension_hook`, meaning a page call that passes through an extension's
main-world wrapper, is **not** extension-initiated. Unknown attribution is not counted.

## Signals

| id | signal | fires when | class | weight |
|---|---|---|---|---|
| T2-7 | `credential_exfil` | a honeypot marker (plain, or after one URL / base64 / hex decoding layer: `sandbox/honeypot.py`) is found in the URL, body or interesting headers of an **extension-initiated** request | heavy | 80 |
| T2-2 | `history_exfil` | a URL or title of a page the harness visited is found in an extension-initiated request to a registrable domain other than that page's domain. A URL is matched in plain form, after 1 or 2 layers of URL decoding, or after base64 / base64url decoding. Only URLs with a path other than `/` count; a bare domain does not. Titles must be at least 8 characters long. | heavy | 50 |
| T2-6 | `affiliate_hijack` | v2 rule (`risk.detect_affiliate_hijack`), except that the Amazon parameter `tag` counts only on `amazon.*` hosts | heavy | 40 |
| T2-3a | `undeclared_domain_contact` (user data) | an extension-initiated request to an undeclared, non-infra, non-harness host (v2 host rules) carries user data: a visited URL or title (T2-2 rule), a honeypot marker, or a persistent identifier | heavy | 40 |
| — | `local_harvest` | v2 rule (honeypot marker in the extension's storage) | heavy | 30 |
| T2-3b | `undeclared_domain_contact` (no user data) | as T2-3a, but no request to such a host carries user data | light | 15, +5 per extra host, max 20 |
| T2-4 | `unsolicited_tab` | a tab with `extension_opened` set (A1a: not opened by the harness, no web-page opener). Excluded: `about:blank` and the extension's own `chrome-extension://<id>/` pages | light | 15 |
| T2-5 | `script_injection` | v2 rule (cross-origin `src`, harness / own-page / welcome-tab exclusions) applied only to `node_injected` records with `node_attributed == "extension"` (A2) | light | 15 |
| T2-8 | `page_api_hooking` | the A4 check finds `fetch`, `XMLHttpRequest.prototype.open` / `send` or `WebSocket` replaced or non-native at the end of any harness page visit | light | 15 |
| — | `beaconing` | v2 rule (≥ 4 requests, CV ≤ 0.25, mean ≥ 0.5 s), restricted to extension-initiated requests | light | 5, +5 if the host is undeclared |
| — | `causes_page_hang` | v2 rule | light | 10 |
| T2-1 | static (permissions, suspicious hosts, broad scope) | computed as in v2 | **display only** | 0 |

Persistent identifier (T2-3): a UUID v4 (8-4-4-4-12 hex digits, version digit 4, variant 8–b)
in the URL or body of extension-initiated requests to the same host, seen in at least two
distinct phases (by timestamp, T1-6). It must not occur in the extension package itself, when
the package is available to the scorer; this excludes hard-coded keys.

Cookie (T2-3): the honey pages set no cookies, so a cookie value of a visited site cannot
be told apart from the extension's own cookies on its own server. Cookies therefore count
only through the honeypot markers. This is a stated limit, not a rule.

T2-4 features (reported, not scored): the redirect chain from `first_url` to `final_url`;
the number of distinct registrable domains in it; final URL; titles; seconds since install;
the SW call (`tabs.create` / `tabs.update` / `windows.create`) that opened it, if recorded.

## Score and level

`score = min(100, Σ weights of the signals that fired)`. The static score is reported next to
it and not added. Levels are the same as in v2: ≥ 90 CRITICAL, ≥ 70 HIGH, ≥ 40 MEDIUM,
≥ 15 LOW, otherwise MINIMAL. **Flag = score ≥ 40 (MEDIUM or higher)**, same threshold as v2.

## Why these weights

- **Rule of thumb.** One heavy signal flags a sample by itself. Light signals need at least
  three of different kinds (3 × 15 = 45, or 20 + 15 + 5 = 40). Two light ones never
  flag (at most 20 + 15 = 35). The post-hoc FP analysis (`eval/expanded/fp_cause/`) found
  that 98 of 127 v2 false positives were benign by design, which is behaviour that weak
  signals add up to.
- **Static display only.** Static took part in 124 of the 127 v2 FPs. It measures
  capability, not behaviour.
- **credential_exfil 80.** Same as v2: honeypot credentials leaving the browser have no
  benign reading. It now needs extension attribution, so a page that posts its own form
  no longer counts.
- **history_exfil 50.** Browsing-history collection is the main harm in the reviewed
  collectors (clickstream SDKs, `eval/expanded/sdk/`). Matching a visited URL with its path
  is specific: a bare domain is excluded because coupon / shopping extensions look domains
  up legitimately. 50 is below credential_exfil (credentials are worse) and above the flag
  threshold.
- **affiliate 40.** Unchanged from v2 (`risk.AFFILIATE_HIJACK_WEIGHT`, reasons there). The
  `tag` restriction removes a false match on non-Amazon sites, where `tag` is an ordinary
  parameter name.
- **undeclared with user data 40 / without 15–20.** Contacting an undeclared host is common
  and benign by itself (telemetry, CDNs). Sending user data to it is not. v2 gave 30 to any
  undeclared SW host, whatever it carried.
- **tab / injection / hooking 15.** Each has benign uses: welcome pages, UI widgets, ad
  blockers wrapping `fetch`. Each alone stays LOW.
- **beaconing 5–10.** Periodic telemetry is common in benign extensions. It is kept only as a
  minor contributor.
- **local_harvest 30, page hang 10.** Unchanged from v2.
