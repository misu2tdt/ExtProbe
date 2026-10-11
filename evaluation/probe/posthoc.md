# v3.1-probe trial: post-hoc analysis (NOT pre-registered)

**Post-hoc.** None of the breakdowns below was registered in `CRITERIA.md`; they were asked for after reading
`results.md` (commit `4886e2d`, unchanged). They only read the existing traces of the trial (`traces_a/b/c`), nothing
was run again, and nothing here replaces a number of `results.md`. Aggregates and types only: no extension id, no
host of a proxy configuration, brand names in button labels generalised. Set (a) = 43 set-A extensions silent
under v3; (b) = 50 test-benign extensions; (c) = the 1 T2 extension listed by Socket.

## Erratum (added after the first version of this file)

The row **"proxy guard: set() calls intercepted after the probe start (samples / calls) = 1 / 1"** in `results.md` is
not a proxy configuration and not an action after the probe start. It is a `chrome.proxy.settings.set` call with
`{"value": {"mode": "direct"}}` made by the extension's service worker at start-up, in the v3 part of the run (about
45 s before the probe start). `analysis.py` counted it because its console replay (a new DevTools session replays the
worker's console with the original timestamp) arrived after the probe start and was not filtered for this row.
`results.md` is left exactly as generated; read that row as 0 / 0. The row "proxy configured" (0 / 43) is correct.

## 1. Yield with and without clicks

| set | group | n | yield | DNR | new extension host | storage (apart) |
|---|---|---|---|---|---|---|
| (a) | 0 clicks | 24 | 6 | 4 | 3 | 0 |
| (a) | ≥ 1 click | 19 | 7 | 2 | 6 | 4 |
| (b) | 0 clicks | 31 | 7 | 2 | 5 | 0 |
| (b) | ≥ 1 click | 19 | 7 | 3 | 4 | 6 |

- Almost half of the yield comes from samples where **nothing was clicked** (6 / 13 in (a), 7 / 14 in (b)): opening
  the popup / options page from the manifest (and the re-run of target_matched) is enough.
- Inside the clicked samples with yield, much of it starts **before the first click**: (a) 7 samples — a new host
  before the first click in 4, only after it in 2; a DNR call before the first click in 2, after it in 1.
  (b) 7 samples — new host before 3 / only after 1; DNR before 3 / after 3.
- So the yield is mostly a "page opened" effect, not a "clicked" effect; clicks add storage changes (UI preferences)
  and a few hosts.
- Why 24 (a) samples had no click: every control skipped as **non-English** 7 (+1 non-English + unlabeled), deny list
  5 (+3 with unlabeled, +2 with external links), page with 0 interactive elements 4, unlabeled only 1, login gate 1.
  (b), 31 samples: no page opened 16, page with 0 elements 6, only external links 3 (+1 with deny), unlabeled only 3,
  `select` only 1, login gate 1.

## 2. "1 set() intercepted" but "proxy configured 0 / 43"

- **Definitions.** "proxy configured" (main yield) counts only a `set` with mode `fixed_servers` or `pac_script`
  (CRITERIA amendment 1). "set() calls intercepted after the probe start" counted every `proxy.settings.set` record in
  the post-probe `api_calls`, whatever its mode.
- **The one record** (one (a) sample): `{"value": {"mode": "direct"}, "scope": "regular"}` from the service worker —
  a request to use **no proxy**, no host in it. Its timestamp is **45.6 s before the probe start** (v3 part, around
  the extension's start-up, no click before it); the same call also appears twice in the pre-probe harness records.
  It reached the post-probe list as a **console replay** (a new DevTools session replays the worker's console with
  the original timestamp; amendment 2 cuts `api_calls` by arrival order) and was tagged `harness_record / guard`.
  It is therefore neither a configured proxy nor an action after the probe start: the "1 / 1" row of `results.md`
  is a counting artefact of `analysis.py` (it neither filters by `ts ≥ probe_t0` nor drops replays for this row).
  Recorded here; `results.md` is left as generated.
- (See the erratum at the top.) No sample of (a), (b) or (c) issued a `fixed_servers` / `pac_script` / SOCKS configuration at any time of the run.

## 3. Controls never clicked (unlabeled / non-English)

Labels as seen in the first snapshot of each page (first 30 controls, truncated to 24 characters; counts = pages):

| meaning | labels (translation) | (a) | (b) | (c) |
|---|---|---|---|---|
| **connect / turn VPN on** | «Включить VPN» (turn on VPN) 3, «Переключить VPN» (toggle VPN) 4, «Подключиться» (connect) | **7** | 0 | **1** |
| premium / pay | «Оплатить» (pay) 4, «Получить премиум (бесплатно)» (get premium (free)) 7, «⚡️ Получить Premium бесп…» (get Premium free) | 11 | 0 | 1 |
| log in / account | «Войти» (log in), «Создать новый» (create new), «Giriş Yap» (log in), «Beni hatırla» (remember me) | 4 | 0 | 0 |
| navigation / settings | «Yönetim Paneli» (dashboard / admin panel) | 1 | 0 | 0 |
| location / region | «Выбор локации» (choose location); Japanese region and prefecture lists (Hokkaidō–Tōhoku, Kantō …; Ibaraki … Tokyo, Kanagawa) | 0 | 2 | 1 |
| other | an author credit (a person's name with a diacritic) | 0 | 1 | 0 |

Unlabeled controls: (a) 8, (b) 25, (c) 0.

- **(c)**: the 3 skipped labels are «Выбор локации» (choose location), «⚡️ Получить Premium бесплатно» (get Premium for
  free) and **«Подключиться» (connect) — the exact equivalent of "Connect"**. The probe never clicked it.
- In (a), **7 samples show a Russian connect / turn-on-VPN control; all 7 request the `proxy` permission** (7 of the 8
  (a) samples with that permission), none was clicked and none had any yield. Together with (c), the non-English rule
  (added in the first review, labels with letters outside ASCII are not clicked) removed exactly the stimulus the
  trial was designed for, on 8 of the 9 VPN-like samples. This is the main limit of the trial's result for VPN
  extensions: "proxy configured 0 / 43" says nothing about those 8.

## 4. New extension hosts: type of host and of data

Host classes by heuristic: analytics / SDK (known service names), CDN (known CDN / static hosts), first-party (the
registrable domain occurs in the package or the manifest), other.

| | (a) | (b) |
|---|---|---|
| samples with a new host | 9 | 9 |
| source of the requests | 13 from extension-attributed page requests, 0 from the service worker | 16 page, 15 service worker |
| CDN — requests (samples) | 7 (5), no data | 4 (3), no data |
| first-party — requests (samples) | 6 (5): 4 no data, 1 with a body, 1 with a page URL / site | 21 (5): 14 no data, 7 with a body (1 with an ID) |
| analytics / SDK — requests (samples) | 0 | 6 (2): all with an ID and a body (an error-reporting SDK and an event-analytics SDK) |
| "other" | 0 | 0 |
| cookie header | 0 | 0 |

- No difference **in kind** that points at (a): its new hosts are CDNs and the extension's own domains, almost
  without data (1 request carries a page URL / site parameter, 1 a body). (b) shows more, and more data-carrying,
  traffic (service-worker calls to its own backend, analytics with install IDs) — ordinary benign telemetry.
  The "new host" part of the yield is therefore not by itself a sign of malicious behaviour.

## 5. DNR changes

| | (a) — 6 samples | (b) — 5 samples |
|---|---|---|
| block rules | 0 | 0 |
| redirect | 13 (`regexSubstitution` 7 with a `regexFilter`, `transform` 6 with a `urlFilter`) | 33 (`regexSubstitution` 18, `extensionPath` 15) |
| modify headers | 0 | 13 rules: set / remove `user-agent`, `accept-language`, `accept`, `referer`; set app-specific headers of a streaming service |
| allow | 0 | 34 (conditions on response headers) |
| rule removals | 19 | 67 (+11 empty updates) |
| CSP removal | 0 | 0 |

- All changes were seen as calls (none only in the rule-count snapshot). (a) only redirects (URL rewriting by
  pattern) and removes rules; whether the redirects are harmful cannot be told from the rules alone (targets are
  derived from the matched URL). (b) does more, including header rewriting for one streaming service — no
  security-header (CSP) removal on either side.

## 6. (b): 34 / 50 samples with a page opened

15 declare **no popup and no options page** (nothing to open), 1 declares one but the open failed (the browser
context was closed during the explorer: `Target page, context or browser has been closed`), 34 opened. Of the 34,
9 had a page with **0 interactive elements** (empty popup or content built later / in a frame the explorer does not
enumerate).

## 7. Score changes without a flag change

| set | changes | detector |
|---|---|---|
| (a) | 8 | all **0 → 15**, `unsolicited_tab` +15 |
| (b) | 4 | 0 → 15 (2) and 20 → 35 (1), `unsolicited_tab` +15; 30 → 35 (1), `undeclared_domain_contact` +5 |

The tabs behind the +15 (extension-opened tabs tagged `post_probe` in the view):

- (a), 8 samples: 22 tabs, all opened **during the explorer, 0.2–2.7 s after a click** (median ≈ 0.7 s); the detector's list has
  19 web pages, 1 browser settings page and 1 error page. The click just before was "Search selected" / "Search & compare" / "Search"
  (16), "Open … page" / "Go to … app" (2), a portal link, "Latest news", "Set as default", "STOP". The tracker saw
  these tabs as `other` (no opener: the popup most likely opened them with `chrome.tabs.create`, which neither
  leaves an opener nor goes through the service worker, so no causal link was recorded).
- (b): 1 tab 0.1 s after a click on a "group" link, 1 browser page (`chrome://extensions`) 0.8 s after a click, and
  1 web tab during the re-run of target_matched with no click before it.
- **Reading**: in (a) all 8 and in (b) 2 of the 4 score changes are very probably **user-requested tabs that the
  causal tagging missed** (a gap: tabs created directly by an extension page via `chrome.tabs.create` are not linked
  to the click), not behaviour elicited by the probe. Only the (b) target_matched tab and the (b) +5 host contact are
  candidates for genuine post-probe behaviour. No flag changed in any case.

## Summary

- Yield ≈ 30 % in both (a) and (b), and about half of it needs no click: it measures mostly what opening the
  extension's own pages triggers, and the kinds of behaviour seen in (a) (CDN / own-domain hosts, URL redirect rules)
  are not more suspicious than those in (b).
- The trial did **not** test what it was designed for on VPN extensions: 7 of the 8 (a) samples with the `proxy`
  permission and the (c) case show a Russian "connect / turn on VPN" control that the non-English rule skipped.
- The "1 intercepted set()" is a replayed `set({mode: "direct"})` from the v3 part, not a proxy configuration.
- The score changes are almost all `unsolicited_tab` +15 from tabs opened by the popup right after a click and not
  linked to it (a causal-tagging gap); no flag changed.

## Known limitations of v3.1-probe

- **Proxy behaviour of 8 VPN-like extensions was not tested.** 8 samples that request the `proxy` permission (7 of
  set (a) and the case of set (c)) have a primary button in Russian ("connect" / "turn on VPN" / "toggle VPN"). The
  English-only click rule (labels with letters outside ASCII are never clicked) skipped it, so what they do after
  "connect" — in particular whether they set a proxy — is unknown. "Proxy configured 0 / 43" and the case study
  of set (c) say nothing about them.
- **`chrome.tabs.create` called from an extension page is not recorded.** The guard records tab calls only in the
  service worker; a popup or options page that opens a tab itself leaves no record and, with no opener, no causal
  link to the click. Such tabs are tagged `post_probe` and enter the `score_v31` view as `unsolicited_tab`. This is
  the source of the score changes 0 → 15 (and 20 → 35) in the trial: tabs opened 0.2–2.7 s after a click, not
  behaviour elicited by the probe (`posthoc.md` §7).
- **The yield mostly comes from opening the pages declared in the manifest, not from clicking.** About half of the
  samples with yield had no click at all, and in the clicked ones much of it starts before the first click
  (`posthoc.md` §1). Clicks add mainly storage changes. The yield measures what the extension's own pages trigger.
