# v3.1-probe: eliciting behaviour that waits for a user action (design + feasibility)

Status: design and a feasibility prototype on 5 development samples. Nothing frozen is changed:
`FREEZE_v3.md`, `score_v3.py`, `SCORING_v3.md`, `sandbox_v3/` and the image `extprobe-sandbox:v3`
(`sha256:0e4016d1…`) stay as they are. Branch `probe-dev`; prototype sandbox in `sandbox_v3_1_probe/`
(image tag `extprobe-sandbox:v3.1-probe`, built `FROM extprobe-sandbox:v3`, adding only `/sandbox/v31/`).
Samples of the blind-labelling dossiers (`itw/labeling/mapping.csv`) and of in-the-wild sets A / B are
excluded automatically from every trial; no extension id is printed or written here.

## 0. Motivation and label check

Socket (2026-08-11) reports 737 VPN / proxy extensions whose SOCKS5 / PAC routing is switched on only
"once the user clicks Connect". A sandbox that never clicks can only see their install-time behaviour.

Label check (counts only): the saved Socket page contains **739** extension-id strings. Of the **41** T2
samples of set A (`eval/v3/in_the_wild/label_tiers_A.csv`), **40** cite that report, but only **1** has its
id in the page's list; `id_listing_verified` is `no` for all 41. The T2 assignment of the other 39 rests on
the name (or on a source that cites the report), not on the id. This should go to the labelling review
before T2 results are quoted.

## 1. What the current `extension_pages` phase does

`sandbox/phases/actions.py::_probe_extension_pages` (v2, also used by v3): for at most 2 extension ids seen,
it tries the fixed paths `popup.html`, `popup/popup.html`, `options.html` in a new tab
(`goto`, `wait_until="commit"`, 4 s), keeps the first that opens, waits 2.5 s, takes a screenshot and
closes it. It **does not read the manifest** and **never interacts** (no click, no input).

On the 610 development traces (v3): 290 extensions declare a popup, but only 142 of those popups are at one of
the three guessed paths; 144 declared popups were never opened; 189 extensions had some page opened at all;
16 request the `proxy` permission.

## 2. Explorer (after the v3 phases, in the same browser)

Order of a v3.1-probe run: the five v3 phases exactly as in v3 → `probe_explore` → `probe_target_matched`.

- **Pages**: the manifest's `action.default_popup` / `browser_action.default_popup`, then `options_page` /
  `options_ui.page`, each opened as a tab `chrome-extension://<id>/<path>` (popup viewport 420×640).
- **Elements**: visible, enabled `button`, `[role=button|switch|checkbox|tab|menuitem]`, `a[href]` inside the
  extension, `input[type=checkbox|radio|submit|button]`, `summary`, `[onclick]`; `select` kept for a later
  version. Label = `aria-label` / text / value / title / associated `<label>`.
- **Priority** by label: connect, start, enable, activate, protect, turn on, on, continue, next, accept, allow,
  scan, apply, save, ok, get started, agree, unlock, secure; then switches / checkboxes; then the rest.
- **Never clicked** (deny list, matched as word **prefixes**, so plurals / inflections are caught:
  "Payments", "Reports", "Deleting"): uninstall, remove, delete, clear, reset, erase, buy, purchase, pay,
  checkout, upgrade, premium, subscribe / unsubscribe / subscription, pricing / price / plan / billing,
  log out / log off / sign out / sign off, report, share, rate / review / feedback, donate, contact / support,
  and informational links (privacy, terms, disclaimer, FAQ, help, learn more, about, tutorial, website);
  log-in / sign-up controls (recorded as `login_gate`, never passed). External links (`http(s)://`,
  `mailto:`, `tel:`) are not clicked: they would only open a web tab. **Controls without a label** (no
  letter: icons, symbols) and **controls whose label is not English** (letters outside ASCII) are never
  clicked either — the deny list cannot be checked on them; counted as `skipped_unlabeled` /
  `skipped_non_english` (a Latin-script label in another language still passes: known limit).
- **Search**: state = hash of (tag, label, checked) of the visible elements + title + text length bucket.
  BFS over states, depth ≤ 3, at most 15 clicks per sample, **≤ 30 s** for the explorer. The same element
  is not clicked twice (key = element position, not label: the prototype keyed on the label and so clicked
  only one of several toggles labelled "on").
- **Forms**: before clicking inside a `<form>`, empty inputs get the honeypot values already used by the
  harness (`honeyuser…`, `HONEYPOT-PASSWORD`).
- **Click**: Playwright click (1.5 s); if an overlay intercepts it, `element.click()` dispatched in the page.
- **After the explorer**: `phase_target_matched_v3` once more (the same served pages), to see behaviour "after
  enabling" (affiliate rewriting, injection, history upload that start only once switched on). In the
  prototype this re-run takes 22–32 s; the production version should visit only the product page of the
  first target host to keep the extra time near 30 s in total.

## 3. What is recorded after every click

Per stimulus: `stimulus_id`, page, depth, label, click result, DOM state before / after, new tabs, then a
snapshot taken **inside the extension's own page** (same permissions as the extension):
- the number of `declarativeNetRequest` dynamic and session rules;
- `chrome.storage.local` keys with value sizes (no values).
Calls to `chrome.proxy.settings.set / clear` and to the DNR update functions are recorded in every extension
context from the load phase on by the proxy guard (§5), with their arguments (4 / 2 kB); the proxy is read from
the guard's records, not from a snapshot (inside an extension page `get` now returns the faked value).
Requests, tabs and DOM events after the probe start are recorded by the unchanged v3 sensors.

## 4. Causality and separation from the v3 trace

`analyze_v31.py` notes `probe_t0` before the explorer, reads the extension storage then (so a value typed
by the explorer cannot appear in the v3 storage fields), and at the end **splits** the trace:
- `events.json`: every list item with `ts < probe_t0`, the pre-probe storage, `honeypot_exfil` recomputed
  from the pre-probe details, `run_status` decided before the probe phases (which are kept out of
  `phases`). Same schema as v3, so `score_v3` reads it unchanged.
- `events_probe.json`: every item with `ts ≥ probe_t0`, each with `cause_class` / `cause_reason` (and the
  preceding `stimulus_id` when caused by a click), the probe log, the probe phases, and the post-probe storage.

Causal class (after the review of 2026-10-11: by origin, **not by a time window**; `v31_split.Causes`):
- `user_initiated` — `typed_input`: carries a PROBE value the explorer typed; `ui_tab`: request / tab /
  navigation of a UI tab (an extension page the explorer opened, a tab whose opener chain leads to one —
  Playwright `page.opener()`, or a tab whose URL a UI-linked SW call asked for), matched by URL with the
  requests Playwright attributes to that tab; `extension_frame`: request or DOM node of a `chrome-extension://`
  frame; `sw_message_from_ui`: service-worker request / tab call whose JS stack goes through a
  `runtime.onMessage` listener run for a message from one of the extension's pages (guard record
  `xp.caused_by_ui`; sync frames, and async frames through `await`: the guard makes itself the only consumer of
  the listener's promise, since V8 follows an async stack only through a promise with a single reaction, and
  hands Chrome its own promise with the same value).
- `post_probe` — everything else; in particular a service-worker request with no such chain is **not**
  user-initiated, however close to a click (timers, `setInterval`, `storage.onChanged`, `.then` chains and
  long-lived ports are not followed: conservative towards keeping behaviour in the view).
- Unit tests both ways (`tests/v31/test_v31_probe.py`): SW request 1 s after a click, unlinked → kept;
  the popup's own request 3 s after the click → dropped; SW request linked to the popup's message, 3 s
  later → dropped. End-to-end on the synthetic extension (`feasibility/guard_check.py`): `from-msg` (SW,
  after two awaits in the listener) → `sw_message_from_ui`; `sw-spont` (SW timer 0.6 s after the message) and
  `sw-tick` (SW interval) → `post_probe`; `popup-late` (popup, 1 s after the click) → `ui_tab`.

How `score_v3` would read probe events if they were merged into `events.json` (why they are not):

| probe event | v3 field | `score_v3` effect |
|---|---|---|
| tab opened by a button in the popup | `tabs_v3` (opener = extension page, so `extension_opened`) | `unsolicited_tab` +15 for a user-requested tab |
| requests of the popup / options page itself (login, settings) | `page_request_initiators` attributed `extension` | undeclared-host contact, possibly `history_exfil` (a popup that looks up the current site) |
| SW requests triggered by a click | `network_requests` (`cdp_sw`) | undeclared-host contact |
| honeypot value typed by the explorer and sent / stored | `honeypot_exfil_details`, extension storage | `credential_exfil` +80, `local_harvest` +30 |
| requests and hooks during the re-run of target_matched | as in v3 | the behaviour we want to see, but after a user action |

Prototype check on 5 samples: `score_v3(events.json)` of the v3.1-probe run equals the v3 dev score of the
same sample in **5 / 5** cases; a naive merge of both files raises 2 of 5 by +5 (extra undeclared hosts)
and changes no flag. Proposed scoring of the probe, **without editing `score_v3`**: a separate
`score_v31.py` (new file) builds a filtered view — pre-probe events + post-probe events that are not
`user_initiated` and not issued by the popup / options frame, plus `probe_target_matched` events — calls the
unchanged `score_v3.score_trace` on it, and reports the probe-only signals (proxy configured, DNR rules
added, storage changed) next to it. Both scores are reported; the v3 score is never replaced.

## 5. Network safety (proxy guard; replaces the iptables egress gate after the review of 2026-10-11)

A probe must not send the sandbox's traffic through an attacker proxy. The first implementation let
`proxy.settings.set` run after an iptables block of the proxy hosts (root helper, `NET_ADMIN`); the review asked
for a design in which no extension proxy configuration can take effect at all. `v31_guard.py`, active from
before the extension is loaded to the end of the run (load phase included):

1. **Managed Chrome policy `ProxyMode=direct`**, written into the image (root-owned, 0644) before Chrome starts:
   `/etc/opt/chrome_for_testing/policies/managed/extprobe_proxy.json`. Evidence that this is the path the image's
   browser reads (Chrome for Testing **153.0.8010.12**, `/ms-playwright/chromium-1243/chrome-linux64/chrome`,
   one launch per candidate directory, `ProxyMode=direct` in it):

   | candidate directory | `chrome://policy` row | extension `proxy.settings.get` before → after its own `set(fixed_servers)` |
   |---|---|---|
   | (none) | `ProxyMode` not set | `system`, `controllable_by_this_extension` → `fixed_servers`, `controlled_by_this_extension` |
   | `/etc/opt/chrome/policies/managed` | not set | same as without policy (proxy applied) |
   | **`/etc/opt/chrome_for_testing/policies/managed`** | **`ProxyMode direct · Platform · Machine · Mandatory`** | **`direct`, `not_controllable` → `direct`, `not_controllable`** |
   | `/etc/chromium/policies/managed` | not set | same as without policy |
   | `/etc/opt/chromium/policies/managed` | not set | same as without policy |

   The binary contains only the string `/etc/opt/chrome_for_testing/policies`. **`ProxyMode` is marked
   *Deprecated* by Chrome** (the `chrome://policy` row above says so) but is still applied by Chrome for Testing
   153 (`not_controllable`, the extension's `set` has no effect). If the browser is changed or updated, switch
   to the `ProxySettings` policy (`{"ProxyMode": "direct"}` inside it) and repeat this check before any run. Every run checks it again: the
   harness reads the effective configuration right after the load phase (`policy_in_force` = `direct` +
   `not_controllable`), and `run_probe.ps1` refuses to start if the file is missing or different in the image.
2. **Recorder of `chrome.proxy.settings.set / clear / get`** in every extension context: `set` stores the
   configuration and reports success without calling Chrome, `get` returns the configuration the extension
   "set" (else what an unmanaged browser shows: `system`, `controllable_by_this_extension`), `clear` resets it.
   The extension therefore behaves as if its proxy were on, while Chrome never receives it.
   - service worker: first start — the guard is appended to the v3 SW hook string at run time (injected at the
     worker's first statement by the unchanged v3 sensor); **restarts** — the v3 DevTools session survives a
     worker restart and v3 hooks a session only once, so `PageGuard`'s own session keeps an instrumentation
     breakpoint (`beforeScriptExecution`) and injects the guard at every such pause (the pauses are per session
     in Chrome 153; v3's resume is held ≤ 0.3 s until the guard is in, through a run-time wrapper of v3_cdp's
     websocket module; `PageGuard` resumes its own pause 50 ms after the injection, any pause after 1.5 s).
     (Tried first and rejected: a conditional breakpoint at line 0 whose condition installs the guard — Chrome
     153 does not run such a condition, not even outside restarts.)
   - pages: `PageGuard`, a separate CDP client with auto-attach (`waitForDebuggerOnStart`), adds the guard with
     `Page.addScriptToEvaluateOnNewDocument` to every page / iframe / other target before it runs: popup,
     options, pages they open, offscreen documents (type `other`), extension iframes inside web pages. The
     script returns at once outside `chrome-extension://` documents that have `chrome.proxy`.
   Records go to `api_calls` (SW, via the v3 console channel) and `events_probe.json → proxy_guard.page_calls`.
3. **Monitor of the effective configuration**, harness side, with the real `get` (kept reachable for the
   harness only): right after the load phase, at the probe start, at the probe end and every 2 s; anything other
   than `direct` is cleared at once and recorded as `proxy_unwrapped_set = true`.

No `NET_ADMIN`, no iptables, no root helper, no gate on 127.0.0.1 (all removed); the container has the same
capabilities as v3. **End-to-end check** (`eval/v3_1_probe/feasibility/guard_check.py`, synthetic extension
with `proxy`: SW sets `fixed_servers` at its first statement, popup "Connect" sets a PAC script; the self-test
switch `PROBE_SELFTEST_STOP_SW=1` stops the worker at the probe start with `ServiceWorker.stopWorker`): policy in
force; effective configuration `direct` in all 15 monitor snapshots; the SW `set` recorded and faked **before
and after** the forced worker stop, and `get` answered with the faked value in both worker starts; the popup's
PAC `set` recorded by the page guard; the offscreen document attached (`other`).

## 6. Metrics

- **Elicitation yield** (main) = samples with new behaviour after the explorer / samples run. New behaviour
  = any of: a proxy configuration (logged `set`, or a snapshot showing a fixed / PAC proxy controlled by the
  extension); a DNR dynamic / session rule added or removed; a new extension-initiated request host (SW or
  content script on harness pages, not the popup / options frame) absent from the pre-probe trace;
  a significant storage change. The prototype used "≥ 1 new key or ≥ 3 changed keys", which counts UI
  preferences (a selected country): it should be reported apart, and the main yield computed **without**
  storage.
- Secondary: samples whose `score_v3` flag at 40 changes between `events.json` and the filtered view of §4;
  benign samples newly flagged.

## 7. Feasibility prototype (5 development samples: 3 malware, 2 benign; none from sets A / B or the dossiers)

Run with `eval/v3_1_probe/run_probe.py` (image `extprobe-sandbox:v3.1-probe`, timeout 240 s); traces local.
M1 = malware VPN with the `proxy` permission; M2, M3 = malware with a popup; B1 = benign VPN with `proxy`;
B2 = benign extension with a popup and an options page (seed 2026 among eligible development samples).

| | popup / options opened | elements | clicks done | outcome | explore s | run s (v3 dev) |
|---|---|---|---|---|---|---|
| M1 | popup | 4 | 1 | only "Log in" / "Sign up" (external) besides a country selector: **login-gated**, Connect not reachable | 2.2 | 78 (53) |
| M2 | popup | 25 | 3 | Playwright clicks intercepted by an overlay; dispatched clicks worked; 2 new extension hosts after the clicks | 9.6 | 81 (48) |
| M3 | popup | 3 | 0 | only an external "install" link and two informational links | 0.9 | 92 (59) |
| B1 | popup | 1 | 2 | "Got it" → **`proxy.settings.set` with a PAC script** (recorded, not executed); storage changed; a private-range address contacted | 3.4 | 28 (26) |
| B2 | popup empty, options page | 0 / 26 | 9 | tabs between settings sections; 2 new storage keys; 3 new hosts | 13.7 | 103 (58) |

- Pages: 5 / 5 opened from the manifest path. Elements found: 1–26 per page.
- Clicks generated new API calls in 1 of 5 (the PAC proxy of B1), new extension hosts in 3 of 5.
- Yield: 4 / 5 with storage, **3 / 5 without** (M2, B1, B2). M1 shows the main limit: VPN apps behind a
  login cannot be switched on without an account.
- Extra time: explorer 1–14 s; the target_matched re-run 0–32 s (0 when the extension has no concrete
  target host); in total +2 to +45 s per sample.
- `score_v3` on `events.json`: identical to the v3 dev score in 5 / 5.

## 8. Known limits

Login walls (the probe cannot create accounts); popups built in shadow DOM or iframes (not enumerated yet);
`select` menus; behaviour gated on a remote configuration or a timer still needs the server to answer
(see `eval/v3/audit/report.md`, group A); the explorer runs once and its order of clicks is a heuristic;
unlabeled / non-English controls are skipped (a toggle without a label is never switched on); the guard's
"faked" proxy state is per context (a `get` in the popup does not see what the service worker "set");
the causal tagging matches by URL inside a time window (a UI tab's request ±3 s, a SW request 0–10 s after a UI-linked
SW call to the same URL, a tab ±10 s around a UI-linked SW `tabs.create`): a spontaneous request or tab with exactly the same URL inside that window would be merged
with the user-initiated one and dropped from the view (small risk, errs towards dropping); SW-side causal links
follow `runtime.onMessage` only (not long-lived ports, `storage.onChanged`, timers,
plain `.then` chains), which errs towards keeping behaviour in the scored view.

## 8b. Limitation of v3 / v2 (found while redesigning the proxy guard)

**The earlier profiles do not block a proxy set by the extension.** The v2 image and the frozen v3 image
(`extprobe-sandbox:v3`, `sha256:0e4016d1…`) launch Chrome without any proxy policy and do not wrap
`chrome.proxy`: an extension with the `proxy` permission that calls `chrome.proxy.settings.set` gets
`controlled_by_this_extension`, and from then on the browser's traffic in that run — honeypot pages, target
pages, the extension's own requests — goes through the extension's proxy (checked in the v3 image: §5, row
"(none)": `set(fixed_servers)` took effect). Neither profile records such a call either (the v2 API hook covers
`management.uninstall`, `tabs.remove`, `runtime.setUninstallURL`, `webRequest.onBeforeRequest`, `Function` /
`eval`; v3 adds tab / window calls). Consequences for the published v2 / v3 results, stated as limits and not
re-measured: (1) a run of such an extension may have sent harness traffic, including honeypot values typed by
the harness, to an attacker-controlled proxy; (2) the proxied requests still appear in the trace (the sensors
sit in the browser), so detections are not lost, but the network side differs from an unproxied run; (3) how
often it happened is unknown — 16 of the 610 development extensions request `proxy`, and the frozen traces do
not record proxy calls. v3.1-probe closes this from the load phase on (§5); the v3 configuration stays frozen.

## 8c. Known limitations of v3.1-probe (after the trial, 2026-10-11)

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

Details and counts: `posthoc.md`. The trial results (`results.md`) are unchanged.

## 9. Remaining effort (estimate)

| item | hours |
|---|---|
| explorer hardening (element keys, shadow DOM / iframe, `select`, login-wall detection and reporting) | 6–8 |
| SW-start proxy / DNR wrappers in the v3.1 image (run-time hook extension, no frozen edit) | 2–3 |
| egress guard (entrypoint rules, root helper, PAC parsing, `NET_ADMIN` only for this image) and tests | 5–7 |
| `score_v31.py` filtered view + probe-only signals + unit tests on synthetic traces | 4–5 |
| trial set (set A T2 VPN minus dossiers, 50 test benign), runner pairing v3 / v3.1 in one batch | 2–3 |
| runs (≈ 90 samples × 2 images, ~2.5 h wall) and checks | 3 |
| analysis and write-up | 4–6 |
| **total** | **26–35 h** (plus compute) |

## 10. Implementation status (steps 1–2, commits after ace5281)

- `sandbox_v3_1_probe/`: `v31_policy` (pages from the manifest, priority / deny list, login gate), `v31_explorer`,
  `v31_split`, `v31_target` (product page of the matched hosts only, while the extra time stays <= 45 s),
  `v31_egress` + `egress_helper.py` (root, iptables; NET_ADMIN for this image only) — **superseded and removed**
  after the review of 2026-10-11 by `v31_guard` (§5: managed policy, recorder in every extension context,
  monitor; no capability added).
- `eval/v3_1_probe/score_v31.py`: filtered view (§4) scored by the unchanged `score_v3`; probe-only facts reported
  apart; no new detector.
- Check on the same 5 development samples (image `extprobe-sandbox:v3.1-probe`):
  `score_v3(events.json)` = dev v3 score in 5 / 5; extra time 3–40 s (explorer <= 29 s); B1's PAC proxy was set
  after its 3 hosts were blocked, 9 packets towards them were rejected and 0 left the container; M1 is marked
  `login_gate`; `score_v31` changes one score (45 -> 50, no flag change); yield (without storage) 3 / 5.
- Tests: `tests/v31/` (policy, split, PAC parsing, filtered view; an empty probe gives exactly the score_v3 score).
- Review round of 2026-10-11 (commits `cf96d64` … `2950106`): deny list by prefix / plural, unlabeled and non-English
  controls skipped (§2); proxy guard instead of the egress gate (§5); causal class by origin (§4); runner refuses an
  existing trace folder and the wrong branch; image `sha256:2ae86e6e…`. Checks on that image: the 5 development
  samples give `score_v3(events.json)` = dev v3 score 5 / 5 and, with an empty probe file, `score_v31` = `score_v3`
  5 / 5; managed policy confirmed in 5 / 5 runs, no `proxy_unwrapped_set`; extra time 7–43 s;
  `feasibility/guard_check.py` 13 / 13; `run_probe.ps1 -Trial` on 2 other development packages: both complete.

## 11. Beaconing check (review 2, 2026-10-11)

Question: does the v3.1 harness (proxy monitor, guard sessions) change what the `beaconing` detector sees in the
v3 part? 3 development samples whose earlier v3 trace fired `beaconing` (seed 2026 among the 10 eligible: complete
trace, package present, not in the dossiers or the 5 samples above), run the same day with the frozen v3 image
(`eval/v3/run_v3.py`) and with v3.1-probe (`sha256:67d0ebe6…`). CV = pstdev / mean of the intervals between the
extension's requests to the beacon host (threshold 0.25, at least 4 requests).

| sample | v3, earlier dev trace | v3 today | v3.1 `events.json` today | v3.1 `score_v31` view |
|---|---|---|---|---|
| BC1 | fired, CV 0.232, score 40 | **not** fired, CV 0.298, score 30 | fired, CV 0.238, score 40 | not fired, score 30 |
| BC2 | fired, CV 0.204, score 50 | fired, CV 0.209, score 50 | **not** fired, CV 0.562 (one 7.7 s interval), score 45 | not fired, score 45 |
| BC3 | fired, CV 0.247, score 35 | fired, CV 0.239, score 35 | **not** fired, CV 0.266, score 30 | not fired, score 30 |

- The "beacons" are content-script requests that follow the harness's page visits (~2–5 s apart), not a timer;
  every CV is close to the 0.25 threshold, and the frozen v3 image alone flips BC1 between two runs.
- The phase durations of the v3 part are the same in all runs (load 3.0–3.1 s, honeypot_pages 14.1–14.6 s,
  target_matched 31.6–33.0 s), so the harness does not slow the page cadence; the differences are per-request
  jitter. Flips go both ways (BC1 v3.1 fires where v3 today does not; BC2 / BC3 the reverse).
- With 3 pairs this neither shows nor excludes an effect of the v3.1 harness on this borderline detector. The
  `score_v31` view adds post-probe requests to the same host series, which can break the regularity (BC1).
  Reported as a limit of the trial: flag changes driven only by `beaconing` must be read with this in mind.
