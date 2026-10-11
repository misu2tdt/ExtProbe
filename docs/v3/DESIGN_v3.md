# ExtProbe v3 sensor design (profile `v3`)

Why v3: see `eval/expanded/posthoc/fp_cause/summary.md` and `eval/expanded/posthoc/v3m/report.md`.
- v2 cannot attribute **page** requests or injected nodes to the extension: provenance is kept per
  host only, and the DOM sensor has no initiator.
- Tabs are assigned to a phase at the moment they are noticed, which races with the phase
  boundaries.
- Request bodies are cut at 2 kB.
- The harness serves the honey page to **every** request on a target host, which produced the
  MyRegistry artefact.

## Isolation: v2 and corpus are untouched

- No file under `sandbox/`, `worker/` or the other frozen paths changes, so `run_ab.ps1` and
  `v2.0-freeze` reproduce exactly.
- v3 lives in `sandbox_v3/`, and the image `extprobe-sandbox:v3` is built **on top of the frozen
  v2 image**:
  - `FROM extprobe-sandbox:v2`, image id recorded in FREEZE.md, so the same Playwright 1.63, Chrome
    for Testing 153 and v2 code;
  - plus `/sandbox/v3/`, `SANDBOX_PROFILE=v3` and its own entrypoint, `analyze_v3.py`.
- v3 reuses the v2 modules (startup, crx, storage, honeypot, phase runner, honey pages) by import and
  replaces only the sensors and the `target_matched` phase.
- Scoring (`worker/risk.py`) does not read the new fields. v3 traces carry
  `startup.profile = "v3"`.

## Feasibility on Chrome 153

Checked with `sandbox_v3/feasibility/probe.py`, in the frozen v2 image, with the canary extension.

| check | result |
|---|---|
| Nested `Target.setAutoAttach` on page sessions | OK. 4 OOPIF iframes were attached. |
| `Runtime.setAsyncCallStackDepth` | **Fails** ("Debugger agent is not enabled"). |
| `Debugger.enable` + `Debugger.setSkipAllPauses(true)` + `Debugger.setAsyncCallStackDepth(32)` | OK on all 9 page/iframe sessions; 0 pauses. |
| Content-script requests (`fetch`, injected `<script>` and `<iframe>`) | Initiator stack holds `chrome-extension://<id>/content.js` (4/4 of each). |
| Page's own inline fetch (`canary-page`) | 0 extension frames. |
| `wallTime` on `Network.requestWillBeSent` | Present. |
| `Network.getRequestPostData` on the service worker | OK. |
| `chrome.tabs.create` wrapper injected at SW attach | Sees the `onInstalled` call. |
| `route.request.resource_type` / `is_navigation_request()` | Separate the document navigation. |
| `page.title()` | Works. |

## Items

| item | how (CDP / Playwright) | new `events.json` fields | risk / cost |
|---|---|---|---|
| **T1-1** per-request attribution of page requests | On every page and iframe target (browser-level and nested auto-attach): `Network.enable`, `Debugger.enable`, `setSkipAllPauses(true)`, `setAsyncCallStackDepth(32)`. On `Network.requestWillBeSent`, walk `initiator.stack` and every `parent` (async) frame. Each Playwright page request is joined to its CDP record by URL + method + nearest `wallTime` (≤ 2 s). | `page_request_initiators[]`: `{url, method, ts, frame_url, initiator_type, ext_frames: [urls], ext_ids, attributed: "extension" \| "page" \| "unknown"}`. On each `network_requests[]` page entry: `initiator_ext` (bool / null) and `initiator_ext_frame`. | Debugger domain on every page: one `scriptParsed` event per script (not stored), some CPU. Anti-debug `debugger;` statements are neutralised by `setSkipAllPauses`. The join can fail for identical concurrent URLs; those get `unknown`. |
| **T1-3** SW calls to `tabs.create` / `tabs.update` / `windows.create` | Extend the SW API hook (injected at attach, before `runIfWaitingForDebugger`) to wrap the three functions and log `{api, url, ts: Date.now()}`. | `api_calls[]` entries `{api: "tabs.create"…, args, ts}`; `sw_tab_calls[]`: `{api, url, ts, t_since_install}`, where install = browser launch (`--load-extension`). | Same limit as v2's hook: calls made synchronously at SW top level before attach can be missed. `onInstalled` calls were seen in the probe. |
| **T1-4** per-tab history | Playwright `context.on("page")`: record `initial_url` and `opened_ts`. Per page: main-frame `framenavigated` (url, ts); for each main-frame navigation request, `redirected_from` gives the redirect chain. `title()` after each `load`, and once more at the end for pages still open. Harness tabs are marked when `new_page()` returns. | `tabs_v3[]`: `{tab_seq, opened_ts, opened_phase_ts, opened_by: "harness" \| "other", initial_url, navigations: [{url, ts, redirect_chain: [...]}], final_url, titles: [{url, title, ts}], closed_ts}`. | Cheap. A title is missed if the page closes before load. |
| **T1-5** `target_matched` serves only document navigations | `route.fulfill` only if `request.resource_type == "document"` and `is_navigation_request()`; otherwise `route.continue_()`, so subresources and extension XHRs go to the real host. | `target_matched_route_log[]`: `{url, resource_type, action: "fulfill" \| "continue", ts}`. | The test pages load no external resources, so stimuli are unchanged; MyRegistry's backend calls now reach the real server instead of receiving the honey page. |
| **T1-6** absolute timestamps; phase by timestamp | Every event gets `ts` (epoch ms): `time.time()` for Playwright and DOM events, `wallTime` for CDP. Phase records get `ts_start` / `ts_end`. A post-pass sets `phase_ts` on every event from the boundaries. The v2 field `phase` (assigned at record time) is kept for comparison. | `ts` and `phase_ts` on `network_requests`, `responses`, `navigations`, `dom_activity`, `api_calls`, `console_logs`, `tabs_v3`; `phases[].ts_start` / `ts_end`; `t0_wall`. | None. |
| **T1-7** bodies up to 64 kB | Playwright `post_data_buffer` and CDP `postData`; when CDP sets `hasPostData` without `postData`, call `Network.getRequestPostData`. Keep the first 65,536 chars. | `post_data` (≤ 64 kB), `post_data_len` (original), `post_data_sha256` (of the full body), `post_data_truncated`. | Larger `events.json`, bounded by request count × 64 kB. |
| **T1-8** response bodies of extension-initiated requests (**design only, not built in this step**) | SW sessions: `Network.getResponseBody(requestId)` after `Network.loadingFinished`. Page requests attributed to the extension: the same on the page session, with `Network.enable({maxResourceBufferSize, maxTotalBufferSize})` raised. Keep up to 64 kB, plus sha256, content type and original length. | `network_requests[].response_body` / `response_body_sha256` / `response_content_type` / `response_len`. | Buffers can be evicted before the call (bodies lost), and memory use grows. Feasible but not tested yet. |

## Smoke test (step 3)

20 real samples plus the canary, through `eval/v3/run_v3.py`. That runner is new: the frozen
`eval/batch_run.py` knows only `corpus` / `v2`. It uses the same docker limits as `batch_run.py`.
Output goes to `eval/v3/smoke/`: traces stay local; only the report is committed.

## Status after step 2 (implementation) and step 3 (smoke)

| item | status |
|---|---|
| T1-1 | done. The final rule uses the outermost caller and adds `page_via_extension_hook` for page calls passing through an extension's main-world wrapper (found on Adobe Acrobat during the smoke test). |
| T1-3 | partial. The hook works when it is injected before the call (6/20 smoke runs); start-up calls race the injection, as with v2's API hook. |
| T1-4 | done. Redirect chains and creation time come from CDP document requests, because Playwright reports extension-opened tabs after their redirects. |
| T1-5 | done. |
| T1-6 | done. |
| T1-7 | done. |
| T1-8 | not built (design only). |

Image: `eval/v3/IMAGE.md`. Smoke: `eval/v3/smoke/report.md`.

## Round 2 (A1–A4)

Feasibility: `sandbox_v3/feasibility/probe2.py` → `eval/v3/feasibility/feasibility2_chrome153.json`,
`probe_hookcheck.py` → `hookcheck_chrome153.json`.

| item | how | new fields | status |
|---|---|---|---|
| **A1a** extension-opened tabs | `context.new_page` is wrapped so every harness tab is marked `opened_by="harness"`. Every other tab gets its Playwright opener: if the opener is a web page (not `chrome-extension://`), a site opened it with `window.open`. | `tabs_v3[].opened_by`, `opener_url`, `opener_is_page`, `extension_opened`, `t_since_install`, `first_url`, `created_ts`, `opened_by_sw_call` | done |
| **A1b** SW hook before the first statement | The extension is no longer passed on the command line: v3 launches Chrome with `--enable-unsafe-extension-debugging` (and without `--disable-extensions`), sets `Target.setAutoAttach{waitForDebuggerOnStart}` on the browser session, then calls `Extensions.loadUnpacked`. When the SW target attaches paused: `Debugger.enable` + `setInstrumentationBreakpoint(beforeScriptExecution)`, `runIfWaitingForDebugger`; on the first pause the hooks are evaluated on that call frame, then resume. `Runtime.evaluate` on a waiting worker did not take effect (probe2). Install time = `loadUnpacked` return. `SANDBOX_V3_LOAD=flag` restores the v2 command-line load. | `v3_load{mode, id, ts, error}`, `install_ts`, `v3_sw_attach[]`, `v3_sw_hooked[]` | done. Smoke round 2: SW hooked in 20 / 20 runs; SW tab calls in 17 / 20 runs (round 1: 6 / 20), and the other 3 open no tab (`eval/v3/smoke/report_r2.md`). |
| **A2** (T1-2) creator of injected nodes | `DOM.enable` + `DOM.setNodeStackTracesEnabled(true)` on every page/iframe session; every SCRIPT / IFRAME / FORM node seen in `getDocument`, `setChildNodes` or `childNodeInserted` gets `DOM.getNodeStackTraces` (one retry through `pushNodesByBackendIdsToFrontend` for stale ids), attributed with the T1-1 rule. Each v2 `dom_activity` `node_injected` record is joined by tag + src, nearest within 5 s. | `dom_node_initiators[]`; `dom_activity[].node_attributed` (`extension` / `page_via_extension_hook` / `page` / `no_stack` / null), `node_ext_frame` | done. Parser-created nodes have no stack (`no_stack`); FORM records are keyed by action URL and often unmatched (null). Only `extension` counts in scoring. |
| **A3** (T1-8) response bodies | `Network.enable` with 100 MB / 20 MB buffers; on `loadingFinished` of a SW request or a page request attributed to the extension, `Network.getResponseBody`. ≤ 64 kB text (or base64), sha256, content type, length. | `response_status`, `response_content_type`, `response_body` / `response_body_base64`, `response_body_len`, `response_body_sha256`, `response_body_truncated`, `response_error` | done (Poper: 96/111 SW bodies, 10/10 page-extension; Image Downloader 11/11). |
| **A4** (T1-9) page API hooking | Init script in the main world (before any page script) keeps the native `fetch`, `XMLHttpRequest.prototype.open/send`, `WebSocket` and `Function.prototype.toString`. At the end of every harness page visit: identity and native-ness of the current values. | `page_api_hooks[]{page_url, phase, where, ts, result, replaced}` | done. Controls without an extension: none → [], wrapper / bound / Proxy / spoofed toString → detected (5/5). |

Tier 2 (scoring of v3 traces): `eval/v3/SCORING_v3.md` (rules and weights, committed first), `eval/v3/score_v3.py`, `eval/v3/report_v3.py` (HTML), tests in `tests/v3/test_score_v3.py`. Smoke round 2 scores: `eval/v3/smoke/report_r2.md`.

## Round 3 (last Tier-1 change before the dev run)

Image `sha256:0e4016d1…` (`IMAGE.md`). After the 610-sample dev run, Tier 1 is not changed.

| addition | why (data for the two weak points in `smoke/report_r2.md`) |
|---|---|
| `network_requests[].source` (`cdp_sw` / `playwright`), `frame_unavailable`, `navigation` | Separates real SW requests from navigations of newly opened tabs, which the v2 fallback labels `origin="service_worker"`. |
| `page_api_hooks[].result.<api>.src` | First 400 characters of a replaced `fetch` / XHR / `WebSocket`. Tells a filtering wrapper (content blocker) from one that reads request or response data. |
| `dom_node_initiators[].outer_html` (≤ 4 kB), `outer_html_len`, `outer_html_sha256` for extension-created nodes; `dom_activity[].node_initiator_index` | Shows what the extension inserted: its own UI, a remote loader, or a form. |
| `extension_storage_v3.uuid_tokens` | Identifiers the extension stores. Recorded only; not scored (SCORING_v3.md, amendment 1). |

Checked on canary + 9 smoke samples (`smoke/report_r2.md`, round-3 section). The data for the
install-time tab (call, URL, chain with 3xx statuses, registrable domains, time since install,
uninstall URL through `api_calls`) was already complete in round 2.
