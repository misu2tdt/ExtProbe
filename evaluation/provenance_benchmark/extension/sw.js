// GT source_type=service_worker. Fires exactly ONE GET from the extension's own
// background service worker, inside the onInstalled event handler (a reliably-hooked
// context, see sandbox/sensors/cdp_sw.py GD1 comment on top-level-vs-handler timing -
// not relevant to THIS sensor, kept as good practice regardless).
//
// Section 5.1 EXPECTED behaviour: SW-origin requests bypass the initiator-stack check
// entirely - sandbox/sensors/cdp_sw.py:_record_cdp_request always tags CDP-session
// requests from a confirmed extension SW target with origin="service_worker", and
// worker/risk.py:317-359 (detect_undeclared_domains) trusts origin=="service_worker"
// as extension-initiated UNCONDITIONALLY, without consulting request_provenance /
// the initiator stack at all. So this is a predicted hit "by construction" (the
// check is skipped, not passed) rather than evidence the stack-walk itself works for
// SW code - the benchmark measures and reports this distinction explicitly.
// NOTE (run #1 finding, kept for the record): firing the fetch as the very first
// synchronous statement of onInstalled raced the CDP attach sequence in
// sandbox/sensors/cdp_sw.py::_cdp_sw_sensor (websocket connect + Target.setAutoAttach
// + Network.enable for the SW's own session all happen async, after browser launch;
// canary's sw.js survives the same race only because its onInstalled handler awaits
// storage/tabs calls first, giving the attach time to land) - the request fired and
// completed before Network.enable had reached that session, so CDP never saw it at
// all (not a miss, an unobserved request - see eval/provenance_benchmark/summary.json
// "not_observed" from the first run). A short await reproduces canary's timing margin
// so this benchmark measures the ATTRIBUTION RULE (SW bypasses the stack check), not
// an unrelated attach-race artifact.
chrome.runtime.onInstalled.addListener(async () => {
  await new Promise((r) => setTimeout(r, 800));
  fetch("https://gt-sw.bench/gt/service_worker").catch(() => {});
});
