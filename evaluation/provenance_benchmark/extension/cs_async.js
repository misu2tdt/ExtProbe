// GT source_type=async_callback. This content script (isolated world) schedules the
// GET across a macrotask boundary (setTimeout - representative of the
// setTimeout/postMessage/chrome.alarms class named in the benchmark spec) instead of
// firing it synchronously at content-script top level. Runs only on gt-async.bench
// (manifest.json). No direct/immediate fetch happens on this host, so this host's
// request_provenance entry is a clean, uncontaminated measurement of the async path
// alone (see run_benchmark.py comment on why each source type gets its own host).
//
// Section 5.1 KNOWN LIMITATION (expected miss, but NOT guaranteed - see
// eval/provenance_benchmark/summary.json for what actually happened): async
// boundaries may break the causal chain that CDP's initiator.stack walk relies on.
// Whether V8 still tags the deferred callback frame with this script's
// chrome-extension:// source URL, or the stack shows no extension frame at all once
// the timer fires as a fresh top-level task, is exactly the open question this
// benchmark quantifies - we do not assume the answer, we report it.
setTimeout(() => { fetch("/gt/async_callback").catch(() => {}); }, 3000);
