// GT source_type=injected_script. Declared with "world": "MAIN" in manifest.json's
// content_scripts entry for gt-injected.bench - Chrome's own MV3 primitive for
// running extension-authored code directly in the page's MAIN world (shares the
// page's window/global scope, unlike the default isolated world).
//
// RUN #1/#2 FINDINGS (kept for the record): the first two fixture versions tried to
// reach MAIN-world execution by hand - a content script (isolated world) using
// document.createElement('script') to inject either a REMOTE <script src=...> or an
// INLINE <script>textContent</script>. BOTH were refused by Chrome:
//   "Refused to load/execute the script ... Content Security Policy directive:
//    script-src 'self' 'wasm-unsafe-eval' 'inline-speculation-rules'
//    http://localhost:* http://127.0.0.1:*"
// That is Chrome's DEFAULT extension_pages CSP (this manifest declares no override),
// applied to any script a content script tries to DOM-inject into a page, regardless
// of the target page's own (here: absent) CSP - i.e. Chrome blocks that injection
// vector outright for MV3 extensions with no custom CSP. The requests never fired at
// all (NOT_OBSERVED) - a platform restriction, not an attribution miss, and worth
// recording as its own finding rather than folding it into the attribution result.
// "world":"MAIN" is Chrome's supported, CSP-exempt way to get extension code running
// in page context, and is the realistic mechanism for modern MV3 code (manual DOM
// script injection being the older, now largely CSP-blocked, technique).
//
// Section 5.1 KNOWN LIMITATION (expected miss): the CDP initiator-stack walk
// (_initiator_is_extension) inspects the call frames active when fetch() fires; code
// running under world:"MAIN" executes as part of the PAGE's own JS realm, so those
// frames are expected to carry the document's own URL, not chrome-extension:// -
// meaning the request is NOT expected to be linked back to the extension even though
// the extension caused it to run. We measure this, we do not assume it.
fetch("/gt/injected_script").catch(() => {});
