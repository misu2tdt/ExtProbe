// GT source_type=content_script (isolated world). Fires exactly ONE synchronous,
// top-level GET so the attributor's initiator-stack walk (sandbox/sensors/cdp_sw.py
// _initiator_is_extension) sees this content script's own chrome-extension://
// call frame at request time. Runs only on gt-cscript.bench (manifest.json).
//
// Section 5.1 EXPECTED behaviour: isolated-world content-script requests ARE linked
// back to the extension (this is the case the attributor is designed to catch) ->
// predicted hit expected. We still measure and report the observed outcome rather
// than assume it.
fetch("/gt/content_script").catch(() => {});
