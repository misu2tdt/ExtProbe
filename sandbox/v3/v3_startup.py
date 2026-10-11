"""v3 start-up (A1b): load the extension AFTER the CDP sensor is attached.

v2 passes --load-extension at launch, so the service worker runs before any CDP session exists
and calls made at start-up (onInstalled tabs.create, setUninstallURL ...) can be missed by the
API hook. v3 launches the browser without the extension, with --enable-unsafe-extension-debugging,
and the CDP sensor loads it with Extensions.loadUnpacked once Target.setAutoAttach
(waitForDebuggerOnStart) is in place: the service worker then attaches paused and the hook is
injected at its first statement (v3_cdp.py). Same extension id as --load-extension (it is derived
from the path). Checked on Chrome 153: eval/v3/feasibility/feasibility2_chrome153.json, 3/3 runs.

The frozen v2 start-up (sandbox/startup.py: pre-flight checks, timeouts, retries) is reused
unchanged; only its launch_kwargs is replaced at run time, in this process, for the v3 profile.
SANDBOX_V3_LOAD=flag restores the v2 way (--load-extension) for comparison.
"""
import asyncio
import os

LOADED = {"event": None}


def load_mode():
    return "flag" if os.environ.get("SANDBOX_V3_LOAD") == "flag" else "cdp"


def install(events):
    import startup as v2_startup
    original = v2_startup.launch_kwargs
    events["v3_load"] = {"mode": load_mode()}
    LOADED["event"] = asyncio.Event()

    def launch_kwargs_v3(ext_dir):
        kw, sandboxed = original(ext_dir)
        events["_ext_dir"] = str(ext_dir)
        if load_mode() == "cdp":
            kw["args"] = [a for a in kw["args"]
                          if not a.startswith(("--load-extension=", "--disable-extensions-except="))]
            kw["args"].append("--enable-unsafe-extension-debugging")
            kw["ignore_default_args"] = ["--disable-extensions"]
        return kw, sandboxed

    v2_startup.launch_kwargs = launch_kwargs_v3


async def wait_loaded(events, timeout=15):
    """Phase load waits for the CDP load to finish (cdp mode). Raises if it failed."""
    if load_mode() != "cdp":
        return
    try:
        await asyncio.wait_for(LOADED["event"].wait(), timeout=timeout)
    except asyncio.TimeoutError:
        raise RuntimeError("extension_load_timeout: Extensions.loadUnpacked did not answer")
    if not events.get("v3_load", {}).get("id"):
        raise RuntimeError(f"extension_load_failed: {events.get('v3_load', {}).get('error')}")
