"""run_benchmark.py -- Tier-1 collection driver for the C1 provenance-attribution
benchmark. Runs INSIDE the extprobe-sandbox:latest container (needs Playwright +
Xvfb + the real CDP stack), NOT on the host.

REUSE, NOT REIMPLEMENTATION: this script imports and calls the exact same sensor
functions the production pipeline uses (sandbox/sensors/cdp_sw.py::_cdp_sw_sensor,
which internally calls _initiator_is_extension -- the real CDP async-initiator
call-stack walk -- and sandbox/sensors/network.py::_setup_context_observers,
sandbox/sensors/dom.py::_setup_dom_sensor, sandbox/crx.py::extract_crx). It does NOT
reimplement the attribution decision; it only adds a bespoke navigation sequence
because the production phase runner (sandbox/phases/actions.py::_phase_target_matched)
caps at MAX_TARGET_HOSTS=2 (sandbox/config.py), too few for this benchmark's 4
extension-controlled hosts (content_script/injected_script/async_callback/service_worker)
plus 1 page-only host.

Why 5 DISTINCT hosts (one per source type) instead of 5 paths on 1 host: the real
provenance signal (events["request_provenance"]) is HOST-keyed and OR-reduced across
every request ever seen to that host (sandbox/sensors/cdp_sw.py:262-263, "host duoc
extension khoi tao du 1 lan => danh dau True"). Putting two source types on the same
host would let one contaminate the other's measured result. Distinct hosts keep each
source type's provenance verdict clean while URLs stay unique either way.

Run (inside container): python3 /bench/run_benchmark.py --output /bench/output --timeout 180
"""
import argparse
import asyncio
import io
import json
import struct
import sys
import time
import zipfile
from pathlib import Path
from urllib.parse import urlparse

SANDBOX = Path("/sandbox")
sys.path.insert(0, str(SANDBOX))

from playwright.async_api import async_playwright  # noqa: E402
from crx import extract_crx  # noqa: E402  (REUSE - same unpacker analyze.py uses)
from sensors.cdp_sw import _cdp_sw_sensor  # noqa: E402  (REUSE - real attribution sensor)
from sensors.network import _setup_context_observers  # noqa: E402  (REUSE)
from sensors.dom import _setup_dom_sensor  # noqa: E402  (REUSE)
from config import REMOTE_DEBUG_PORT  # noqa: E402

BENCH = Path(__file__).resolve().parent
EXT_SRC = BENCH / "extension"
HONEYPAGE = BENCH / "honeypage"
PROFILE_DIR = "/tmp/gt-bench-chrome-profile"

# host -> (bytes served at "/", content_type)
_LANDING = {
    "gt-page.bench": (HONEYPAGE / "page_js.html").read_bytes(),
    "gt-cscript.bench": (HONEYPAGE / "generic.html").read_bytes(),
    "gt-injected.bench": (HONEYPAGE / "generic.html").read_bytes(),
    "gt-async.bench": (HONEYPAGE / "generic.html").read_bytes(),
    "gt-sw.bench": (HONEYPAGE / "generic.html").read_bytes(),
}

def _build_fake_crx(src_dir: Path, crx_path: Path):
    """Recursive version of sandbox/smoke_test.py::build_crx (that one only zips
    top-level files; our fixture is flat too, but this stays correct if it grows
    subdirectories). Same minimal CRX3 framing accepted by sandbox/crx.py::extract_crx
    (magic + empty header, no real signature needed - extract_crx never checks one)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(src_dir.rglob("*")):
            if f.is_file():
                z.writestr(str(f.relative_to(src_dir)).replace("\\", "/"), f.read_bytes())
    crx = b"Cr24" + struct.pack("<I", 3) + struct.pack("<I", 0) + buf.getvalue()
    crx_path.write_bytes(crx)


async def _route_handler(route):
    """Single dispatcher for every gt-*.bench request. Playwright's route interception
    happens before any real DNS/network I/O, so these fake .bench hosts never need to
    resolve - this is the same offline mechanism sandbox/phases/actions.py
    ::_phase_target_matched already uses (context.route + route.fulfill) to spoof
    real target hosts; we're reusing the identical Playwright primitive, just with our
    own routing table instead of a single universal.html."""
    url = route.request.url
    parsed = urlparse(url)
    host, path = parsed.hostname or "", parsed.path or "/"
    try:
        if path == "/":
            body = _LANDING.get(host, b"<!doctype html><html><body>gt-bench</body></html>")
            await route.fulfill(status=200, content_type="text/html", body=body)
        elif path.startswith("/gt/"):
            # THE ground-truth-tagged request itself. Body content is irrelevant to
            # attribution (CDP captures the request at initiation time, regardless of
            # the response) - 200 JSON just keeps devtools/console quiet.
            await route.fulfill(status=200, content_type="application/json",
                                 body=json.dumps({"ok": True, "path": path}))
        else:
            await route.fulfill(status=404, content_type="text/plain", body="not found")
    except Exception:
        try:
            await route.continue_()
        except Exception:
            pass


def _new_events():
    """Same skeleton as sandbox/analyze.py::analyze_extension's events dict, so the
    real sensor modules (which read/write these keys unconditionally) never KeyError."""
    return {
        "schema_version": "1.0",
        "manifest": {},
        "network_requests": [],
        "responses": [],
        "console_logs": [],
        "errors": [],
        "pages_visited": [],
        "new_tabs": [],
        "navigations": [],
        "service_workers": [],
        "dom_activity": [],
        "extension_pages_opened": [],
        "extension_ids_seen": [],
        "extension_storage": {},
        "honeypot_exfil": False,
        "honeypot_exfil_details": [],
        "honeypot_stored": False,
        "page_hang_count": 0,
        "api_calls": [],
        "summary": {},
    }


async def _visit(context, events, url, phase, dwell_s):
    events["_current_phase"] = phase
    tab = None
    try:
        tab = await context.new_page()
        tab.on("console", lambda msg: events["console_logs"].append(
            {"type": msg.type, "text": msg.text[:200]}))
        tab.on("pageerror", lambda err: events["errors"].append(str(err)[:200]))
        await tab.goto(url, wait_until="commit", timeout=8000)
        await tab.wait_for_timeout(int(dwell_s * 1000))
        events["pages_visited"].append(url)
        print(f"[GT-bench] visited {url} (dwell {dwell_s}s)", flush=True)
    except Exception as e:
        events["errors"].append(f"navigate {url}: {str(e).split(chr(10))[0][:150]}")
        print(f"[GT-bench] ERROR visiting {url}: {e}", flush=True)
    finally:
        if tab:
            try:
                await tab.close()
            except Exception:
                pass


async def _run(output_dir: Path, timeout_s: int):
    output_dir.mkdir(parents=True, exist_ok=True)
    crx_path = Path("/tmp/gt_bench.crx")
    _build_fake_crx(EXT_SRC, crx_path)
    print(f"[GT-bench] built {crx_path} ({crx_path.stat().st_size} bytes)", flush=True)

    ext_dir = output_dir / "extension_unpacked"
    events = _new_events()
    events["manifest"] = extract_crx(str(crx_path), ext_dir)  # REUSE real unpacker
    print(f"[GT-bench] extension: {events['manifest'].get('name')} "
          f"v{events['manifest'].get('version')}", flush=True)

    async def _body():
        async with async_playwright() as p:
            events["_t0"] = time.monotonic()
            context = await p.chromium.launch_persistent_context(
                user_data_dir=PROFILE_DIR,
                headless=False,
                args=[
                    f"--disable-extensions-except={ext_dir}",
                    f"--load-extension={ext_dir}",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-blink-features=AutomationControlled",
                    f"--remote-debugging-port={REMOTE_DEBUG_PORT}",
                ],
            )
            stop_cdp = asyncio.Event()
            cdp_task = asyncio.create_task(_cdp_sw_sensor(events, stop_cdp))  # REUSE
            try:
                await _setup_context_observers(context, events)  # REUSE
                await _setup_dom_sensor(context, events)          # REUSE
                await context.route("**://gt-*.bench/**", _route_handler)

                # Let the SW register + onInstalled fire (GT source_type=service_worker).
                events["_current_phase"] = "gt_load"
                await asyncio.sleep(2.5)
                # Catch-up for SWs created before context.on("serviceworker") attached
                # (same pattern as sandbox/phases/actions.py::_phase_load).
                seen_sw = {s.get("url") for s in events["service_workers"]}
                for sw in context.service_workers:
                    if sw.url not in seen_sw:
                        events["service_workers"].append({"url": sw.url})
                        seen_sw.add(sw.url)

                await _visit(context, events, "https://gt-page.bench/", "gt_page_js", 1.5)
                await _visit(context, events, "https://gt-cscript.bench/", "gt_content_script", 1.5)
                await _visit(context, events, "https://gt-injected.bench/", "gt_injected_script", 1.5)
                # async_callback fires 3s after cs_async.js loads - dwell past that
                # BEFORE closing the tab, or the pending timer never fires.
                await _visit(context, events, "https://gt-async.bench/", "gt_async_callback", 4.5)

                # Grace window for any straggler (e.g. slow-firing SW onInstalled).
                events["_current_phase"] = "gt_drain"
                await asyncio.sleep(2)
            finally:
                stop_cdp.set()
                try:
                    await asyncio.wait_for(cdp_task, timeout=5)
                except Exception:
                    cdp_task.cancel()
                await context.close()

    try:
        await asyncio.wait_for(_body(), timeout=timeout_s)
    except asyncio.TimeoutError:
        events["errors"].append(f"gt_bench_timeout_{timeout_s}s")
        print(f"[GT-bench] TIMEOUT after {timeout_s}s", flush=True)

    with open(output_dir / "events.json", "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2, ensure_ascii=False, default=str)
    print(f"[GT-bench] DONE. requests={len(events['network_requests'])} "
          f"provenance_hosts={len(events.get('request_provenance', {}))}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", required=True)
    ap.add_argument("--timeout", type=int, default=180)
    args = ap.parse_args()
    asyncio.run(_run(Path(args.output), args.timeout))


if __name__ == "__main__":
    main()
