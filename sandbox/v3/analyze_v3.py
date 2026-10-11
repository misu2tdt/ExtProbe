"""ExtProbe v3 analysis entry point (profile `v3`, image extprobe-sandbox:v3).

Same flow, phases, budgets and stimuli as the v2 profile (sandbox/analyze.py), using the frozen
v2 modules by import, with the v3 sensors (eval/v3/DESIGN_v3.md):
  T1-1 per-request attribution of page requests   (v3_cdp)
  T1-3 SW tabs.create / tabs.update / windows.create calls   (v3_cdp)
  T1-4 per-tab URL history, redirects and titles   (v3_network)
  T1-5 target_matched serves documents only   (v3_actions)
  T1-6 absolute timestamps; phase by timestamp   (all + v3_post)
  T1-7 request bodies up to 64 kB   (v3_cdp, v3_network)
  A1   extension loaded through CDP after attach (v3_startup); extension-opened tabs (opener)
  A2   creation stacks of injected nodes   (v3_cdp)
  A3   response bodies of extension-initiated requests   (v3_cdp)
  A4   page API hooking check on harness pages   (v3_actions)
  round 3: request source (cdp_sw / playwright, frame_unavailable, navigation); replacement source
       of hooked APIs; outerHTML of extension-created nodes; UUIDs in extension storage (v3_storage)
"""
import argparse
import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(1, str(HERE.parent))              # /sandbox: the frozen v2 modules

import config  # noqa: E402
from config import SOFT_TIMEOUT_MARGIN_S  # noqa: E402
from crx import extract_crx  # noqa: E402
from startup import run_with_startup  # noqa: E402
from sw_crosscheck import sw_crosscheck  # noqa: E402
from sensors.storage import dump_extension_storage  # noqa: E402
from phases.runner import _phase_budget, _run_phase, _finalize_run_status  # noqa: E402
from phases.actions import _probe_extension_pages  # noqa: E402
from analyze import summarize  # noqa: E402
from v3_actions import phase_load_v3, phase_target_matched_v3, visit_pages_v3  # noqa: E402
import v3_startup  # noqa: E402
from v3_cdp import cdp_sensor_v3  # noqa: E402
from v3_network import final_titles  # noqa: E402
from v3_post import post_process  # noqa: E402
from v3_storage import storage_ids_v3  # noqa: E402

SCHEMA = "1.1+v3"


async def _phase(name, coro, default_budget, events):
    status = await _run_phase(name, coro, _phase_budget(name, default_budget), events)
    rec = events["phases"][-1]
    rec["ts_start"] = round((events["t0_wall"] + rec["t_start"]) * 1000, 1)
    rec["ts_end"] = round((events["t0_wall"] + rec["t_end"]) * 1000, 1) if rec.get("t_end") is not None else None
    return status


async def _run_phases_v3(context, events, output, save_events):
    events["phases"] = []
    # wall-clock instant of startup's monotonic _t0 (browser launch = extension install)
    events["t0_wall"] = round(time.time() - (time.monotonic() - events["_t0"]), 3)
    stop_cdp = asyncio.Event()
    cdp_task = asyncio.create_task(cdp_sensor_v3(events, stop_cdp))
    try:
        status = await _phase("load", phase_load_v3(context, events), 15, events)
        if status != "failed":
            await _phase("honeypot_pages", visit_pages_v3(context, events, output, save_events), 60, events)
            await _phase("target_matched", phase_target_matched_v3(context, events), 40, events)
            await _phase("extension_pages", _probe_extension_pages(context, events, output), 30, events)
            await _phase("delayed_observation", asyncio.sleep(3), 15, events)
    finally:
        try:
            await asyncio.wait_for(final_titles(), timeout=8)
        except Exception:
            pass
        _finalize_run_status(events)
        events["_browser_closing"] = True
        await context.close()
        stop_cdp.set()
        try:
            await asyncio.wait_for(cdp_task, timeout=5)
        except Exception:
            cdp_task.cancel()
        events.pop("_browser_closing", None)


async def analyze_extension(crx_path, output_dir):
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    events = {
        "schema_version": SCHEMA, "manifest": {}, "network_requests": [], "responses": [], "console_logs": [],
        "errors": [], "pages_visited": [], "new_tabs": [], "navigations": [], "service_workers": [],
        "dom_activity": [], "extension_pages_opened": [], "extension_ids_seen": [], "extension_storage": {},
        "honeypot_exfil": False, "honeypot_exfil_encoding": None, "honeypot_exfil_details": [],
        "honeypot_stored": False, "page_hang_count": 0, "api_calls": [], "summary": {},
        "page_request_initiators": [], "sw_tab_calls": [], "tabs_v3": [], "target_matched_route_log": [],
        "dom_node_initiators": [], "page_api_hooks": [],
    }

    def save_events():
        summarize(events)
        clean = {k: v for k, v in events.items() if k not in ("_harness_page_ids", "_ext_dir")}
        with open(output / "events.json", "w", encoding="utf-8") as f:
            json.dump(clean, f, indent=2, ensure_ascii=False, default=str)

    ext_dir = output / "extension_unpacked"
    events["manifest"] = extract_crx(crx_path, ext_dir)
    print(f"[Analyze v3] Extension: {events['manifest'].get('name')} v{events['manifest'].get('version')}", flush=True)
    save_events()
    v3_startup.install(events)
    try:
        await asyncio.wait_for(
            run_with_startup(ext_dir, events, lambda ctx: _run_phases_v3(ctx, events, output, save_events)),
            timeout=config.BROWSER_SOFT_TIMEOUT_S)
    except asyncio.TimeoutError:
        events["errors"].append(f"browser_soft_timeout_{config.BROWSER_SOFT_TIMEOUT_S}s")
        if "run_status" not in events:
            in_startup = (events.get("startup") or {}).get("status") != "ok"
            events["run_status"] = {"status": "failed", "reason": f"soft_timeout_{config.BROWSER_SOFT_TIMEOUT_S}s",
                                    "stuck_step": "startup" if in_startup else "phases",
                                    "phases_completed": 0, "phases_total": len(config.PHASE_NAMES)}
    except Exception as e:
        events["errors"].append(f"browser_error: {str(e)[:150]}")
    try:
        dump_extension_storage(events)
    except Exception as e:
        print(f"[Analyze v3] Storage dump failed: {str(e)[:100]}", flush=True)
    try:
        storage_ids_v3(events)
    except Exception as e:
        events["errors"].append(f"v3_storage_error: {str(e)[:120]}")
    sw_crosscheck(events)
    try:
        post_process(events)
    except Exception as e:
        events["errors"].append(f"v3_post_error: {str(e)[:150]}")
    save_events()
    s = events["summary"]
    print(f"[Analyze v3] DONE. requests={s['total_requests']} tabs={len(events['tabs_v3'])} "
          f"initiators={len(events['page_request_initiators'])} sw_tab_calls={len(events['sw_tab_calls'])}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--crx", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--timeout", type=int, default=120)
    a = ap.parse_args()
    logging.basicConfig(level=os.environ.get("SANDBOX_LOG_LEVEL", "WARNING").upper(),
                        format="[%(levelname)s %(name)s] %(message)s")
    config.BROWSER_SOFT_TIMEOUT_S = max(30, a.timeout - SOFT_TIMEOUT_MARGIN_S)
    asyncio.run(analyze_extension(a.crx, a.output))


if __name__ == "__main__":
    main()
