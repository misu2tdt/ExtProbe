"""ExtProbe v3.1-probe analysis entry point (image extprobe-sandbox:v3.1-probe; eval/v3_1_probe/DESIGN.md).

Runs exactly the v3 phases (modules imported from /sandbox/v3, unchanged), then, in the same browser:
  probe_explore         v31_explorer.explore: popup / options pages from the manifest, clicked by policy
  probe_target_matched  v31_target.rerun_target: product page of the already-matched target hosts
Proxy guard (v31_guard), from before the extension is loaded to the end: managed policy ProxyMode=direct (in the
image), chrome.proxy.settings recorder in the service worker (appended to the v3 SW hook string) and in every
extension page (PageGuard, a separate CDP client), effective-configuration monitor every 2 s.
Before the probe: the extension storage is read and list lengths are noted.
Output (v31_split):
  events.json        the v3 trace up to the probe start (score_v3 reads it unchanged)
  events_probe.json  everything from the probe start on, with stimulus_id / cause_class, the probe log,
                     the proxy guard record
The probe phases are kept out of events["phases"], so run_status keeps its v3 meaning.
"""
import argparse
import asyncio
import copy
import json
import logging
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(1, "/sandbox/v3")
sys.path.insert(2, "/sandbox")

import config  # noqa: E402
from config import SOFT_TIMEOUT_MARGIN_S  # noqa: E402
from crx import extract_crx  # noqa: E402
from startup import run_with_startup  # noqa: E402
from sw_crosscheck import sw_crosscheck  # noqa: E402
from sensors.storage import dump_extension_storage  # noqa: E402
from phases.runner import _finalize_run_status  # noqa: E402
from phases.actions import _probe_extension_pages  # noqa: E402
from analyze import summarize  # noqa: E402
import analyze_v3 as A3  # noqa: E402
from v3_actions import phase_load_v3, phase_target_matched_v3, visit_pages_v3  # noqa: E402
import v3_startup  # noqa: E402
from v3_cdp import cdp_sensor_v3  # noqa: E402
from v3_network import final_titles  # noqa: E402
from v3_post import post_process  # noqa: E402
from v3_storage import storage_ids_v3  # noqa: E402
from v3_common import now_ms  # noqa: E402
from v31_explorer import explore  # noqa: E402
from v31_target import rerun_target  # noqa: E402
from v31_split import offsets, split  # noqa: E402
from v31_guard import PageGuard, ProxyMonitor, install_sw_hook, policy_file, policy_page  # noqa: E402

SCHEMA = "1.1+v3"
PROFILE = "v3.1-probe"


async def _probe_phase(name, coro, budget, events):
    rec = {"name": name, "status": "running", "budget_s": budget, "ts_start": now_ms()}
    events.setdefault("probe_phases", []).append(rec)
    events["_current_phase"] = name
    try:
        await asyncio.wait_for(coro, timeout=budget)
        rec["status"] = "completed"
    except asyncio.TimeoutError:
        rec["status"] = "timed_out"
    except Exception as e:
        rec["status"], rec["reason"] = "failed", str(e)[:150]
    rec["ts_end"] = now_ms()
    print(f"[Probe] {name}: {rec['status']} ({(rec['ts_end'] - rec['ts_start']) / 1000:.1f}s)", flush=True)


async def _run(context, events, output, save_events):
    events["phases"] = []
    events["t0_wall"] = round(time.time() - (time.monotonic() - events["_t0"]), 3)
    install_sw_hook()
    guard = PageGuard(events)
    await guard.start()                                   # auto-attach in place before the extension is loaded
    stop_cdp = asyncio.Event()
    cdp_task = asyncio.create_task(cdp_sensor_v3(events, stop_cdp))
    monitor = ProxyMonitor(context, events)
    monitor.start()
    try:
        status = await A3._phase("load", phase_load_v3(context, events), 15, events)
        await monitor.snapshot(mark="after_load")
        if status != "failed":
            await A3._phase("honeypot_pages", visit_pages_v3(context, events, output, save_events), 60, events)
            await A3._phase("target_matched", phase_target_matched_v3(context, events), 40, events)
            await A3._phase("extension_pages", _probe_extension_pages(context, events, output), 30, events)
            await A3._phase("delayed_observation", asyncio.sleep(3), 15, events)
        _finalize_run_status(events)                      # v3 meaning, decided before any probe phase
        # ---------------- probe ----------------
        try:
            dump_extension_storage(events)                # storage as the v3 part left it
            storage_ids_v3(events)
        except Exception as e:
            events["errors"].append(f"v31_pre_storage: {str(e)[:100]}")
        events["_pre_storage"] = (copy.deepcopy(events.get("extension_storage")), copy.deepcopy(events.get("extension_storage_v3")))
        events["_offsets"] = offsets(events)
        events["probe_t0"] = now_ms()
        t_probe = time.monotonic()
        probe = {}
        events["_probe"] = probe
        await monitor.snapshot(mark="probe_start")
        events["_policy_page"] = await policy_page(context)   # harness side, independent of the extension
        if os.environ.get("PROBE_SELFTEST_STOP_SW") == "1":   # feasibility/guard_check.py only
            guard.stop_all_workers()
            await asyncio.sleep(1.5)
        if status != "failed":
            await _probe_phase("probe_explore", explore(context, events, probe), 34, events)
            await _probe_phase("probe_target_matched", rerun_target(context, events, t_probe), 30, events)
        probe["extra_s"] = round(time.monotonic() - t_probe, 1)
        await monitor.snapshot(mark="probe_end")
    finally:
        await monitor.stop()
        try:
            await asyncio.wait_for(final_titles(), timeout=8)
        except Exception:
            pass
        events["_browser_closing"] = True
        await context.close()
        stop_cdp.set()
        try:
            await asyncio.wait_for(cdp_task, timeout=5)
        except Exception:
            cdp_task.cancel()
        events.pop("_browser_closing", None)
        await guard.stop()


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
        clean = {k: v for k, v in events.items() if not k.startswith("_")}
        with open(output / "events.json", "w", encoding="utf-8") as f:
            json.dump(clean, f, indent=2, ensure_ascii=False, default=str)

    ext_dir = output / "extension_unpacked"
    events["manifest"] = extract_crx(crx_path, ext_dir)
    save_events()
    v3_startup.install(events)
    try:
        await asyncio.wait_for(run_with_startup(ext_dir, events, lambda ctx: _run(ctx, events, output, save_events)),
                               timeout=config.BROWSER_SOFT_TIMEOUT_S)
    except asyncio.TimeoutError:
        events["errors"].append(f"browser_soft_timeout_{config.BROWSER_SOFT_TIMEOUT_S}s")
        if "run_status" not in events:
            events["run_status"] = {"status": "failed", "reason": "soft_timeout", "phases_completed": 0,
                                    "phases_total": len(config.PHASE_NAMES)}
    except Exception as e:
        events["errors"].append(f"browser_error: {str(e)[:150]}")
    try:
        dump_extension_storage(events)
        storage_ids_v3(events)
    except Exception as e:
        events["errors"].append(f"storage: {str(e)[:100]}")
    sw_crosscheck(events)
    try:
        post_process(events)
    except Exception as e:
        events["errors"].append(f"v3_post_error: {str(e)[:150]}")
    pre, post = split(events)
    mon = events.get("_proxy_monitor") or {}
    start = (mon.get("marks") or {}).get("after_load") or {}
    page = events.get("_policy_page") or ""
    post["proxy_guard"] = {
        "policy_file": policy_file(),
        "policy_page": page,
        "policy_in_force": (page.startswith("ProxyMode direct") and "Mandatory" in page)
                           or (start.get("level") == "not_controllable" and start.get("mode") == "direct"),
        "extension_proxy_api": start.get("level") != "no_proxy_api",
        "monitor": mon, "proxy_unwrapped_set": bool(mon.get("proxy_unwrapped_set")),
        "sw_hooked": len(events.get("v3_sw_hooked") or []),
        "page_guard": events.get("_guard_stats"), "page_calls": events.get("_guard_pages") or []}
    post["profile"] = PROFILE
    summarize(pre)
    with open(output / "events.json", "w", encoding="utf-8") as f:
        json.dump({k: v for k, v in pre.items() if k not in ("_harness_page_ids", "_ext_dir")}, f, indent=2,
                  ensure_ascii=False, default=str)
    with open(output / "events_probe.json", "w", encoding="utf-8") as f:
        json.dump(post, f, indent=2, ensure_ascii=False, default=str)
    pr = post.get("probe", {})
    print(f"[Analyze v3.1] DONE. pages={[(p['kind'], p['opened'], p['elements']) for p in pr.get('pages', [])]} "
          f"clicks={len(pr.get('stimuli', []))} explore_s={pr.get('explore_s')} extra_s={pr.get('extra_s')} "
          f"login_gate={pr.get('login_gate')} policy_in_force={post['proxy_guard']['policy_in_force']} "
          f"unwrapped={post['proxy_guard']['proxy_unwrapped_set']} page_guard={events.get('_guard_stats')}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--crx", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--timeout", type=int, default=240)
    a = ap.parse_args()
    logging.basicConfig(level=os.environ.get("SANDBOX_LOG_LEVEL", "WARNING").upper())
    config.BROWSER_SOFT_TIMEOUT_S = max(30, a.timeout - SOFT_TIMEOUT_MARGIN_S)
    asyncio.run(analyze_extension(a.crx, a.output))


if __name__ == "__main__":
    main()
