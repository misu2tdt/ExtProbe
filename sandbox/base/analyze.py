import asyncio
import argparse
import json
import logging
import os
from crx import extract_crx
import config
from pathlib import Path
from config import SOFT_TIMEOUT_MARGIN_S
from startup import run_with_startup
from sw_crosscheck import sw_crosscheck
from sensors.cdp_sw import _cdp_sw_sensor
from sensors.storage import dump_extension_storage
from phases.runner import _phase_budget, _run_phase, _finalize_run_status
from phases.actions import (
    _phase_load, _phase_target_matched, _visit_pages, _probe_extension_pages,
)


async def _run_browser(ext_dir, events, output, save_events):
    await run_with_startup(ext_dir, events,
                           lambda context: _run_phases(context, events, output, save_events))


async def _run_phases(context, events, output, save_events):
    events["phases"] = []

    # CDP SW sensor chay nen suot ca luot (vuot qua ranh gioi cac phase).
    stop_cdp = asyncio.Event()
    cdp_task = asyncio.create_task(_cdp_sw_sensor(events, stop_cdp))

    try:
        status = await _run_phase(
            "load", _phase_load(context, events),
            _phase_budget("load", 15), events)

        if status != "failed":
            await _run_phase(
                "honeypot_pages",
                _visit_pages(context, events, output, save_events),
                _phase_budget("honeypot_pages", 60), events)
            await _run_phase(
                "target_matched",
                _phase_target_matched(context, events),
                _phase_budget("target_matched", 40), events)
            await _run_phase(
                "extension_pages",
                _probe_extension_pages(context, events, output),
                _phase_budget("extension_pages", 30), events)
            await _run_phase(
                "delayed_observation",
                asyncio.sleep(3),
                _phase_budget("delayed_observation", 15), events)
    finally:
        if os.environ.get("SANDBOX_CDP_DRAIN_ON_CLOSE") == "1":
            # v2: dong browser TRUOC roi moi dung CDP -> CDP van nhan request SW phat ra luc
            # dong (vd bao loi gui luc tat), sensor tu dung khi websocket CDP dong theo browser.
            _finalize_run_status(events)
            events["_browser_closing"] = True
            await context.close()
            stop_cdp.set()
            try:
                await asyncio.wait_for(cdp_task, timeout=5)
            except Exception:
                cdp_task.cancel()
            events.pop("_browser_closing", None)
        else:
            stop_cdp.set()
            try:
                await asyncio.wait_for(cdp_task, timeout=5)
            except Exception:
                cdp_task.cancel()
            _finalize_run_status(events)
            await context.close()


# ==================== TONG HOP ====================
def summarize(events):
    reqs = events["network_requests"]
    sw_reqs = [r for r in reqs if r.get("origin") == "service_worker"]
    ext_hosts = {r["host"] for r in reqs
                 if r.get("host") and r["host"] not in ("localhost", "127.0.0.1")}

    events["summary"] = {
        "total_requests": len(reqs),
        "service_worker_requests": len(sw_reqs),
        "external_domains": sorted(ext_hosts),
        "external_domain_count": len(ext_hosts),
        "post_requests": len([r for r in reqs if r.get("method") == "POST"]),
        "requests_with_body": len([r for r in reqs if r.get("post_data")]),
        "new_tabs_opened": len(events["new_tabs"]),
        "scripts_injected": len([d for d in events["dom_activity"]
                                 if d.get("type") == "node_injected"]),
        "dom_nodes_injected": sum(d.get("injected_nodes", 0)
                                  for d in events["dom_activity"]
                                  if d.get("type") == "mutation_summary"),
        "page_hang_count": events["page_hang_count"],
        "honeypot_exfil": events["honeypot_exfil"],
        "honeypot_stored": events.get("honeypot_stored", False),
        "service_worker_count": len(events["service_workers"]),
    }


# ==================== MAIN ====================
async def analyze_extension(crx_path: str, output_dir: str):
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    events = {
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
        "honeypot_exfil_encoding": None,   # plain / url / base64 / hex (see honeypot.py)
        "honeypot_exfil_details": [],
        "honeypot_stored": False,
        "page_hang_count": 0,
        "api_calls": [],  # sensor #7 GD1 (cdp_sw.py): Chrome API hooks trong service worker
        "summary": {},
    }

    def save_events():
        summarize(events)
        with open(output / "events.json", "w", encoding="utf-8") as f:
            json.dump(events, f, indent=2, ensure_ascii=False, default=str)

    ext_dir = output / "extension_unpacked"
    events["manifest"] = extract_crx(crx_path, ext_dir)
    print(f"[Analyze] Extension: {events['manifest'].get('name')} "
          f"v{events['manifest'].get('version')} "
          f"(MV{events['manifest'].get('manifest_version')})", flush=True)
    save_events()

    try:
        await asyncio.wait_for(
            _run_browser(ext_dir, events, output, save_events),
            timeout=config.BROWSER_SOFT_TIMEOUT_S,
        )
    except asyncio.TimeoutError:
        print(f"[Analyze] Browser SOFT TIMEOUT ({config.BROWSER_SOFT_TIMEOUT_S}s)", flush=True)
        events["errors"].append(f"browser_soft_timeout_{config.BROWSER_SOFT_TIMEOUT_S}s")
        if "run_status" not in events:
            in_startup = (events.get("startup") or {}).get("status") != "ok"
            events["run_status"] = {
                "status": "failed",
                "reason": f"soft_timeout_{config.BROWSER_SOFT_TIMEOUT_S}s",
                "stuck_step": "startup" if in_startup else "phases",
                "phases_completed": 0, "phases_total": len(config.PHASE_NAMES)}
    except Exception as e:
        print(f"[Analyze] Browser error: {str(e)[:150]}", flush=True)
        events["errors"].append(f"browser_error: {str(e)[:150]}")

    # Doc storage SAU khi browser dong (du lieu da duoc flush xuong dia)
    try:
        dump_extension_storage(events)
    except Exception as e:
        print(f"[Analyze] Storage dump failed: {str(e)[:100]}", flush=True)

    cc = sw_crosscheck(events)       # chi khi SANDBOX_RECORD_PW_SW=1 (v2); khong cham diem
    if cc:
        print(f"[Analyze] SW crosscheck: CDP={cc['cdp']} Playwright={cc['playwright']} "
              f"both={cc['both']}", flush=True)

    save_events()
    s = events["summary"]
    print(f"[Analyze] DONE. requests={s['total_requests']} "
          f"(SW={s['service_worker_requests']}, POST={s['post_requests']}) | "
          f"domains={s['external_domain_count']} | tabs={s['new_tabs_opened']} | "
          f"injected={s['scripts_injected']} | hangs={s['page_hang_count']} | "
          f"exfil={s['honeypot_exfil']} stored={s['honeypot_stored']}", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--crx", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout", type=int, default=120,
                        help="Ngan sach thoi gian TONG (giay) do shell cap")
    args = parser.parse_args()
    logging.basicConfig(level=os.environ.get("SANDBOX_LOG_LEVEL", "WARNING").upper(),
                        format="[%(levelname)s %(name)s] %(message)s")

    config.BROWSER_SOFT_TIMEOUT_S = max(30, args.timeout - SOFT_TIMEOUT_MARGIN_S)
    print(f"[Analyze] Budget={args.timeout}s, soft={config.BROWSER_SOFT_TIMEOUT_S}s",
          flush=True)

    asyncio.run(analyze_extension(args.crx, args.output))


if __name__ == "__main__":
    main()