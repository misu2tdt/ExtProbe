"""v3 Playwright observers: the v2 network / tab sensor (sandbox/sensors/network.py) plus

  T1-4  events["tabs_v3"]: per tab the initial URL, every main-frame navigation (with the
        redirect chain of its navigation request), titles after each load, close time, and
        whether the harness opened it (marked by the wrapped context.new_page).
  T1-6  `ts` (epoch ms) on requests, responses, new_tabs, navigations, console logs.
  T1-7  page request bodies up to 64 kB (+ original length and sha256).
Only used by the v3 profile; the v2 module is unchanged.
"""
import asyncio
import json
import logging
import os
import time

from config import INTERESTING_HEADERS
from honeypot import find_honeypot_any, record_exfil_encoding
from utils import _host_of
from v3_common import body_fields, now_ms

logger = logging.getLogger(__name__)
_TAB_RECS = {}           # id(page) -> tabs_v3 record (kept out of events: not JSON)
_PAGES = {}              # id(page) -> page


def _record_request(req, events, origin):
    entry = {"url": req.url, "method": req.method, "resource_type": req.resource_type, "origin": origin,
             "host": _host_of(req.url), "phase": events.get("_current_phase"), "ts": now_ms(),
             "source": "playwright"}
    if events.get("_t0") is not None:
        entry["t"] = round(time.monotonic() - events["_t0"], 3)
    body = None
    try:
        raw = req.post_data_buffer
        if raw:
            entry.update(body_fields(raw))
            body = entry.get("post_data")
            if req.post_data is None:
                entry["post_data_binary"] = True
    except Exception:
        body = None
    try:
        picked = {k: v[:200] for k, v in (req.headers or {}).items() if k.lower() in INTERESTING_HEADERS}
        if picked:
            entry["headers_of_interest"] = picked
    except Exception as e:
        logger.warning("v3 network sensor: headers dropped for %s: %s", req.url[:120], e)
    surface = req.url + " " + (body or "") + " " + json.dumps(entry.get("headers_of_interest", {}))
    hits, encoding = find_honeypot_any(surface)
    if hits:
        entry["honeypot_markers"] = hits
        entry["honeypot_encoding"] = encoding
        events["honeypot_exfil"] = True
        record_exfil_encoding(events, encoding)
        events["honeypot_exfil_details"].append({
            "url": req.url, "method": req.method, "markers": hits, "encoding": encoding, "ts": entry["ts"],
            "where": "post_data" if (body and find_honeypot_any(body)[0]) else "url_or_header"})
    events["network_requests"].append(entry)


async def _grab_opener(page, rec):
    """A1a: a tab whose opener is a web page (window.open from a site) is not opened by the
    extension; an opener that is an extension page (popup / options) still counts as extension."""
    try:
        op = await page.opener()
        rec["opener_url"] = (op.url[:300] if op else None)
        rec["opener_is_page"] = bool(op) and not op.url.startswith("chrome-extension://")
    except Exception as e:
        rec["opener_error"] = str(e)[:80]


async def _grab_title(page, rec):
    try:
        title = await page.title()
        rec["titles"].append({"url": page.url, "title": title[:300], "ts": now_ms()})
    except Exception as e:
        logger.debug("v3 tab sensor: title not read: %s", e)


def mark_harness_pages(context, events):
    """Wrap context.new_page so tabs opened by the harness are marked in tabs_v3 (T1-4)."""
    original = context.new_page

    async def new_page(*a, **k):
        page = await original(*a, **k)
        rec = _TAB_RECS.get(id(page))
        if rec is not None:
            rec["opened_by"] = "harness"
        else:
            events.setdefault("_harness_page_ids", []).append(id(page))
        return page
    context.new_page = new_page


async def setup_observers_v3(context, events):
    events.setdefault("tabs_v3", [])

    def on_request(req):
        sw = getattr(req, "service_worker", None)
        if sw is not None:
            if os.environ.get("SANDBOX_RECORD_PW_SW") == "1":
                events.setdefault("pw_sw_requests", []).append({
                    "url": req.url, "method": req.method, "resource_type": req.resource_type, "sw_url": sw.url,
                    "phase": events.get("_current_phase"), "ts": now_ms(),
                    "t": round(time.monotonic() - events["_t0"], 3) if events.get("_t0") else None})
            return
        try:
            _ = req.frame
            origin = "page"
        except Exception:
            # v2 rule kept for comparability; in v3 this is mostly the navigation of a tab whose
            # page object does not exist yet (frame_unavailable), not a service-worker request
            origin = "service_worker"
        _record_request(req, events, origin)
        entry = events["network_requests"][-1]
        if origin == "service_worker":
            entry["frame_unavailable"] = True
        try:
            entry["navigation"] = bool(req.is_navigation_request())
        except Exception:
            entry["navigation"] = None

    context.on("request", on_request)

    def on_response(res):
        try:
            events["responses"].append({"url": res.url[:300], "status": res.status, "ts": now_ms()})
        except Exception as e:
            logger.warning("v3 network sensor: response not recorded: %s", e)

    context.on("response", on_response)

    def on_page(p):
        try:
            ts = now_ms()
            events["new_tabs"].append({"url": p.url, "phase": events.get("_current_phase"), "ts": ts})
            rec = {"tab_seq": len(events["tabs_v3"]), "opened_ts": ts, "opened_phase": events.get("_current_phase"),
                   "opened_by": "harness" if id(p) in events.get("_harness_page_ids", []) else "other",
                   "initial_url": p.url, "navigations": [], "titles": [], "_nav_requests": [], "closed_ts": None}
            events["tabs_v3"].append(rec)
            _TAB_RECS[id(p)] = rec
            _PAGES[id(p)] = p

            def on_nav(f):
                if f == p.main_frame:
                    rec["navigations"].append({"url": f.url[:2000], "ts": now_ms()})
                events["navigations"].append({"url": f.url[:300], "ts": now_ms(), "tab_seq": rec["tab_seq"],
                                              "main_frame": f == p.main_frame})

            def on_req(r):
                try:
                    if r.is_navigation_request() and r.frame == p.main_frame:
                        chain, prev = [], r.redirected_from
                        while prev is not None and len(chain) < 20:
                            chain.insert(0, prev.url[:2000])
                            prev = prev.redirected_from
                        rec["_nav_requests"].append({"url": r.url[:2000], "ts": now_ms(), "redirect_chain": chain})
                except Exception as e:
                    logger.debug("v3 tab sensor: navigation request skipped: %s", e)

            def on_close(_):
                rec["closed_ts"] = now_ms()

            asyncio.ensure_future(_grab_opener(p, rec))
            p.on("framenavigated", on_nav)
            p.on("request", on_req)
            p.on("load", lambda _: asyncio.ensure_future(_grab_title(p, rec)))
            p.on("close", on_close)
            # console logs: the v2 phase code attaches its own listener to harness tabs (no ts);
            # not duplicated here.
            print(f"[Analyze] * New tab opened: {p.url[:100]}", flush=True)
        except Exception as e:
            logger.warning("v3 tab sensor: new tab not recorded: %s", e)

    context.on("page", on_page)

    def on_sw(sw):
        try:
            events["service_workers"].append({"url": sw.url, "ts": now_ms()})
        except Exception as e:
            logger.warning("v3 service-worker sensor: not recorded: %s", e)

    context.on("serviceworker", on_sw)


async def final_titles():
    """Read the title of every page still open at the end of the run (T1-4)."""
    for pid, page in list(_PAGES.items()):
        rec = _TAB_RECS.get(pid)
        if rec is None or rec.get("closed_ts"):
            continue
        try:
            await asyncio.wait_for(_grab_title(page, rec), timeout=2)
        except Exception:
            pass
