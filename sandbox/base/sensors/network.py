import json
import logging
import os
import time
from config import MAX_BODY_LEN, INTERESTING_HEADERS
from honeypot import find_honeypot_any, record_exfil_encoding
from utils import _host_of

logger = logging.getLogger(__name__)


# ============ CAM BIEN 1+2: NETWORK + PAYLOAD SAU ============
def _record_request(req, events, origin: str):
    entry = {
        "url": req.url,
        "method": req.method,
        "resource_type": req.resource_type,
        "origin": origin,
        "host": _host_of(req.url),
    }
    entry["phase"] = events.get("_current_phase")

    if events.get("_t0") is not None:
        entry["t"] = round(time.monotonic() - events["_t0"], 3)

    body = None
    try:
        body = req.post_data
        if body is None:
            raw = req.post_data_buffer           # bytes -- luon co neu request co body
            if raw:
                entry["post_data_binary_len"] = len(raw)
                body = raw.decode("utf-8", "replace")
    except Exception:
        body = None
    if body:
        entry["post_data"] = body[:MAX_BODY_LEN]
        entry["post_data_len"] = len(body)

    try:
        picked = {k: v[:200] for k, v in (req.headers or {}).items()
                  if k.lower() in INTERESTING_HEADERS}
        if picked:
            entry["headers_of_interest"] = picked
    except Exception as e:
        logger.warning("network sensor: headers_of_interest dropped for %s: %s", req.url[:120], e)

    surface = req.url + " " + (body or "") + " " + \
              json.dumps(entry.get("headers_of_interest", {}))
    hits, encoding = find_honeypot_any(surface)
    if hits:
        entry["honeypot_markers"] = hits
        entry["honeypot_encoding"] = encoding
        events["honeypot_exfil"] = True
        record_exfil_encoding(events, encoding)
        events["honeypot_exfil_details"].append({
            "url": req.url, "method": req.method, "markers": hits, "encoding": encoding,
            "where": "post_data" if (body and find_honeypot_any(body)[0]) else "url_or_header",
        })
        print(f"[Analyze] !!! HONEYPOT EXFIL ({encoding}): {hits} -> {req.url[:80]}", flush=True)

    events["network_requests"].append(entry)


async def _setup_context_observers(context, events):
    """Gan cam bien o CAP CONTEXT => phu ca page lan service worker."""

    def on_request(req):
        # Playwright moi (>=1.4x, profile v2) bao ca request cua MOI service worker (extension
        # lan SW cua chinh trang); Playwright 1.40 (corpus) thi khong. SW cua extension da do
        # cam bien CDP (cdp_sw.py) ghi -> bo qua o day de moi request chi ghi 1 lan va khong
        # quy nham SW cua trang thanh SW cua extension. Tren corpus nhanh nay khong bao gio chay.
        sw = getattr(req, "service_worker", None)
        if sw is not None:
            if os.environ.get("SANDBOX_RECORD_PW_SW") == "1":   # chan doan, mac dinh tat
                events.setdefault("pw_sw_requests", []).append({
                    "url": req.url, "method": req.method, "resource_type": req.resource_type,
                    "sw_url": sw.url, "phase": events.get("_current_phase"),
                    "t": round(time.monotonic() - events["_t0"], 3) if events.get("_t0") else None})
            return
        # Request tu service worker khong co frame => truy cap se nem loi
        try:
            _ = req.frame
            origin = "page"
        except Exception:
            origin = "service_worker"
        _record_request(req, events, origin)

    context.on("request", on_request)

    def on_response(res):
        try:
            events["responses"].append({"url": res.url[:300], "status": res.status})
        except Exception as e:
            logger.warning("network sensor: response not recorded: %s", e)

    context.on("response", on_response)

    # CAM BIEN 3: tab/popup moi (dau hieu backdoor tu mo URL)
    def on_page(p):
        try:
            events["new_tabs"].append({
                "url": p.url,
                "phase": events.get("_current_phase"),   # THEM: tab mo o phase nao
            })
            print(f"[Analyze] * New tab opened: {p.url[:100]}", flush=True)
            p.on("framenavigated",
                 lambda f: events["navigations"].append({"url": f.url[:300]}))
        except Exception as e:
            logger.warning("tab sensor: new tab / navigation hook not recorded: %s", e)

    context.on("page", on_page)

    def on_sw(sw):
        try:
            events["service_workers"].append({"url": sw.url})
            print(f"[Analyze] * Service worker: {sw.url[:100]}", flush=True)
        except Exception as e:
            logger.warning("service-worker sensor: service worker not recorded: %s", e)

    context.on("serviceworker", on_sw)