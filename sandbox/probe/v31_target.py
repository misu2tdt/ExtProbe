"""Short re-run of target_matched after the explorer (DESIGN.md §2): only the hosts the v3 phase already
matched (events["target_matched_visited"]), only their product page, with the same route rule as v3 (the
honey product page is served to document navigations only), the same dwell, the same API-hook check and the
same link record (affiliate detection). Hosts are visited while the probe's extra time stays within
EXTRA_BUDGET_S (explorer + this phase), so the whole probe adds at most ~45 s per sample.
"""
import time
from urllib.parse import urlparse

from config import DWELL_MS, PER_PAGE_TIMEOUT_MS
from phases.actions import PRODUCT_PATH, _read_honey, _record_target_links
from v3_actions import hook_check
from v3_common import now_ms

EXTRA_BUDGET_S = 45
PER_HOST_S = 13


async def rerun_target(context, events, probe_t0_monotonic):
    hosts = list(events.get("target_matched_visited") or [])
    rec = {"hosts_matched": len(hosts), "hosts_visited": 0, "skipped_for_budget": 0}
    events["probe_target"] = rec
    if not hosts:
        return
    product = _read_honey("product_test.html")
    try:
        universal = _read_honey("universal.html")
    except Exception:
        universal = product
    fallback = "retailer_fallback" in (events.get("target_matched_mode") or "")
    for host in hosts:
        if time.monotonic() - probe_t0_monotonic + PER_HOST_S > EXTRA_BUDGET_S:
            rec["skipped_for_budget"] += 1
            continue
        glob = f"**://*{host}/**"

        async def _route(route):
            req = route.request
            is_doc = req.resource_type == "document" and req.is_navigation_request()
            events["target_matched_route_log"].append({"url": req.url[:300], "resource_type": req.resource_type,
                                                       "ts": now_ms(), "action": "fulfill" if is_doc else "continue"})
            try:
                if is_doc:
                    path = urlparse(req.url).path or "/"
                    is_product = fallback or path == PRODUCT_PATH or path.startswith("/dp/") or path.startswith("/item/")
                    await route.fulfill(status=200, content_type="text/html", body=product if is_product else universal)
                else:
                    await route.continue_()
            except Exception:
                try:
                    await route.continue_()
                except Exception:
                    pass

        tab = None
        try:
            await context.route(glob, _route)
            tab = await context.new_page()
            page_url = f"https://{host}{PRODUCT_PATH}"
            await tab.goto(page_url, wait_until="commit", timeout=PER_PAGE_TIMEOUT_MS)
            await tab.wait_for_timeout(DWELL_MS)
            await hook_check(tab, events, page_url)
            await _record_target_links(tab, host, events, product, page_url=page_url)
            rec["hosts_visited"] += 1
        except Exception as e:
            events["errors"].append(f"probe_target {host}: {str(e).split(chr(10))[0][:120]}")
        finally:
            if tab:
                try:
                    await tab.close()
                except Exception:
                    pass
            try:
                await context.unroute(glob)
            except Exception:
                pass
