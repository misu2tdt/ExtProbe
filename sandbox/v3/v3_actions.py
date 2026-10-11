"""v3 phases that differ from v2.

  load            v3 sensors; waits for the CDP extension load (A1b); installs the A4 init script
  honeypot_pages  the v2 visit of TEST_URLS (same dwell and stimulus) + the A4 check before close
  target_matched  T1-5: the honey / product page is served (route.fulfill) only to DOCUMENT
                  navigation requests on a target host; everything else continues to the network.
                  Same stimulus and link probe as v2's product probe. + the A4 check before close.

A4 (T1-9): an init script, added before any page loads, keeps references to the native
window.fetch, XMLHttpRequest.prototype.open / send and window.WebSocket, and to the native
Function.prototype.toString, in a closure. At the end of every harness page visit the harness asks
it whether those four are still the originals (identity) and still native (toString of the
current value, through the saved native toString). For a replaced one it also returns the first
400 characters of the replacement's source (`src`), to tell a filtering wrapper from one that
reads request / response data. Harness pages load no script that patches
them, so a change was made by the extension (directly or through a script it injected).
"""
import asyncio
import logging
from urllib.parse import urlparse

from config import DWELL_MS, MAX_TARGET_HOSTS, PER_PAGE_TIMEOUT_MS, TEST_URLS
from phases.actions import (PRODUCT_PATH, RETAILER_FALLBACK_HOSTS, _concrete_target_hosts,
                            _has_all_hosts_match, _read_honey, _record_target_links)
from v3_common import now_ms
from v3_dom import setup_dom_sensor_v3
from v3_network import mark_harness_pages, setup_observers_v3
import v3_startup

logger = logging.getLogger(__name__)

HOOK_CHECK_INIT = r"""
(() => {
  try {
    const T = Function.prototype.toString;
    const X = window.XMLHttpRequest && window.XMLHttpRequest.prototype;
    const orig = {fetch: window.fetch, xhr_open: X && X.open, xhr_send: X && X.send, websocket: window.WebSocket};
    const nat = (f) => { try { return typeof f === 'function' && /\{\s*\[native code\]\s*\}\s*$/.test(T.call(f)); }
                         catch (e) { return null; } };
    Object.defineProperty(window, '__extprobe_hook_check', {enumerable: false, configurable: false, value: () => {
      const XP = window.XMLHttpRequest && window.XMLHttpRequest.prototype;
      const cur = {fetch: window.fetch, xhr_open: XP && XP.open, xhr_send: XP && XP.send, websocket: window.WebSocket};
      const out = {};
      for (const k of Object.keys(orig)) {
        out[k] = {same: cur[k] === orig[k], native: nat(cur[k])};
        if (!out[k].same || out[k].native === false) {
          // source of the replacement, through the saved native toString (a Proxy reads as native)
          try { out[k].src = typeof cur[k] === 'function' ? T.call(cur[k]).slice(0, 400) : String(typeof cur[k]); }
          catch (e) { out[k].src = null; }
        }
      }
      return out;
    }});
  } catch (e) {}
})();
"""


async def hook_check(tab, events, where):
    try:
        res = await tab.evaluate("window.__extprobe_hook_check ? window.__extprobe_hook_check() : null")
    except Exception as e:
        res, err = None, str(e).split("\n")[0][:100]
    else:
        err = None
    rec = {"page_url": tab.url[:300], "phase": events.get("_current_phase"), "where": where, "ts": now_ms(),
           "result": res, "error": err}
    if isinstance(res, dict):
        rec["replaced"] = sorted(k for k, v in res.items() if isinstance(v, dict) and (not v.get("same") or v.get("native") is False))
    events.setdefault("page_api_hooks", []).append(rec)


async def phase_load_v3(context, events):
    mark_harness_pages(context, events)
    await setup_observers_v3(context, events)
    await setup_dom_sensor_v3(context, events)
    await context.add_init_script(HOOK_CHECK_INIT)
    await v3_startup.wait_loaded(events)
    await asyncio.sleep(3)
    seen = {s.get("url") for s in events["service_workers"]}
    for sw in context.service_workers:
        if sw.url not in seen:
            events["service_workers"].append({"url": sw.url, "ts": now_ms()})
            seen.add(sw.url)


async def visit_pages_v3(context, events, output, save_events):
    """The v2 honeypot_pages visit (sandbox/phases/actions.py::_visit_pages), plus hook_check."""
    for i, url in enumerate(TEST_URLS):
        tab = None
        try:
            tab = await context.new_page()
            tab.on("console", lambda msg: events["console_logs"].append(
                {"type": msg.type, "text": msg.text[:200], "ts": now_ms()}))
            tab.on("pageerror", lambda err: events["errors"].append(str(err)[:200]))
            await tab.goto(url, wait_until="commit", timeout=PER_PAGE_TIMEOUT_MS)
            await tab.wait_for_timeout(DWELL_MS)
            try:
                await tab.evaluate("window.scrollBy(0, 400)")
                await tab.evaluate("""
                    (() => {
                      const el = document.querySelector('input[type=password], input');
                      if (el) { el.focus();
                                el.dispatchEvent(new Event('input', {bubbles:true})); }
                    })()
                """)
            except Exception as e:
                logger.debug("honeypot_pages %s: stimulus skipped: %s", url, e)
            await tab.wait_for_timeout(1500)
            await hook_check(tab, events, url)
            await tab.screenshot(path=str(output / f"screenshot_{i}.png"))
            events["pages_visited"].append(url)
            save_events()
        except Exception as e:
            msg = str(e).split("\n")[0][:150]
            events["errors"].append(f"navigate {url}: {msg}")
            events["page_hang_count"] += 1
            save_events()
        finally:
            if tab:
                try:
                    await tab.close()
                except Exception:
                    pass


async def phase_target_matched_v3(context, events):
    manifest = events.get("manifest", {}) or {}
    hosts = _concrete_target_hosts(manifest)
    try:
        universal = _read_honey("universal.html")
    except Exception:
        universal = "<!doctype html><html><body><form><input type=password value=HONEYPOT-PASSWORD></form></body></html>"
    product = _read_honey("product_test.html")
    fallback = not hosts and _has_all_hosts_match(manifest)
    if fallback:
        hosts = list(RETAILER_FALLBACK_HOSTS)
    events["target_matched_hosts"] = hosts
    events["target_matched_mode"] = "product_probe" + ("+retailer_fallback" if fallback else "") + "+doc_only_v3"
    events.setdefault("target_matched_route_log", [])
    if not hosts:
        events["target_matched_note"] = "no_concrete_target"
        return
    events.setdefault("target_matched_visited", [])
    for host in hosts[:MAX_TARGET_HOSTS]:
        glob = f"**://*{host}/**"

        async def _route(route):
            req = route.request
            is_doc = req.resource_type == "document" and req.is_navigation_request()
            log = {"url": req.url[:300], "resource_type": req.resource_type, "ts": now_ms(),
                   "action": "fulfill" if is_doc else "continue"}
            events["target_matched_route_log"].append(log)
            try:
                if is_doc:
                    path = urlparse(req.url).path or "/"
                    is_product = (fallback or path == PRODUCT_PATH or path.startswith("/dp/") or path.startswith("/item/"))
                    await route.fulfill(status=200, content_type="text/html", body=product if is_product else universal)
                else:
                    await route.continue_()
            except Exception as e:
                log["error"] = str(e).split("\n")[0][:120]
                try:
                    await route.continue_()
                except Exception:
                    pass

        tab = None
        try:
            await context.route(glob, _route)
            tab = await context.new_page()
            tab.on("console", lambda msg: events["console_logs"].append(
                {"type": msg.type, "text": msg.text[:200], "ts": now_ms()}))
            tab.on("pageerror", lambda err: events["errors"].append(str(err)[:200]))
            if not fallback:
                await tab.goto(f"https://{host}/", wait_until="commit", timeout=PER_PAGE_TIMEOUT_MS)
                await tab.wait_for_timeout(DWELL_MS)
                try:
                    await tab.evaluate("window.scrollBy(0, 400)")
                    await tab.evaluate("""(() => {
                        const el = document.querySelector('input[type=password], input');
                        if (el) { el.focus(); el.dispatchEvent(new Event('input', {bubbles:true})); }
                    })()""")
                except Exception as e:
                    logger.debug("target_matched %s: stimulus skipped: %s", host, e)
                await tab.wait_for_timeout(1500)
                await hook_check(tab, events, f"https://{host}/")
            page_url = f"https://{host}{PRODUCT_PATH}"
            await tab.goto(page_url, wait_until="commit", timeout=PER_PAGE_TIMEOUT_MS)
            await tab.wait_for_timeout(DWELL_MS)
            await hook_check(tab, events, page_url)
            await _record_target_links(tab, host, events, product, page_url=page_url)
            events["target_matched_visited"].append(host)
        except Exception as e:
            events["errors"].append(f"target_matched {host}: {str(e).split(chr(10))[0][:150]}")
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
