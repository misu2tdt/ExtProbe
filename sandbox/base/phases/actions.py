import asyncio
import logging
import re
import time
from urllib.parse import urljoin, urlparse
from config import TEST_URLS, PER_PAGE_TIMEOUT_MS, DWELL_MS, MAX_TARGET_HOSTS
from utils import _host_of
from sensors.network import _setup_context_observers
from sensors.dom import _setup_dom_sensor

logger = logging.getLogger(__name__)


async def _phase_load(context, events):
    """Phase load: gan sensor, cho service worker dang ky."""
    await _setup_context_observers(context, events)
    await _setup_dom_sensor(context, events)
    await asyncio.sleep(3)                    # cho SW kip dang ky
    seen_sw = {s.get("url") for s in events["service_workers"]}
    for sw in context.service_workers:
        if sw.url not in seen_sw:
            events["service_workers"].append({"url": sw.url})
            seen_sw.add(sw.url)


_GENERIC_HOSTS = {"<all_urls>", "*", ""}


def _host_from_match(m):
    """Rut host tu content_scripts match pattern (vd 'https://*.tiktok.com/*' -> 'tiktok.com')."""
    if "://" not in m:
        return ""
    host = m.split("://", 1)[1].split("/", 1)[0]
    if host.startswith("*."):
        host = host[2:]
    return host


def _concrete_target_hosts(manifest):
    """Cac host CU THE ma extension nham (bo <all_urls>, *://*/*, host thuan wildcard,
    va host khong co dau cham nhu 'localhost' - khong spoof duoc/khong nen)."""
    hosts = []
    for cs in (manifest.get("content_scripts") or []):
        for m in (cs.get("matches") or []):
            if m == "<all_urls>":
                continue
            h = _host_from_match(m)
            if not h or h in _GENERIC_HOSTS or "*" in h or "." not in h:
                continue
            if h not in hosts:
                hosts.append(h)
    return hosts


PROBE_FALLBACK_HOST = "shop.bench.test"
_ALL_HOSTS_MATCHES = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}


def _has_all_hosts_match(manifest):
    return any(m in _ALL_HOSTS_MATCHES
               for cs in (manifest.get("content_scripts") or []) for m in (cs.get("matches") or []))


def _served_hrefs(html, host):
    """Link URLs exactly as the sandbox served them (before any extension ran)."""
    return [urljoin(f"https://{host}/", h)
            for h in re.findall(r"""<a\b[^>]*\bhref=["']([^"']+)["']""", html, re.I)]


async def _record_target_links(tab, host, events, served_html="", page_url=None):
    """Record every link's href as the page stands after the extension ran, then follow one
    /dp/ and one /item/ link and record the URL the tab ends on. Result:
    events["target_page_probe"] (read by risk.detect_affiliate_hijack on v2 traces)."""
    page_url = page_url or f"https://{host}/"
    t0 = events.get("_t0")
    rec = {"host": host, "url_before_click": tab.url, "clicks": [],
           "hrefs_served": _served_hrefs(served_html, host)}
    try:
        rec["hrefs"] = await tab.eval_on_selector_all("a", "els => els.map(e => e.href)")
    except Exception as e:
        rec["hrefs_error"] = str(e).split("\n")[0][:150]
    # One /dp/ link and one /item/<id>.html link; reload the test page before the second.
    for i, sel in enumerate(("#p1", "#a1")):
        click = {"selector": sel}
        try:
            if i:
                await tab.goto(page_url, wait_until="commit", timeout=PER_PAGE_TIMEOUT_MS)
                await tab.wait_for_timeout(2000)
            click["t_click"] = round(time.monotonic() - t0, 3) if t0 is not None else None
            await tab.click(sel, timeout=3000)
            await tab.wait_for_timeout(3000)
            click["url_after_click"] = tab.url
        except Exception as e:
            click["click_error"] = str(e).split("\n")[0][:150]
        rec["clicks"].append(click)
    events.setdefault("target_page_probe", []).append(rec)


async def _phase_target_matched(context, events):
    """Hulk-style honey page (ref: Kapravelos et al. 2014). Doc content_scripts.matches,
    spoof tung host dich bang route.fulfill(honey page van nang) => content script cua
    extension (chi chay tren site do) duoc tiem => 6 sensor bat hanh vi. Malware tuong
    dang o dung site nen ra tay; honey page co san form login/payment (kem honeypot
    marker) de no 'thay cai no tim'."""
    import os
    manifest = events.get("manifest", {}) or {}
    hosts = _concrete_target_hosts(manifest)
    # SANDBOX_TARGET_PAGE (do luong, mac dinh tat): phuc vu trang khac thay universal.html
    # va ghi lai link sau khi extension chay (xem _record_target_links).
    probe_page = os.path.basename(os.environ.get("SANDBOX_TARGET_PAGE", ""))
    forced_host = os.environ.get("SANDBOX_TARGET_HOST", "").strip().lower()
    if not probe_page and os.environ.get("SANDBOX_PRODUCT_PROBE") == "1":
        return await _phase_target_matched_product(context, events, manifest, hosts)
    if probe_page and forced_host:
        # Measurement only: serve the test page at this host whatever the manifest declares
        # (e.g. a retailer host for shopping extensions). Ignored without SANDBOX_TARGET_PAGE.
        hosts = [forced_host]
    elif not hosts and probe_page and _has_all_hosts_match(manifest):
        # Measurement only: an extension whose content scripts run everywhere gets the test
        # page at a neutral shop-like test host (intercepted by route.fulfill, never resolved).
        hosts = [PROBE_FALLBACK_HOST]
    events["target_matched_hosts"] = hosts
    if not hosts:
        events["target_matched_note"] = "no_concrete_target"
        return
    honey_path = os.path.join(os.path.dirname(__file__), "..", "honey_pages",
                              probe_page or "universal.html")
    try:
        with open(honey_path, encoding="utf-8") as f:
            honey = f.read()
    except Exception:
        honey = "<!doctype html><html><body><form><input type=password value=HONEYPOT-PASSWORD></form></body></html>"

    events.setdefault("target_matched_visited", [])
    for host in hosts[:MAX_TARGET_HOSTS]:
        glob = f"**://*{host}/**"

        async def _fulfill(route):
            try:
                await route.fulfill(status=200, content_type="text/html", body=honey)
            except Exception:
                try:
                    await route.continue_()
                except Exception as e:
                    logger.warning("target_matched: could not fulfill or continue %s, "
                                   "honey page not served: %s", route.request.url[:120], e)

        tab = None
        try:
            await context.route(glob, _fulfill)
            tab = await context.new_page()
            tab.on("console", lambda msg: events["console_logs"].append(
                {"type": msg.type, "text": msg.text[:200]}))
            tab.on("pageerror", lambda err: events["errors"].append(str(err)[:200]))
            await tab.goto(f"https://{host}/", wait_until="commit", timeout=PER_PAGE_TIMEOUT_MS)
            await tab.wait_for_timeout(DWELL_MS)
            try:
                await tab.evaluate("window.scrollBy(0, 400)")
                await tab.evaluate("""(() => {
                    const el = document.querySelector('input[type=password], input');
                    if (el) { el.focus(); el.dispatchEvent(new Event('input', {bubbles:true})); }
                })()""")
            except Exception as e:
                logger.debug("target_matched %s: scroll/focus stimulus skipped "
                             "(page may have navigated): %s", host, e)
            await tab.wait_for_timeout(1500)
            if probe_page:
                await _record_target_links(tab, host, events, honey)
            events["target_matched_visited"].append(host)
            print(f"[Analyze] target_matched spoofed {host}", flush=True)
        except Exception as e:
            events["errors"].append(f"target_matched {host}: {str(e).split(chr(10))[0][:150]}")
        finally:
            if tab:
                try:
                    await tab.close()
                except Exception as e:
                    logger.debug("target_matched %s: tab.close failed (already closed?): %s", host, e)
            try:
                await context.unroute(glob)
            except Exception as e:
                logger.debug("target_matched %s: unroute %s failed: %s", host, glob, e)


PRODUCT_PATH = "/shop-test"
# Retailer hosts for extensions whose content scripts only match all hosts (no concrete
# target): the unbranded product test page is served there so shopping-link rewriters that
# key on retailer domains can act. Exactly MAX_TARGET_HOSTS (2) hosts; see FREEZE.md.
RETAILER_FALLBACK_HOSTS = ["amazon.com", "aliexpress.com"]


def _read_honey(name):
    import os
    path = os.path.join(os.path.dirname(__file__), "..", "honey_pages", name)
    with open(path, encoding="utf-8") as f:
        return f.read()


async def _phase_target_matched_product(context, events, manifest, hosts):
    """v2 default (SANDBOX_PRODUCT_PROBE=1, set in Dockerfile.v2): the corpus visit plus the
    product test page, so affiliate_hijack has something to observe. Per target host, in one
    tab: universal.html at "/" with the same dwell and stimulus as the corpus profile, then
    the unbranded product page at /shop-test and the link probe (_record_target_links). The
    route serves by path: /shop-test, /dp/*, /item/* -> product page, anything else ->
    universal.html. An extension with no concrete target but all-hosts content scripts gets
    only the product page, at RETAILER_FALLBACK_HOSTS."""
    try:
        universal = _read_honey("universal.html")
    except Exception:
        universal = "<!doctype html><html><body><form><input type=password value=HONEYPOT-PASSWORD></form></body></html>"
    product = _read_honey("product_test.html")
    fallback = not hosts and _has_all_hosts_match(manifest)
    if fallback:
        hosts = list(RETAILER_FALLBACK_HOSTS)
    events["target_matched_hosts"] = hosts
    events["target_matched_mode"] = "product_probe" + ("+retailer_fallback" if fallback else "")
    if not hosts:
        events["target_matched_note"] = "no_concrete_target"
        return
    events.setdefault("target_matched_visited", [])
    for host in hosts[:MAX_TARGET_HOSTS]:
        glob = f"**://*{host}/**"

        # One positional parameter only: Playwright passes (route, request) to a handler
        # that accepts two, which would shadow any extra parameter.
        async def _fulfill(route):
            path = urlparse(route.request.url).path or "/"
            is_product = (fallback or path == PRODUCT_PATH
                          or path.startswith("/dp/") or path.startswith("/item/"))
            try:
                await route.fulfill(status=200, content_type="text/html",
                                    body=product if is_product else universal)
            except Exception:
                try:
                    await route.continue_()
                except Exception as e:
                    logger.warning("target_matched: could not fulfill or continue %s: %s",
                                   route.request.url[:120], e)

        tab = None
        try:
            await context.route(glob, _fulfill)
            tab = await context.new_page()
            tab.on("console", lambda msg: events["console_logs"].append(
                {"type": msg.type, "text": msg.text[:200]}))
            tab.on("pageerror", lambda err: events["errors"].append(str(err)[:200]))
            if not fallback:   # same visit as the corpus profile first
                await tab.goto(f"https://{host}/", wait_until="commit", timeout=PER_PAGE_TIMEOUT_MS)
                await tab.wait_for_timeout(DWELL_MS)
                try:
                    await tab.evaluate("window.scrollBy(0, 400)")
                    await tab.evaluate("""(() => {
                        const el = document.querySelector('input[type=password], input');
                        if (el) { el.focus(); el.dispatchEvent(new Event('input', {bubbles:true})); }
                    })()""")
                except Exception as e:
                    logger.debug("target_matched %s: scroll/focus stimulus skipped: %s", host, e)
                await tab.wait_for_timeout(1500)
            page_url = f"https://{host}{PRODUCT_PATH}"
            await tab.goto(page_url, wait_until="commit", timeout=PER_PAGE_TIMEOUT_MS)
            await tab.wait_for_timeout(DWELL_MS)
            await _record_target_links(tab, host, events, product, page_url=page_url)
            events["target_matched_visited"].append(host)
            print(f"[Analyze] target_matched spoofed {host} (+product page)", flush=True)
        except Exception as e:
            events["errors"].append(f"target_matched {host}: {str(e).split(chr(10))[0][:150]}")
        finally:
            if tab:
                try:
                    await tab.close()
                except Exception as e:
                    logger.debug("target_matched %s: tab.close failed: %s", host, e)
            try:
                await context.unroute(glob)
            except Exception as e:
                logger.debug("target_matched %s: unroute %s failed: %s", host, glob, e)


async def _visit_pages(context, events, output, save_events):
    for i, url in enumerate(TEST_URLS):
        tab = None
        try:
            print(f"[Analyze] Visiting {url}", flush=True)
            tab = await context.new_page()
            tab.on("console", lambda msg: events["console_logs"].append(
                {"type": msg.type, "text": msg.text[:200]}))
            tab.on("pageerror", lambda err: events["errors"].append(str(err)[:200]))

            await tab.goto(url, wait_until="commit", timeout=PER_PAGE_TIMEOUT_MS)
            await tab.wait_for_timeout(DWELL_MS)

            # Kich thich nhe: scroll + cham vao o input (du extension doc form)
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
                logger.debug("honeypot_pages %s: scroll/focus stimulus skipped "
                             "(page may have navigated): %s", url, e)
            await tab.wait_for_timeout(1500)

            await tab.screenshot(path=str(output / f"screenshot_{i}.png"))
            events["pages_visited"].append(url)
            save_events()              # GHI TANG DAN: song sot qua timeout
        except Exception as e:
            msg = str(e).split("\n")[0][:150]
            print(f"[Analyze] Error at {url}: {msg}", flush=True)
            events["errors"].append(f"navigate {url}: {msg}")
            events["page_hang_count"] += 1
            save_events()
        finally:
            if tab:
                try:
                    await tab.close()   # dong tab => cat hanh vi tich luy
                except Exception as e:
                    logger.debug("honeypot_pages %s: tab.close failed (already closed?): %s", url, e)


async def _probe_extension_pages(context, events, output):
    """Mo popup/options cua extension - nhieu extension chi chay logic khi popup mo."""
    ext_ids = set()
    for sw in events.get("service_workers", []):
        h = _host_of(sw.get("url", ""))
        if h:
            ext_ids.add(h)
    for r in events.get("network_requests", []):
        if r.get("url", "").startswith("chrome-extension://"):
            h = _host_of(r["url"])
            if h:
                ext_ids.add(h)
    events["extension_ids_seen"] = sorted(ext_ids)

    for ext_id in list(ext_ids)[:2]:
        for page_name in ["popup.html", "popup/popup.html", "options.html"]:
            tab = None
            try:
                tab = await context.new_page()
                await tab.goto(f"chrome-extension://{ext_id}/{page_name}",
                               wait_until="commit", timeout=4000)
                await tab.wait_for_timeout(2500)
                await tab.screenshot(
                    path=str(output / f"ext_{page_name.replace('/', '_')}.png"))
                events["extension_pages_opened"].append(f"{ext_id}/{page_name}")
                print(f"[Analyze] Opened extension page: {page_name}", flush=True)
                break
            except Exception as e:
                logger.debug("extension_pages: %s/%s not openable, trying next candidate: %s",
                             ext_id, page_name, e)
            finally:
                if tab:
                    try:
                        await tab.close()
                    except Exception as e:
                        logger.debug("extension_pages: tab.close failed (already closed?): %s", e)
