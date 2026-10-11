"""Unit tests of the v3 Tier-2 detectors (eval/v3/score_v3.py) on synthetic traces."""
import base64
import sys
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "eval" / "v3"))
import score_v3 as S  # noqa: E402

EXT = "abcdefghijklmnopabcdefghijklmnop"
BANK = "http://localhost:8888/fake_bank.html"


def _trace(**kw):
    ev = {"schema_version": "1.1+v3", "manifest": {"name": "t", "permissions": [], "host_permissions": []},
          "startup": {"profile": "v3"}, "service_workers": [{"url": f"chrome-extension://{EXT}/bg.js"}],
          "network_requests": [], "page_request_initiators": [], "tabs_v3": [
              {"opened_by": "harness", "initial_url": BANK, "navigations": [{"url": BANK}],
               "titles": [{"url": BANK, "title": "SecureBank - Login"}]}],
          "dom_activity": [], "page_api_hooks": [], "new_tabs": [], "extension_storage": {}, "page_hang_count": 0}
    ev.update(kw)
    return ev


def _sw(url, body="", phase="load", ts=1.0):
    return {"origin": "service_worker", "source": "cdp_sw", "resource_type": "Fetch", "url": url,
            "method": "POST" if body else "GET", "post_data": body, "ts": ts, "phase_ts": phase}


# ---- T2-2 history_exfil ----
def test_history_plain_urlencoded_twice_and_base64():
    for url in (f"https://c.evil.com/c?u={BANK}",
                f"https://c.evil.com/c?u={quote(quote(BANK, safe=''), safe='')}",
                "https://c.evil.com/c?d=" + base64.urlsafe_b64encode(BANK.encode()).decode().rstrip("=")):
        r = S.score_trace(_trace(network_requests=[_sw(url)]))
        assert r["signals"]["history_exfil"]["fired"], url
    enc = S.score_trace(_trace(network_requests=[_sw("https://c.evil.com/c?u=" + quote(quote(BANK, safe=""), safe=""))]))
    assert enc["signals"]["history_exfil"]["details"][0]["encoding"] == "url2"


def test_history_title_in_body_and_same_domain_ignored():
    r = S.score_trace(_trace(network_requests=[_sw("https://c.evil.com/t", body='{"title":"SecureBank - Login"}')]))
    assert r["signals"]["history_exfil"]["details"][0]["kind"] == "title"
    same = S.score_trace(_trace(network_requests=[_sw(f"http://localhost:8888/log?u={BANK}")]))
    assert not same["signals"]["history_exfil"]["fired"]


def test_history_bare_domain_and_page_requests_do_not_count():
    root = _trace(tabs_v3=[{"opened_by": "harness", "initial_url": "https://example.com/", "navigations": [],
                            "titles": []}],
                  network_requests=[_sw("https://c.evil.com/c?u=https://example.com/")])
    assert not S.score_trace(root)["signals"]["history_exfil"]["fired"]
    page = _trace(page_request_initiators=[{"url": f"https://c.evil.com/c?u={BANK}", "method": "GET",
                                            "attributed": "page"}])
    assert not S.score_trace(page)["signals"]["history_exfil"]["fired"]
    hook = _trace(page_request_initiators=[{"url": f"https://c.evil.com/c?u={BANK}", "method": "GET",
                                            "attributed": "page_via_extension_hook"}])
    assert not S.score_trace(hook)["signals"]["history_exfil"]["fired"]
    ext = _trace(page_request_initiators=[{"url": f"https://c.evil.com/c?u={BANK}", "method": "GET",
                                           "attributed": "extension", "ext_frames": [f"chrome-extension://{EXT}/cs.js"]}])
    assert S.score_trace(ext)["signals"]["history_exfil"]["fired"]


# ---- T2-3 undeclared heavy / light ----
def test_undeclared_light_vs_user_data():
    light = S.score_trace(_trace(network_requests=[_sw("https://api.vendor-x.com/ping"),
                                                   _sw("https://cdn.vendor-y.com/cfg")]))
    u = light["signals"]["undeclared_domain_contact"]
    assert u["class"] == "light" and u["weight"] == 20
    heavy = S.score_trace(_trace(network_requests=[_sw(f"https://api.vendor-x.com/p?u={BANK}")]))
    u = heavy["signals"]["undeclared_domain_contact"]
    assert u["class"] == "heavy" and u["weight"] == 40 and u["details"][0]["user_data"] == ["visited_url"]
    declared = _trace(network_requests=[_sw("https://api.vendor-x.com/ping")])
    declared["manifest"]["host_permissions"] = ["https://api.vendor-x.com/*"]
    assert not S.score_trace(declared)["signals"]["undeclared_domain_contact"]["fired"]


def test_persistent_id_needs_two_phases_and_not_in_package():
    uid = "3f2b8c1e-9a4d-4e7f-8b21-0c9d5e6f7a81"
    one = [_sw(f"https://t.vendor-x.com/e?id={uid}", phase="load")]
    assert S.persistent_ids(S.ext_requests(_trace(network_requests=one))) == {}
    two = one + [_sw(f"https://t.vendor-x.com/e?id={uid}", phase="honeypot_pages", ts=2.0)]
    r = S.score_trace(_trace(network_requests=two))
    assert r["signals"]["undeclared_domain_contact"]["details"][0]["user_data"] == ["persistent_id"]
    r = S.score_trace(_trace(network_requests=two), pkg_text=f"const KEY='{uid}';")
    assert r["signals"]["undeclared_domain_contact"]["class"] == "light"


# ---- T2-4 unsolicited_tab ----
def test_tabs_only_extension_opened_with_features():
    tabs = [{"opened_by": "harness", "initial_url": BANK, "navigations": [], "titles": [], "extension_opened": False},
            {"opened_by": "other", "opener_is_page": True, "extension_opened": False,
             "first_url": "https://popup.site/", "final_url": "https://popup.site/"},
            {"opened_by": "other", "extension_opened": True, "first_url": f"chrome-extension://{EXT}/welcome.html",
             "final_url": f"chrome-extension://{EXT}/welcome.html"},
            {"opened_by": "other", "extension_opened": True, "first_url": "https://go.vendor.com/install",
             "final_url": "https://land.offers.net/x",
             "redirects": [{"redirect_chain": ["https://go.vendor.com/install", "https://trk.ads.co.uk/r"]}],
             "titles": [{"title": "Offer"}], "t_since_install": 1.2, "opened_by_sw_call": "tabs.create"}]
    r = S.score_trace(_trace(tabs_v3=tabs))
    d = r["signals"]["unsolicited_tab"]["details"]
    assert len(d) == 1
    assert d[0]["registrable_domains"] == ["vendor.com", "ads.co.uk", "offers.net"]
    assert d[0]["n_registrable_domains"] == 3 and d[0]["t_since_install"] == 1.2


# ---- T2-5 script_injection ----
def test_injection_only_extension_attributed():
    node = {"type": "node_injected", "tag": "SCRIPT", "src": "https://ads.evil.com/a.js",
            "page_url": "https://shop.test-site.com/"}
    for who, fired in (("extension", True), ("page", False), (None, False), ("page_via_extension_hook", False)):
        r = S.score_trace(_trace(dom_activity=[dict(node, node_attributed=who)]))
        assert r["signals"]["script_injection"]["fired"] is fired, who


# ---- T2-6 affiliate: Amazon tag only on amazon.* ----
def test_affiliate_tag_only_on_amazon():
    def tr(host, href):
        return _trace(target_matched_visited=[host], target_page_probe=[
            {"hrefs_served": [f"https://{host}/shop-test"], "hrefs": [href], "clicks": []}])
    assert S.score_trace(tr("www.amazon.com", "https://www.amazon.com/shop-test?tag=x-20"))["signals"][
        "affiliate_hijack"]["fired"]
    assert not S.score_trace(tr("www.etsy.com", "https://www.etsy.com/shop-test?tag=x-20"))["signals"][
        "affiliate_hijack"]["fired"]
    r = S.score_trace(tr("www.etsy.com", "https://www.etsy.com/shop-test?tag=x&awc=1"))
    assert r["signals"]["affiliate_hijack"]["details"][0]["params"] == ["awc"]


# ---- T2-7 credential_exfil ----
def test_credential_exfil_only_extension_requests():
    page = {"origin": "page", "url": "https://bank.site/login", "post_data": "pw=HONEYPOT-PASSWORD",
            "honeypot_markers": ["HONEYPOT-PASSWORD"]}
    r = S.score_trace(_trace(network_requests=[page], honeypot_exfil=True))
    assert not r["signals"]["credential_exfil"]["fired"]
    r = S.score_trace(_trace(network_requests=[_sw("https://c2.evil.com/x", body="p=SE9ORVlQT1QtUEFTU1dPUkQ=")]))
    assert r["signals"]["credential_exfil"]["fired"] and r["score"] >= 80


# ---- T2-8 page_api_hooking ----
def test_page_api_hooking():
    hooks = [{"page_url": BANK, "phase": "honeypot_pages", "replaced": []},
             {"page_url": BANK, "phase": "honeypot_pages", "replaced": ["fetch", "xhr_open"]}]
    r = S.score_trace(_trace(page_api_hooks=hooks))
    assert r["signals"]["page_api_hooking"]["fired"] and r["signals"]["page_api_hooking"]["weight"] == 15
    assert not S.score_trace(_trace(page_api_hooks=hooks[:1]))["signals"]["page_api_hooking"]["fired"]


# ---- score composition ----
def test_static_is_display_only_and_light_signals_add_up():
    ev = _trace()
    ev["manifest"].update(permissions=["tabs", "cookies", "history", "webRequest", "scripting", "downloads"],
                          host_permissions=["<all_urls>"])
    r = S.score_trace(ev)
    assert r["score"] == 0 and r["static_display"]["static_score"] > 0 and not r["flag"]
    two = _trace(page_api_hooks=[{"replaced": ["fetch"]}],
                 dom_activity=[{"type": "node_injected", "tag": "SCRIPT", "src": "https://ads.evil.com/a.js",
                                "page_url": "https://x.site/", "node_attributed": "extension"}])
    assert S.score_trace(two)["score"] == 30 and not S.score_trace(two)["flag"]
    three = dict(two, network_requests=[_sw("https://api.vendor-x.com/ping")])
    assert S.score_trace(three)["score"] == 45 and S.score_trace(three)["flag"]


def test_registrable():
    assert S.registrable("a.b.example.co.uk") == "example.co.uk"
    assert S.registrable("x.y.com") == "y.com"
    assert S.registrable("localhost") == "localhost"


# ---- amendment 1 ----
def test_frameless_playwright_records_are_not_sw_requests():
    nav = {"origin": "service_worker", "url": "https://land.example-x.com/install", "resource_type": "document",
           "source": "playwright", "frame_unavailable": True, "phase_ts": "load"}
    old_nav = {k: v for k, v in nav.items() if k not in ("source", "frame_unavailable")}
    cdp = {"origin": "service_worker", "url": "https://api.vendor-x.com/p", "resource_type": "Fetch", "source": "cdp_sw"}
    old_cdp = {k: v for k, v in cdp.items() if k != "source"}
    assert [S.is_sw_request(r) for r in (nav, old_nav, cdp, old_cdp)] == [False, False, True, True]
    r = S.score_trace(_trace(network_requests=[nav]))
    assert not r["signals"]["undeclared_domain_contact"]["fired"]


def test_link_sw_call_relative_and_trailing_slash():
    calls = [{"api": "tabs.create", "url": "welcome.html", "ts": 1000},
             {"api": "tabs.create", "url": "https://www.shop-x.com?src=ext", "ts": 1001}]
    ext_tab = {"first_url": f"chrome-extension://{EXT}/welcome.html", "opened_ts": 1100}
    web_tab = {"first_url": "https://www.shop-x.com/?src=ext", "opened_ts": 1300}
    late = {"first_url": "https://www.shop-x.com/?src=ext", "opened_ts": 99999}
    assert S.link_sw_call(ext_tab, calls, EXT) == ("tabs.create", 1000)
    assert S.link_sw_call(web_tab, calls, EXT) == ("tabs.create", 1001)
    assert S.link_sw_call(late, calls, EXT) == (None, None)


def test_stored_uuid_alone_is_not_persistent_id():
    uid = "3f2b8c1e-9a4d-4e7f-8b21-0c9d5e6f7a81"
    ev = _trace(network_requests=[_sw(f"https://t.vendor-x.com/e?id={uid}")],
                extension_storage_v3={"uuid_tokens": [{"token": uid, "version": "4"}]})
    assert S.score_trace(ev)["signals"]["undeclared_domain_contact"]["details"][0]["user_data"] == []
