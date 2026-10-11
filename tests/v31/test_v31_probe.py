"""Unit tests of the v3.1-probe pure modules: click policy, login gate, trace split, proxy-host parsing."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sandbox_v3_1_probe"))
from v31_policy import PRIORITY, ext_pages, login_gate, priority, skip_reason, state_hash  # noqa: E402
from v31_split import offsets, split  # noqa: E402


def it(text, tag="button", href="", role="", type_=""):
    return {"text": text, "tag": tag, "href": href, "role": role, "type": type_, "xp": "0"}


# ---------------- policy
def test_deny_list_never_clicked():
    for t in ["Uninstall", "Remove extension", "Buy now", "Upgrade to Premium", "Log out", "Sign out", "Report abuse",
              "Share", "Rate us", "Privacy policy", "Terms of use", "Pricing", "Delete all data", "Subscribe", "Contact support"]:
        assert priority(it(t)) is None, t


def test_deny_list_prefix_and_plural():
    for t in ["Payments", "Purchases", "Subscriptions", "Reports", "Deleting history", "Delete", "Clear data",
              "Clear all", "Reset settings", "Erase", "Unsubscribe", "Log off", "Sign off", "Logoff", "Removed items",
              "Upgrades", "Sharing", "Reviews"]:
        assert priority(it(t)) is None and skip_reason(it(t)) == "deny", t
    assert skip_reason(it("Login")) == "login" and skip_reason(it("Sign-up free")) == "login"
    assert priority(it("Online status")) is not None and priority(it("Connect now")) == PRIORITY.index("connect")


def test_unlabeled_and_non_english_not_clicked():
    for t in ["", "   ", "✓", "→", "12", "⚙"]:
        assert priority(it(t)) is None and skip_reason(it(t)) == "unlabeled", repr(t)
    assert priority(it("", role="switch")) is None and priority(it("", type_="checkbox")) is None
    for t in ["Подключить", "连接", "Connexión", "Löschen", "Bật"]:
        assert priority(it(t)) is None and skip_reason(it(t)) == "non_english", t
    assert skip_reason(it("Settings")) is None


def test_login_controls_not_clicked_and_external_links_skipped():
    assert priority(it("Log in")) is None and priority(it("Sign up")) is None and priority(it("Continue with Google")) is None
    assert priority(it("Open dashboard", tag="a", href="https://vendor.example/app")) is None
    assert priority(it("Settings", tag="a", href="#settings")) is not None
    assert priority(it("", tag="select")) is None


def test_priority_order_and_word_boundaries():
    assert priority(it("Connect")) == PRIORITY.index("connect")
    assert priority(it("Turn ON protection")) < priority(it("Settings"))
    assert priority(it("Online status")) == len(PRIORITY) + 1           # "on" must not match inside "online"
    assert priority(it("Auto mode", role="switch")) == len(PRIORITY)
    assert priority(it("Connect")) < priority(it("Save"))


def test_login_gate():
    gate = {"items": [it("Log in"), it("Sign up"), it("France")], "password_inputs": 0}
    assert login_gate(gate) is True
    vpn = {"items": [it("Connect"), it("Log in")], "password_inputs": 0}
    assert login_gate(vpn) is False                                     # something to switch on without an account
    form = {"items": [it("Next")], "password_inputs": 1}
    assert login_gate(form) is False                                    # "next" is a priority control
    assert login_gate({"items": [it("Submit")], "password_inputs": 1}) is True
    assert login_gate({"items": [it("Settings")], "password_inputs": 0}) is False


def test_ext_pages_from_manifest():
    assert ext_pages({"action": {"default_popup": "/ui/popup.html"}, "options_ui": {"page": "opt.html"}}) == \
        [("popup", "ui/popup.html"), ("options", "opt.html")]
    assert ext_pages({"browser_action": {"default_popup": "p.html"}, "options_page": "p.html"}) == [("popup", "p.html")]
    assert ext_pages({}) == [] and ext_pages({"action": {}}) == []


def test_state_hash_changes_with_state():
    a = {"items": [it("Connect")], "title": "x", "textLen": 10}
    b = {"items": [it("Disconnect")], "title": "x", "textLen": 10}
    assert state_hash(a) != state_hash(b) and state_hash(a) == state_hash(dict(a))


# ---------------- split
def _run():
    ev = {"probe_t0": 5000, "network_requests": [{"url": "a", "ts": 1000}, {"url": "b", "ts": 5100}, {"url": "c", "ts": 9000}],
          "tabs_v3": [{"created_ts": 4000}, {"created_ts": 5200}],
          "target_page_probe": [{"host": "x"}, {"host": "y"}], "errors": ["e1"],
          "honeypot_exfil": True, "honeypot_exfil_details": [{"ts": 6000, "markers": ["HONEYPOT"]}],
          "extension_storage": {"honeypot_found": True}, "manifest": {"name": "n"}}
    ev["_offsets"] = {"target_page_probe": 1, "errors": 1, "network_requests": 1, "tabs_v3": 1, "honeypot_exfil_details": 0}
    ev["_probe"] = {"stimuli": [{"stimulus_id": "s1", "ts": 5000, "ts_end": 5050}]}
    ev["_pre_storage"] = ({"honeypot_found": False}, {"uuid_tokens": []})
    return ev


def test_split_moves_everything_after_the_probe_start():
    pre, post = split(_run())
    assert [r["url"] for r in pre["network_requests"]] == ["a"]
    assert [r["url"] for r in post["network_requests"]] == ["b", "c"]
    assert len(pre["tabs_v3"]) == 1 and len(post["tabs_v3"]) == 1
    assert pre["target_page_probe"] == [{"host": "x"}] and post["target_page_probe"] == [{"host": "y"}]   # no ts: by position
    assert pre["errors"] == ["e1"]
    assert pre["manifest"] == {"name": "n"}


def test_split_storage_and_honeypot():
    pre, post = split(_run())
    assert pre["honeypot_exfil"] is False and pre["honeypot_exfil_details"] == []      # the hit came after the probe start
    assert pre["extension_storage"] == {"honeypot_found": False} and pre["honeypot_stored"] is False
    assert post["extension_storage"] == {"honeypot_found": True}
    assert "_probe" not in pre and "probe_t0" not in pre


def test_split_without_probe_keeps_everything():
    ev = {"network_requests": [{"ts": 1}], "errors": ["x"]}
    pre, post = split(ev)
    assert pre["network_requests"] == [{"ts": 1}] and "network_requests" not in post


def test_offsets():
    assert offsets({"a": [1, 2], "b": {}, "_c": [1]}) == {"a": 2}


# ---------------- causal tags: by origin (frame / tab / initiator chain), not by time
EXT = "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
CLICK = 10_000


def _causal_run(net=(), pri=(), tabs=(), api=(), ui_requests=(), ui_tabs=None):
    ev = {"probe_t0": 5000, "network_requests": list(net), "page_request_initiators": list(pri), "tabs_v3": list(tabs),
          "api_calls": list(api), "_offsets": {}}
    ev["_probe"] = {"stimuli": [{"stimulus_id": "s1", "ts": CLICK, "ts_end": CLICK + 1200}],
                    "ui": {"tabs": ui_tabs if ui_tabs is not None else [{"tab": 0, "why": "explored", "urls": [EXT + "/popup.html"]}],
                           "requests": list(ui_requests)}}
    return split(ev)[1]


def sw_req(url, ts):
    return {"origin": "service_worker", "source": "cdp_sw", "url": url, "ts": ts}


def test_sw_request_one_second_after_a_click_is_kept():
    """A service-worker request 1 s after a click, with no initiator chain to the click: post_probe (kept)."""
    post = _causal_run(net=[sw_req("https://c2.example/beacon", CLICK + 1000)])
    r = post["network_requests"][0]
    assert (r["cause_class"], r["cause_reason"], r["stimulus_id"]) == ("post_probe", "sw_unlinked", None)


def test_async_popup_request_three_seconds_after_a_click_is_dropped():
    """A request the popup itself sends 3 s after the click (setTimeout / promise): user_initiated (dropped)."""
    late = CLICK + 3000
    post = _causal_run(net=[{"origin": "page", "url": "https://api.vendor.example/login", "ts": late + 5}],
                       pri=[{"url": "https://api.vendor.example/login", "ts": late, "frame_target_url": "about:blank",
                             "attributed": "extension"}],
                       ui_requests=[{"url": "https://api.vendor.example/login", "ts": late, "tab": 0}])
    assert (post["network_requests"][0]["cause_class"], post["network_requests"][0]["cause_reason"]) == ("user_initiated", "ui_tab")
    pr = post["page_request_initiators"][0]
    assert (pr["cause_class"], pr["cause_reason"], pr["stimulus_id"]) == ("user_initiated", "ui_tab", "s1")


def test_sw_request_linked_to_the_popup_message_is_dropped_even_late():
    """SW fetch whose JS stack goes through onMessage for the popup's message (guard record): user_initiated."""
    url = "https://api.vendor.example/connect"
    post = _causal_run(net=[sw_req(url, CLICK + 3050)],
                       api=[{"api": "xp.caused_by_ui", "kind": "fetch", "url": url, "ts": CLICK + 3000}])
    r = post["network_requests"][0]
    assert (r["cause_class"], r["cause_reason"]) == ("user_initiated", "sw_message_from_ui")
    assert post["api_calls"][0]["cause_class"] == "harness_record"
    assert post["probe"]["stimuli"][0]["requests_caused"] == 1


def test_same_url_later_without_link_is_kept():
    url = "https://api.vendor.example/connect"
    post = _causal_run(net=[sw_req(url, CLICK + 60_000)],
                       api=[{"api": "xp.caused_by_ui", "kind": "fetch", "url": url, "ts": CLICK}])
    assert post["network_requests"][0]["cause_class"] == "post_probe"


def test_extension_frame_and_typed_input():
    post = _causal_run(pri=[{"url": "https://x.example/a", "ts": 20_000, "frame_target_url": EXT + "/options.html"}],
                       net=[sw_req("https://c2.example/u?p=HONEYPOT-PROBE-PW", 30_000)])
    assert post["page_request_initiators"][0]["cause_reason"] == "extension_frame"
    assert (post["network_requests"][0]["cause_class"], post["network_requests"][0]["cause_reason"]) == ("user_initiated", "typed_input")


def test_tabs_by_opener_and_by_linked_sw_call():
    ui_tabs = [{"tab": 0, "why": "explored", "urls": [EXT + "/popup.html"]},
               {"tab": 1, "why": "opened_by_ui", "urls": ["about:blank", "https://vendor.example/welcome"]},
               {"tab": 2, "why": "other", "urls": ["https://vendor.example/pricing"]},
               {"tab": 3, "why": "other", "urls": ["https://ads.example/x"]}]
    tabs = [{"initial_url": "https://vendor.example/welcome", "created_ts": 11_000},
            {"initial_url": "https://vendor.example/pricing", "created_ts": 12_000},
            {"initial_url": "https://ads.example/x", "created_ts": 13_000}]
    api = [{"api": "xp.caused_by_ui", "kind": "tabs.create", "url": "https://vendor.example/pricing", "ts": 11_900}]
    post = _causal_run(tabs=tabs, api=api, ui_tabs=ui_tabs)
    got = [(t["cause_class"], t["cause_reason"]) for t in post["tabs_v3"]]
    assert got == [("user_initiated", "ui_tab"), ("user_initiated", "ui_tab"), ("post_probe", None)]


# ---------------- api_calls: arrival order, harness records out of events.json
def test_api_calls_replays_and_harness_records_leave_events_json():
    tab = {"api": "tabs.create", "args": [{"url": "https://v.example/welcome"}], "ts": 1000}
    mon = {"api": "eval", "preview": "async () => { if (!(self.chrome && chrome.proxy)) return {no_api: true}; ...", "ts": 2000}
    guard = {"api": "proxy.settings.set", "faked": True, "ts": 2500}
    dnr = {"api": "declarativeNetRequest.updateSessionRules", "args": "{}", "ts": 2600}
    own_eval = {"api": "eval", "preview": "var x = atob(payload)", "ts": 2700}
    replay = dict(tab)                                   # replayed after the probe start, original timestamp
    ev = {"probe_t0": 5000, "api_calls": [tab, mon, guard, dnr, own_eval, replay],
          "sw_tab_calls": [{"api": "tabs.create", "url": "https://v.example/welcome", "ts": 1000}] * 2,
          "_offsets": {"api_calls": 5, "sw_tab_calls": 1}, "_probe": {"stimuli": []}}
    pre, post = split(ev)
    assert pre["api_calls"] == [tab, own_eval]                       # what the v3 sensor recorded from the extension
    assert post["api_calls_harness_pre"] == [mon, guard, dnr]
    assert [(a["api"], a["cause_class"], a["cause_reason"]) for a in post["api_calls"]] == [("tabs.create", "harness_record", "replay")]
    assert len(pre["sw_tab_calls"]) == 1 and post["sw_tab_calls"][0]["cause_reason"] == "replay"
