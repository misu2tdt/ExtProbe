"""Unit tests of the v3 post-processing and helpers (synthetic traces; no browser)."""
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sandbox_v3"))
from v3_common import MAX_BODY_LEN_V3, attribute, body_fields  # noqa: E402
from v3_post import (assign_phase_ts, finalize_sw_tab_calls, finalize_tabs, join_initiators,  # noqa: E402
                     phase_of, post_process)


def _phases():
    return [{"name": "load", "ts_start": 1000.0, "ts_end": 4000.0},
            {"name": "honeypot_pages", "ts_start": 4000.0, "ts_end": 18000.0},
            {"name": "target_matched", "ts_start": 18000.0, "ts_end": 40000.0}]


def test_phase_of_boundaries():
    b = sorted((p["ts_start"], p["ts_end"], p["name"]) for p in _phases())
    assert phase_of(500, b) == "pre_load"
    assert phase_of(1000, b) == "load"
    assert phase_of(3999.9, b) == "load"
    assert phase_of(4000, b) == "honeypot_pages"
    assert phase_of(40001, b) == "post_run"


def test_assign_phase_ts_keeps_v2_phase():
    ev = {"phases": _phases(), "network_requests": [{"ts": 3500, "phase": "honeypot_pages"}],
          "tabs_v3": [{"opened_ts": 5000, "created_ts": 3000}]}
    assign_phase_ts(ev)
    assert ev["network_requests"][0]["phase_ts"] == "load"
    assert ev["network_requests"][0]["phase"] == "honeypot_pages"      # v2 field untouched
    assert ev["tabs_v3"][0]["phase_ts"] == "load"                      # creation time, not report time


def test_attribute_sync_async_and_page():
    # async: a page-library frame on top, the content script as the outermost (async) caller
    ext = {"type": "script", "stack": {"callFrames": [{"url": "https://page/x.js"}],
                                       "parent": {"callFrames": [{"url": "chrome-extension://abc/content.js"}]}}}
    assert attribute(ext) == ("extension", ["chrome-extension://abc/content.js"])
    # the page's own fetch passing through a main-world wrapper the extension installed
    hooked = {"type": "script", "stack": {"callFrames": [{"url": "chrome-extension://abc/inject.js"},
                                                         {"url": "https://page/"}]}}
    assert attribute(hooked) == ("page_via_extension_hook", ["chrome-extension://abc/inject.js"])
    cs = {"type": "script", "stack": {"callFrames": [{"url": "chrome-extension://abc/content.js"}]}}
    assert attribute(cs)[0] == "extension"
    assert attribute({"type": "script", "stack": {"callFrames": [{"url": "https://page/"}]}})[0] == "page"
    assert attribute({"type": "parser", "url": "https://page/"})[0] == "page"
    assert attribute({"type": "other"})[0] == "unknown"


def test_join_initiators_nearest_and_once():
    ev = {"network_requests": [{"origin": "page", "url": "https://a/x", "method": "GET", "ts": 1000},
                               {"origin": "page", "url": "https://a/x", "method": "GET", "ts": 1500},
                               {"origin": "page", "url": "https://b/y", "method": "GET", "ts": 9000},
                               {"origin": "service_worker", "url": "https://c/z", "method": "POST", "ts": 1}],
          "page_request_initiators": [{"url": "https://a/x", "method": "GET", "ts": 1490, "attributed": "page"},
                                      {"url": "https://a/x", "method": "GET", "ts": 1010, "attributed": "extension",
                                       "ext_frames": ["chrome-extension://abc/cs.js"]},
                                      {"url": "https://b/y", "method": "GET", "ts": 2000, "attributed": "extension"}]}
    assert join_initiators(ev) == 2
    r = ev["network_requests"]
    assert r[0]["initiator_ext"] is True and r[0]["initiator_ext_frame"] == "chrome-extension://abc/cs.js"
    assert r[1]["initiator_ext"] is False
    assert r[2]["initiator_ext"] is None                                # 7 s away: outside the window
    assert "initiator_ext" not in r[3]                                  # SW requests are not joined


def test_finalize_tabs_cdp_redirect_chain():
    ev = {"tabs_v3": [{"initial_url": "https://land/x", "opened_ts": 20000, "navigations": [], "_nav_requests": []}],
          "page_request_initiators": [
              {"resource_type": "Document", "request_id": "R1", "url": "https://c2/install", "ts": 3000},
              {"resource_type": "Document", "request_id": "R1", "url": "https://land/x", "ts": 3100,
               "redirect_from": "https://c2/install", "redirect_status": 301}]}
    finalize_tabs(ev)
    t = ev["tabs_v3"][0]
    assert t["first_url"] == "https://c2/install"
    assert t["created_ts"] == 3000
    assert t["redirects"][0]["redirect_chain"] == ["https://c2/install"]
    assert t["final_url"] == "https://land/x"


def test_finalize_tabs_uses_sw_call_time():
    ev = {"sw_tab_calls": [{"api": "tabs.create", "url": "https://c2/install?x=1", "ts": 2500}],
          "tabs_v3": [{"initial_url": "https://land/x", "opened_ts": 20000, "navigations": [], "_nav_requests": []}],
          "page_request_initiators": [
              {"resource_type": "Document", "request_id": "R1", "url": "https://c2/install?x=1", "ts": 4100},
              {"resource_type": "Document", "request_id": "R1", "url": "https://land/x", "ts": 4200,
               "redirect_from": "https://c2/install?x=1"}]}
    finalize_tabs(ev)
    t = ev["tabs_v3"][0]
    assert t["created_ts"] == 2500 and t["opened_by_sw_call"] == "tabs.create"


def test_body_fields_truncation_and_hash():
    body = "a" * (MAX_BODY_LEN_V3 + 10)
    f = body_fields(body)
    assert len(f["post_data"]) == MAX_BODY_LEN_V3 and f["post_data_len"] == MAX_BODY_LEN_V3 + 10
    assert f["post_data_truncated"] is True
    assert f["post_data_sha256"] == hashlib.sha256(body.encode()).hexdigest()
    assert body_fields(None) == {} and body_fields(b"") == {}
    assert body_fields(b"\xff\x00")["post_data_bytes"] == 2


def test_sw_tab_calls_dedup_and_install_offset():
    ev = {"t0_wall": 100.0, "sw_tab_calls": [{"api": "tabs.create", "url": "u", "ts": 101500.0},
                                             {"api": "tabs.create", "url": "u", "ts": 101500.0}]}
    finalize_sw_tab_calls(ev)
    assert len(ev["sw_tab_calls"]) == 1 and ev["sw_tab_calls"][0]["t_since_install"] == 1.5


def test_post_process_runs_on_minimal_trace():
    ev = {"phases": _phases(), "network_requests": [], "page_request_initiators": [], "tabs_v3": []}
    post_process(ev)
    assert ev["v3_post"] == {"initiator_joined": 0, "nodes_joined": 0, "events_with_phase_ts": 0}
