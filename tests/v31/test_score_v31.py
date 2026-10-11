"""Unit tests of eval/v3_1_probe/score_v31.py (filtered view + unchanged score_v3), on synthetic traces."""
import base64
import copy
import sys
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "eval" / "v3_1_probe"))
sys.path.insert(0, str(ROOT / "eval" / "v3"))
import score_v31 as V  # noqa: E402
import score_v3 as S  # noqa: E402

EXT = "abcdefghijklmnopabcdefghijklmnop"
BANK = "http://localhost:8888/fake_bank.html"


def pre_trace():
    return {"schema_version": "1.1+v3", "manifest": {"name": "t", "permissions": [], "host_permissions": []},
            "startup": {"profile": "v3"}, "service_workers": [{"url": f"chrome-extension://{EXT}/bg.js"}],
            "network_requests": [{"origin": "service_worker", "source": "cdp_sw", "resource_type": "Fetch",
                                  "url": "https://api.vendor-x.com/ping", "method": "GET", "post_data": "", "ts": 10,
                                  "phase_ts": "load"}],
            "page_request_initiators": [], "dom_activity": [], "page_api_hooks": [], "new_tabs": [],
            "tabs_v3": [{"opened_by": "harness", "initial_url": BANK, "navigations": [{"url": BANK}],
                         "titles": [{"url": BANK, "title": "SecureBank - Login"}]}],
            "extension_storage": {"honeypot_hits": []}, "page_hang_count": 0}


def sw(url, body="", cause="post_probe", ts=9000):
    return {"origin": "service_worker", "source": "cdp_sw", "resource_type": "Fetch", "url": url, "method": "POST",
            "post_data": body, "ts": ts, "phase_ts": "post_run", "cause_class": cause, "stimulus_id": None}


def test_empty_probe_gives_the_score_v3_score():
    pre = pre_trace()
    for post in ({}, {"probe": {}, "network_requests": [], "tabs_v3": []}):
        r = V.score_run(pre, post)
        assert r["v31_score"] == r["v3_score"] == S.score_trace(pre)["score"]
        assert r["v31_fired"] == S.score_trace(pre)["fired"]


def test_user_initiated_tab_and_ui_requests_dropped():
    pre = pre_trace()
    post = {"tabs_v3": [{"opened_by": "other", "extension_opened": True, "first_url": "https://vendor.example/welcome",
                         "final_url": "https://vendor.example/welcome", "created_ts": 9000, "cause_class": "user_initiated"}],
            "page_request_initiators": [{"url": "https://api.other-y.com/login", "method": "POST", "attributed": "extension",
                                         "frame_target_url": f"chrome-extension://{EXT}/popup.html", "ts": 9500,
                                         "cause_class": "post_probe"}]}
    r = V.score_run(pre, post)
    assert "unsolicited_tab" not in r["v31_fired"]
    assert r["view"]["dropped_user_initiated"] == 1 and r["view"]["dropped_ui_requests"] == 1
    assert r["v31_score"] == r["v3_score"]


def test_probe_form_values_do_not_raise_credential_exfil():
    pre = pre_trace()
    for body in ("pw=HONEYPOT-PROBE-PW", "pw=" + quote("HONEYPOT-PROBE-PW"),
                 "d=" + base64.b64encode(b"HONEYPOT-PROBE-PW").decode()):
        r = V.score_run(pre, {"network_requests": [sw("https://c2.evil-z.com/x", body)]})
        assert "credential_exfil" not in r["v31_fired"], body
    real = V.score_run(pre, {"network_requests": [sw("https://c2.evil-z.com/x", "pw=HONEYPOT-PASSWORD")]})
    assert "credential_exfil" in real["v31_fired"]          # the harness's own honeypot still counts


def test_post_probe_behaviour_is_scored():
    pre = pre_trace()
    post = {"network_requests": [sw("https://collector.evil-z.com/c", "u=" + BANK)]}
    r = V.score_run(pre, post)
    assert "history_exfil" in r["v31_fired"] and r["v31_score"] > r["v3_score"]
    assert r["probe"]["new_extension_hosts"] == 1 and r["probe"]["yield"] is True


def test_storage_hits_with_probe_values_dropped():
    pre = pre_trace()
    post = {"extension_storage": {"honeypot_hits": [{"markers": ["HONEYPOT"], "snippet": "pw HONEYPOT-PROBE-PW"}],
                                  "honeypot_found": True}}
    r = V.score_run(pre, post)
    assert "local_harvest" not in r["v31_fired"] and r["view"]["storage_hits_dropped"] == 1


def test_view_does_not_change_inputs():
    pre, post = pre_trace(), {"network_requests": [sw("https://c2.evil-z.com/x", "pw=HONEYPOT-PROBE-PW")]}
    a, b = copy.deepcopy(pre), copy.deepcopy(post)
    V.score_run(pre, post)
    assert pre == a and post == b


def test_flag_change_only_by_beaconing_is_separated():
    def res(score_parts):
        sig = {k: {"fired": w > 0, "weight": w} for k, w in score_parts.items()}
        return {"signals": sig}
    assert V._without(res({"beaconing": 10, "unsolicited_tab": 15, "undeclared_domain_contact": 20}), "beaconing") == 35
    assert V._without(res({"beaconing": 10, "credential_exfil": 95}), "beaconing") == 95
