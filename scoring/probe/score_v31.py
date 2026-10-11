"""score_v31.py -- score a v3.1-probe run with the UNCHANGED score_v3 (eval/v3_1_probe/DESIGN.md §4).

No detector is added and score_v3.py is not modified. A filtered view is built from events.json (the v3 part of
the run) and events_probe.json (everything from the probe start on):
  kept     every post-probe item that is not a direct result of a click (cause_class != user_initiated),
           i.e. behaviour that continues after the extension was switched on, and the re-run of target_matched
  dropped  items with cause_class == user_initiated (a tab or request the click itself asked for);
           requests issued by the extension's own popup / options page (its UI talking to its backend)
  cleaned  the PROBE-tagged form values the explorer typed (plain, URL-encoded, base64) are replaced in request
           URLs / bodies, and storage hits that contain them are dropped, so they cannot raise
           credential_exfil / local_harvest
Then score_v3.score_trace(view) as it is. With an empty probe file the view is events.json and the score is
exactly score_v3's (unit test).

Probe-only facts are reported next to the score, not added to it: proxy configured, DNR rules changed,
storage changed, new extension hosts, login gate, proxy guard (set calls intercepted, policy in force,
proxy_unwrapped_set).

  py eval/v3_1_probe/score_v31.py --traces <dir with <name>/output/{events,events_probe}.json> [--samples <crx dir>]
"""
import argparse
import base64
import copy
import json
import sys
from pathlib import Path
from urllib.parse import quote, quote_plus

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(REPO / "scoring" / "v3"))
sys.path.insert(1, str(REPO / "scoring"))             # risk.py
sys.path.insert(2, str(REPO / "sandbox" / "base"))         # honeypot.py
sys.path.insert(3, str(REPO / "sandbox" / "probe"))        # v31_policy.py
import score_v3 as S  # noqa: E402
from v31_policy import PROBE_TOKENS  # noqa: E402

REQUEST_LISTS = ("network_requests", "page_request_initiators")


def _variants(tok):
    out = {tok, quote(tok), quote_plus(tok), quote(quote(tok, safe=""), safe="")}
    for enc in (base64.b64encode, base64.urlsafe_b64encode):
        b = enc(tok.encode()).decode()
        out |= {b, b.rstrip("=")}
    return sorted(out, key=len, reverse=True)


VARIANTS = [v for t in PROBE_TOKENS for v in _variants(t)]


def strip_probe_values(text):
    if not isinstance(text, str) or not text:
        return text, 0
    n = 0
    for v in VARIANTS:
        if v and v in text:
            n += text.count(v)
            text = text.replace(v, "XPROBEX")
    return text, n


def _ui_request(r):
    return (r.get("frame_target_url") or "").startswith("chrome-extension://")


def build_view(pre, post):
    """-> (view, stats). pre = events.json, post = events_probe.json (may be {})."""
    view = copy.deepcopy(pre)
    stats = {"dropped_user_initiated": 0, "dropped_ui_requests": 0, "probe_values_stripped": 0, "kept": 0,
             "storage_hits_dropped": 0}
    for k, items in (post or {}).items():
        if not isinstance(items, list) or k in ("probe_phases", "api_calls_harness_pre"):
            continue
        keep = []
        for it in items:
            if isinstance(it, dict) and it.get("cause_class") == "user_initiated":
                stats["dropped_user_initiated"] += 1
                continue
            if isinstance(it, dict) and it.get("cause_class") == "harness_record":
                stats["dropped_harness_records"] = stats.get("dropped_harness_records", 0) + 1
                continue
            if k == "page_request_initiators" and isinstance(it, dict) and _ui_request(it):
                stats["dropped_ui_requests"] += 1
                continue
            if k in REQUEST_LISTS and isinstance(it, dict):
                it = copy.copy(it)
                for f in ("url", "post_data"):
                    it[f], n = strip_probe_values(it.get(f))
                    stats["probe_values_stripped"] += n
            keep.append(it)
        stats["kept"] += len(keep)
        view[k] = list(view.get(k) or []) + keep
    st = (post or {}).get("extension_storage")
    if isinstance(st, dict):
        st = copy.deepcopy(st)
        hits = st.get("honeypot_hits") or []
        kept = [h for h in hits if not any(t.lower() in (h.get("snippet") or "").lower() for t in PROBE_TOKENS)]
        stats["storage_hits_dropped"] = len(hits) - len(kept)
        st["honeypot_hits"], st["honeypot_found"] = kept, bool(kept)
        view["extension_storage"] = st
    return view, stats


PROXY_MODES = ("fixed_servers", "pac_script")


def proxy_calls(post):
    """chrome.proxy.settings.set calls recorded by the guard after the probe start (service worker records are
    in the post-probe api_calls; page records in proxy_guard.page_calls, filtered by time)."""
    t0 = (post or {}).get("probe_t0")
    sw = [a for a in (post or {}).get("api_calls", []) if isinstance(a, dict) and a.get("api") == "proxy.settings.set"]
    pg = [a for a in ((post or {}).get("proxy_guard") or {}).get("page_calls", [])
          if a.get("api") == "proxy.settings.set" and t0 is not None and (a.get("ts") or 0) >= t0]
    # a record can arrive more than once (each new CDP session's Runtime.enable replays the worker's console)
    return list({(a.get("ts"), a.get("ctx"), a.get("args")): a for a in sw + pg}.values())


def probe_facts(pre, post):
    p = (post or {}).get("probe") or {}
    st = p.get("stimuli") or []
    guard = (post or {}).get("proxy_guard") or {}
    api = [a for a in (post or {}).get("api_calls", []) if isinstance(a, dict)] + \
          [a for a in guard.get("page_calls", []) if (post or {}).get("probe_t0") is not None and (a.get("ts") or 0) >= post["probe_t0"]]
    pcalls = proxy_calls(post)
    pre_hosts = {r["host"] for r in S.ext_requests(pre)}
    post_reqs = [r for r in (post or {}).get("network_requests", []) if S.is_sw_request(r)]
    post_reqs += [r for r in (post or {}).get("page_request_initiators", []) if r.get("attributed") == "extension" and not _ui_request(r)]
    new_hosts = {S.host_of(r["url"]) for r in post_reqs if (r.get("url") or "").startswith("http")} - pre_hosts - {""}
    return {
        "pages_declared": p.get("pages_declared", []),
        "pages_opened": sum(1 for x in p.get("pages", []) if x.get("opened")),
        "clicks": sum(1 for s in st if s.get("clicked")),
        "login_gate": bool(p.get("login_gate")),
        "proxy_set_calls": len(pcalls),
        "proxy_configured": any(a.get("mode") in PROXY_MODES for a in pcalls),
        "proxy_unwrapped_set": bool(guard.get("proxy_unwrapped_set")),
        "policy_in_force": guard.get("policy_in_force"),
        "dnr_changed": any((s.get("dnr_dynamic_delta") or 0) or (s.get("dnr_session_delta") or 0) for s in st)
                       or any(str(a.get("api", "")).startswith("declarativeNetRequest") for a in api),
        "storage_changed": any((s.get("storage_new_keys") or 0) >= 1 or (s.get("storage_changed_keys") or 0) >= 3 for s in st),
        "new_extension_hosts": len(new_hosts),
        "skipped_unlabeled": p.get("skipped_unlabeled", 0),
        "skipped_non_english": p.get("skipped_non_english", 0),
        "explore_s": p.get("explore_s"),
        "extra_s": p.get("extra_s"),
    }


def score_run(pre, post, pkg_text=None):
    v3 = S.score_trace(pre, pkg_text)
    view, stats = build_view(pre, post)
    v31 = S.score_trace(view, pkg_text)
    facts = probe_facts(pre, post)
    facts["yield"] = facts["proxy_configured"] or facts["dnr_changed"] or facts["new_extension_hosts"] > 0
    nb3, nb31 = _without(v3, "beaconing"), _without(v31, "beaconing")
    flag_change = v3["flag"] != v31["flag"]
    return {"v3_score": v3["score"], "v3_fired": v3["fired"], "v31_score": v31["score"], "v31_fired": v31["fired"],
            "flag_v3": v3["flag"], "flag_v31": v31["flag"], "view": stats, "probe": facts,
            # CRITERIA amendment 3: beaconing is unstable near its threshold (DESIGN §11)
            "v3_score_nobeacon": nb3, "v31_score_nobeacon": nb31,
            "flag_v3_nobeacon": nb3 >= S.FLAG_THRESHOLD, "flag_v31_nobeacon": nb31 >= S.FLAG_THRESHOLD,
            "flag_change_beacon_only": flag_change and (nb3 >= S.FLAG_THRESHOLD) == (nb31 >= S.FLAG_THRESHOLD)}


def _without(result, name):
    """score_v3's score with one detector's weight left out (same cap at 100)."""
    return min(100, sum(s["weight"] for k, s in result["signals"].items() if k != name))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", required=True)
    ap.add_argument("--samples", default=None, help="folder with <name>.crx (persistent-id package check)")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    res = {}
    for d in sorted(Path(a.traces).iterdir()):
        evp, prp = d / "output" / "events.json", d / "output" / "events_probe.json"
        if not evp.exists():
            continue
        pre = json.loads(evp.read_text(encoding="utf-8"))
        post = json.loads(prp.read_text(encoding="utf-8")) if prp.exists() else {}
        crx = Path(a.samples) / f"{d.name}.crx" if a.samples else None
        r = score_run(pre, post, S.package_text(crx) if crx and crx.exists() else None)
        res[d.name] = r
        print(f"{d.name}: v3 {r['v3_score']} -> v3.1 {r['v31_score']} | yield {r['probe']['yield']} | "
              f"login_gate {r['probe']['login_gate']} | proxy {r['probe']['proxy_configured']}")
    if a.out:
        Path(a.out).write_text(json.dumps(res, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
