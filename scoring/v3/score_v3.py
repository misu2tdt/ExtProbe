"""score_v3.py -- Tier-2 scoring of v3 traces (rules and weights: eval/v3/SCORING_v3.md, fixed
before the dev run). worker/risk.py is not modified: its host rules and v2 detectors are
imported and applied to filtered copies of the trace.

  py eval/v3/score_v3.py --traces eval/v3/smoke/traces [--samples samples] [--out scores.json]

`--samples`: root searched for each trace's package (meta.json source_filename), used only to
drop persistent-identifier candidates that are hard-coded in the package.
"""
import argparse
import base64
import binascii
import json
import re
import sys
import zipfile
from collections import defaultdict
from pathlib import Path
from urllib.parse import unquote, urlparse

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "worker"))
sys.path.insert(1, str(REPO / "sandbox"))
import risk  # noqa: E402
from honeypot import find_honeypot_any  # noqa: E402

# ---- weights (SCORING_v3.md; change only with a commit that says why) ----
W = {
    "credential_exfil": 80,
    "history_exfil": 50,
    "affiliate_hijack": 40,
    "undeclared_user_data": 40,
    "local_harvest": 30,
    "undeclared_base": 15, "undeclared_per_extra": 5, "undeclared_cap": 20,
    "unsolicited_tab": 15,
    "script_injection": 15,
    "page_api_hooking": 15,
    "beaconing_base": 5, "beaconing_undeclared_bonus": 5,
    "causes_page_hang": 10,
}
FLAG_THRESHOLD = 40
MIN_TITLE_LEN = 8
B64_MIN_LEN = 16
UUID4_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.I)
_B64_RE = re.compile(r"[A-Za-z0-9+/_-]{%d,}={0,2}" % B64_MIN_LEN)
# second-level labels under which the registrable domain takes three labels (short fixed list;
# no public-suffix library in the image or on the host)
_SLD2 = {"co", "com", "net", "org", "gov", "edu", "ac", "ne", "or", "go"}


def host_of(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def registrable(host):
    host = (host or "").lower().rstrip(".")
    if not host or re.fullmatch(r"[\d.]+", host) or "." not in host:
        return host
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in _SLD2 and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


# ---- extension-initiated requests ----
def is_sw_request(r):
    """A service-worker request recorded by the CDP SW session. network_requests also holds
    Playwright records labelled origin="service_worker" by the v2 fallback when the request has
    no frame yet; in v3 those are navigations of newly opened tabs (SCORING_v3.md, amendment 1).
    Traces without the `source` field: CDP types are capitalised ("Fetch"), Playwright ones are not."""
    if r.get("origin") != "service_worker":
        return False
    if r.get("source"):
        return r["source"] == "cdp_sw"
    rt = r.get("resource_type") or ""
    return not r.get("frame_unavailable") and rt[:1].isupper()


def ext_requests(ev):
    """SW requests + CDP page requests whose outermost caller is the extension (T1-1)."""
    out = []
    for r in ev.get("network_requests", []) or []:
        if is_sw_request(r) and r.get("url", "").startswith("http"):
            out.append({"url": r["url"], "method": r.get("method"), "body": r.get("post_data") or "",
                        "headers": r.get("headers_of_interest") or {}, "ts": r.get("ts"),
                        "phase_ts": r.get("phase_ts"), "t": r.get("t"), "via": "service_worker"})
    for r in ev.get("page_request_initiators", []) or []:
        if r.get("attributed") == "extension" and r.get("url", "").startswith("http"):
            out.append({"url": r["url"], "method": r.get("method"), "body": r.get("post_data") or "",
                        "headers": {}, "ts": r.get("ts"), "phase_ts": r.get("phase_ts"), "t": None,
                        "via": "page_extension", "ext_frame": (r.get("ext_frames") or [None])[0]})
    for r in out:
        r["host"] = host_of(r["url"])
    return out


# ---- decoding of a request surface (T2-2: plain, URL-decoded x1 / x2, base64 / base64url) ----
def _b64_runs(text):
    out = []
    for m in _B64_RE.finditer(text):
        s = m.group(0)
        for dec in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                t = dec(s + "=" * (-len(s) % 4)).decode("utf-8", "ignore")
            except (binascii.Error, ValueError):
                continue
            if t:
                out.append(t)
    return " ".join(out)


def surface_variants(text):
    u1 = unquote(text)
    u2 = unquote(u1)
    out = [("plain", text), ("url1", u1), ("url2", u2)]
    for name, t in (("base64", text), ("url1+base64", u1)):
        d = _b64_runs(t)
        if d:
            out.append((name, d))
            dd = unquote(d)
            if dd != d:
                out.append((name + "+url", dd))
    return [(n, t.lower().replace("\\/", "/")) for n, t in out]


# ---- visited pages ----
def visited_needles(ev):
    """URLs (host + non-root path) and titles of pages the harness opened."""
    needles = {}
    for t in ev.get("tabs_v3", []) or []:
        if t.get("opened_by") != "harness":
            continue
        urls = [t.get("initial_url")] + [n.get("url") for n in t.get("navigations") or []]
        for u in urls:
            if not u or not u.startswith("http"):
                continue
            pu = urlparse(u)
            path = (pu.path or "").rstrip("/")
            if not path:
                continue                                      # bare domain: not history (SCORING_v3.md)
            needle = (pu.netloc + path).lower()
            needles[needle] = {"kind": "visited_url", "page_domain": registrable(pu.hostname), "value": u[:200]}
        for ti in t.get("titles") or []:
            title = (ti.get("title") or "").strip()
            if len(title) >= MIN_TITLE_LEN and ti.get("url", "").startswith("http"):
                needles[title.lower()] = {"kind": "title", "page_domain": registrable(host_of(ti["url"])),
                                          "value": title[:120]}
    return needles


def history_hits(reqs, needles):
    hits = []
    for r in reqs:
        dest = registrable(r["host"])
        text = r["url"] + " " + r["body"]
        variants = surface_variants(text)
        for needle, meta in needles.items():
            if meta["page_domain"] == dest:
                continue
            for enc, t in variants:
                if needle in t:
                    hits.append({"host": r["host"], "via": r["via"], "kind": meta["kind"], "value": meta["value"],
                                 "encoding": enc, "ts": r["ts"]})
                    break
    return hits


# ---- persistent identifiers ----
def package_text(crx_path):
    """Lower-cased text of every file in the package (crx = zip with a prefix header)."""
    try:
        with zipfile.ZipFile(crx_path) as z:
            return " ".join(z.read(n).decode("utf-8", "ignore") for n in z.namelist()
                            if not n.endswith("/")).lower()
    except (zipfile.BadZipFile, OSError):
        return None


def persistent_ids(reqs, pkg_text=None):
    """UUID v4 sent to the same host in >= 2 phases, not hard-coded in the package. (UUIDs kept in
    the extension's storage are recorded in extension_storage_v3 but not used: SCORING_v3.md.)"""
    seen = defaultdict(set)                                   # (host, uuid) -> phases
    for r in reqs:
        for m in UUID4_RE.finditer(r["url"] + " " + r["body"]):
            seen[(r["host"], m.group(0).lower())].add(r.get("phase_ts"))
    out = defaultdict(list)
    for (host, tok), phases in seen.items():
        phases.discard(None)
        if len(phases) >= 2 and not (pkg_text and tok in pkg_text):
            out[host].append(tok)
    return out


# ---- signals ----
def _own_ids(ev):
    ids = risk._own_extension_ids(ev)
    if (ev.get("v3_load") or {}).get("id"):
        ids.add(ev["v3_load"]["id"])
    return ids


def norm_url(u, ext_id=None):
    """Comparable form of a tab URL: a relative URL (chrome.tabs.create({url: "welcome.html"})) is
    resolved against chrome-extension://<id>/; an empty path becomes "/"; scheme and host lower-cased."""
    if not u:
        return ""
    if "://" not in u and ext_id:
        u = f"chrome-extension://{ext_id}/" + u.lstrip("/")
    try:
        p = urlparse(u)
    except ValueError:
        return u
    return f"{p.scheme.lower()}://{p.netloc.lower()}{p.path or '/'}" + (f"?{p.query}" if p.query else "")


def link_sw_call(tab, calls, ext_id=None, lookback_ms=30000):
    """(api, ts) of the recorded SW call that opened this tab, else (None, None). Matched on the
    normalised first / initial URL, call made at most lookback_ms before the tab was reported."""
    targets = {norm_url(tab.get(k), ext_id) for k in ("first_url", "initial_url") if tab.get(k)}
    opened = tab.get("opened_ts")
    for c in calls or []:
        cu = norm_url(c.get("url"), ext_id)
        if not cu or c.get("ts") is None or opened is None:
            continue
        if not (opened - lookback_ms <= c["ts"] <= opened):
            continue
        if cu in targets or any(t.startswith(cu) for t in targets):
            return c.get("api"), c["ts"]
    return None, None


def detect_tabs(ev):
    own = _own_ids(ev)
    ext_id = (ev.get("v3_load") or {}).get("id")
    tabs = []
    for t in ev.get("tabs_v3", []) or []:
        if not t.get("extension_opened"):
            continue
        first, final = t.get("first_url") or t.get("initial_url") or "", t.get("final_url") or ""
        urls = [first] + [u for r in t.get("redirects") or [] for u in r.get("redirect_chain") or []] + [final]
        urls = [u for u in urls if u]
        if all(u in ("", "about:blank") for u in urls):
            continue
        if any(u.startswith(f"chrome-extension://{i}/") for i in own for u in (first, final)):
            continue
        chain = []                                            # CDP and Playwright can both report a hop
        for u in urls:
            if u not in chain:
                chain.append(u)
        doms = []
        for u in chain:
            d = registrable(host_of(u))
            if d and d not in doms:
                doms.append(d)
        tabs.append({"first_url": first[:300], "final_url": final[:300], "chain": [u[:300] for u in chain],
                     "registrable_domains": doms, "n_registrable_domains": len(doms),
                     "titles": [x.get("title") for x in t.get("titles") or []][:5],
                     "t_since_install": t.get("t_since_install"),
                     "opened_by_sw_call": t.get("opened_by_sw_call") or link_sw_call(t, ev.get("sw_tab_calls"), ext_id)[0],
                     "phase_ts": t.get("phase_ts")})
    return tabs


def detect_injection(ev):
    view = dict(ev)
    view["dom_activity"] = [d for d in ev.get("dom_activity", []) or [] if d.get("node_attributed") == "extension"]
    return risk.detect_script_injection(view)


def detect_hooks(ev):
    out = []
    for h in ev.get("page_api_hooks", []) or []:
        if h.get("replaced"):
            out.append({"page_url": (h.get("page_url") or "")[:200], "phase": h.get("phase"), "replaced": h["replaced"]})
    return out


def detect_affiliate(ev):
    view = dict(ev)
    view["startup"] = dict(ev.get("startup") or {}, profile="v2")
    res = risk.detect_affiliate_hijack(view)
    kept = []
    for h in res.get("hits", []):
        host = host_of(h["url"])
        is_amazon = bool(re.search(r"(^|\.)amazon\.[a-z.]+$", host))
        if h["kind"] != "redirect_domain" and not is_amazon and "tag" in h["params"]:
            params = [p for p in h["params"] if p != "tag"]
            if not params:
                continue
            h = dict(h, params=params)
        kept.append(h)
    return kept


def detect_beacons(ev, reqs_hosts_undeclared):
    view = dict(ev)
    view["startup"] = dict(ev.get("startup") or {}, profile=None)
    keep = []
    for r in ev.get("network_requests", []) or []:
        if is_sw_request(r) or r.get("initiator_ext") is True:
            keep.append(r)
    view["network_requests"] = keep
    res = risk.detect_beaconing(view)
    for b in res["beacons"]:
        b["host_undeclared"] = b["host"] in reqs_hosts_undeclared
    res["has_undeclared_beacon"] = any(b["host_undeclared"] for b in res["beacons"])
    return res


def score_trace(ev, pkg_text=None):
    reqs = ext_requests(ev)
    declared = risk._manifest_declared_hosts(ev.get("manifest", {}) or {})

    def undeclared(h):
        return (risk._is_real_domain(h) and not risk._is_harness_host(h) and not risk._is_declared_host(h, declared)
                and not risk._is_known_infra_host(h))

    # T2-7
    cred = []
    for r in reqs:
        hits, enc = find_honeypot_any(r["url"] + " " + r["body"] + " " + json.dumps(r["headers"]))
        if hits:
            cred.append({"host": r["host"], "via": r["via"], "markers": hits, "encoding": enc, "ts": r["ts"]})
    # T2-2
    hist = history_hits(reqs, visited_needles(ev))
    # T2-3
    pids = persistent_ids(reqs, pkg_text)
    und = {}
    for r in reqs:
        if undeclared(r["host"]):
            und.setdefault(r["host"], {"host": r["host"], "requests": 0, "via": set(), "user_data": set()})
            und[r["host"]]["requests"] += 1
            und[r["host"]]["via"].add(r["via"])
    for h in hist:
        if h["host"] in und:
            und[h["host"]]["user_data"].add(h["kind"])
    for c in cred:
        if c["host"] in und:
            und[c["host"]]["user_data"].add("honeypot")
    for host, toks in pids.items():
        if host in und:
            und[host]["user_data"].add("persistent_id")
            und[host]["persistent_ids"] = toks[:3]
    und_list = sorted(({**v, "via": sorted(v["via"]), "user_data": sorted(v["user_data"])} for v in und.values()),
                      key=lambda x: (not x["user_data"], x["host"]))
    und_data = [u for u in und_list if u["user_data"]]

    tabs = detect_tabs(ev)
    inj = detect_injection(ev)
    hooks = detect_hooks(ev)
    aff = detect_affiliate(ev)
    harvest = risk.detect_local_harvest(ev)
    beac = detect_beacons(ev, set(und))
    hang = (ev.get("page_hang_count") or 0) > 0

    sig = {}

    def put(name, fired, weight, details):
        sig[name] = {"fired": bool(fired), "weight": weight if fired else 0, "details": details}

    put("credential_exfil", cred, W["credential_exfil"], cred[:10])
    put("history_exfil", hist, W["history_exfil"], hist[:10])
    put("affiliate_hijack", aff, W["affiliate_hijack"], aff[:10])
    put("local_harvest", harvest["has_harvest"], W["local_harvest"], harvest["harvested_markers"])
    if und_data:
        put("undeclared_domain_contact", True, W["undeclared_user_data"], und_list[:15])
        sig["undeclared_domain_contact"]["class"] = "heavy"
    else:
        w = min(W["undeclared_base"] + W["undeclared_per_extra"] * (len(und_list) - 1), W["undeclared_cap"]) if und_list else 0
        put("undeclared_domain_contact", und_list, w, und_list[:15])
        sig["undeclared_domain_contact"]["class"] = "light"
    put("unsolicited_tab", tabs, W["unsolicited_tab"], tabs[:10])
    put("script_injection", inj["has_injection"], W["script_injection"], inj["injected_nodes"][:10])
    put("page_api_hooking", hooks, W["page_api_hooking"], hooks[:10])
    bw = W["beaconing_base"] + (W["beaconing_undeclared_bonus"] if beac["has_undeclared_beacon"] else 0)
    put("beaconing", beac["has_beaconing"], bw, beac["beacons"][:5])
    put("causes_page_hang", hang, W["causes_page_hang"], ev.get("page_hang_count", 0))

    score = min(100, sum(s["weight"] for s in sig.values()))
    level = risk._level_of(score)
    static_report = risk.build_behavioral_report(dict(ev, startup=dict(ev.get("startup") or {}, profile="v2")))
    return {
        "score": score, "level": level, "flag": score >= FLAG_THRESHOLD,
        "fired": [k for k, s in sig.items() if s["fired"]],
        "signals": sig,
        "static_display": {"static_score": risk._static_score(static_report), **static_report["static"]},
        "ext_request_count": len(reqs),
    }


def find_package(meta, samples_root):
    name = (meta or {}).get("source_filename")
    if not name or not samples_root:
        return None
    for p in Path(samples_root).rglob(name):
        return p
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", required=True)
    ap.add_argument("--samples", default=None)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    out = {}
    for d in sorted(Path(a.traces).iterdir()):
        evp = d / "output" / "events.json"
        if not evp.exists():
            continue
        ev = json.loads(evp.read_text(encoding="utf-8"))
        meta = json.loads((d / "meta.json").read_text(encoding="utf-8")) if (d / "meta.json").exists() else {}
        pkg = find_package(meta, a.samples)
        res = score_trace(ev, package_text(pkg) if pkg else None)
        out[d.name] = res
        print(f"{d.name:34s} {res['score']:3d} {res['level']:8s} {','.join(res['fired'])}")
    if a.out:
        Path(a.out).write_text(json.dumps(out, indent=1, ensure_ascii=False, default=str), encoding="utf-8")


if __name__ == "__main__":
    main()
