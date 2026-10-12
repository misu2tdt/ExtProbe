"""report_v3.py -- analyst-facing HTML report of v3 traces and their scores (score_v3.py).

  py report/report_v3.py --traces <dir with <name>/output/events.json> [--samples samples] [--out report_v3.html]

Reading order: score and level, what the extension did (one sentence per detector that fired), the signals that fired, the
evidence behind each (repeated records merged), diagnostics (collapsed), and the manifest risk (display only). The scoring is
score_v3's and is not touched here; this module only describes its result. The sentences and evidence are rebuilt from the
trace with score_v3's own helpers, so they are not cut off at the detail limits of score_trace().
The trace records the file of the script that started a request (initiator stack), not the line.
"""
import argparse
import html
import json
import re
from pathlib import Path

import score_v3 as S

CSS = """
:root{--bg:#fff;--fg:#1d1d1f;--mut:#6b7280;--line:#e5e7eb;--hi:#b91c1c;--md:#c2410c;--lo:#a16207;--ok:#15803d}
@media (prefers-color-scheme: dark){:root{--bg:#111827;--fg:#e5e7eb;--mut:#9ca3af;--line:#374151}}
body{background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif;margin:0 auto;max-width:1200px;padding:16px}
table{border-collapse:collapse;width:100%;margin:6px 0 14px}th,td{border-bottom:1px solid var(--line);padding:4px 6px;
text-align:left;vertical-align:top}th{color:var(--mut);font-weight:600}code,.u{font:12px ui-monospace,monospace;word-break:break-all}
.flagged{color:var(--hi);font-weight:700}.review{color:var(--md);font-weight:700}.none{color:var(--ok)}
details{border:1px solid var(--line);border-radius:6px;margin:8px 0;padding:6px 10px}summary{cursor:pointer;font-weight:600}
.mut{color:var(--mut)}h2{margin:22px 0 6px;font-size:16px}h3{margin:12px 0 4px;font-size:14px}ul.did{margin:6px 0;padding-left:20px}
"""

FLAG_AT, REVIEW_AT = 40, 15
LABELS = ("Flagged for review", "Review suggested", "No notable behavior observed")
NOTE = "The score prioritizes review; it is not a malware verdict."

NAMES = {
    "credential_exfil": "Credential exfiltration",
    "history_exfil": "Browsing-history exfiltration",
    "affiliate_hijack": "Affiliate hijacking",
    "local_harvest": "Local data harvesting",
    "undeclared_domain_contact": "Contact with undeclared domains",
    "unsolicited_tab": "Unsolicited tabs",
    "script_injection": "Script injection",
    "page_api_hooking": "Page API hooking",
    "beaconing": "Beaconing",
    "causes_page_hang": "Page hangs",
}
ENCODINGS = {"plain": "plain text", "url1": "URL-encoded", "url2": "double URL-encoded", "base64": "base64",
             "url1+base64": "URL-encoded base64", "base64+url": "base64, URL-encoded", "url1+base64+url": "URL-encoded base64"}
EXCERPT = 120


def label_of(score):
    return LABELS[0] if score >= FLAG_AT else LABELS[1] if score >= REVIEW_AT else LABELS[2]


def label_class(score):
    return "flagged" if score >= FLAG_AT else "review" if score >= REVIEW_AT else "none"


def e(x):
    return html.escape(str(x if x is not None else ""))


def table(rows, cols):
    if not rows:
        return '<p class="mut">none</p>'
    head = "".join(f"<th>{e(c)}</th>" for c in cols)
    body = "".join("<tr>" + "".join(f'<td class="u">{e(r.get(c) if not isinstance(r.get(c), list) else " → ".join(map(str, r.get(c))))}</td>'
                                    for c in cols) + "</tr>" for r in rows)
    return f"<table><tr>{head}</tr>{body}</table>"


# ---- helpers for the wording ----
def excerpt(text, around=None):
    """<= EXCERPT characters of `text`, whitespace collapsed; centred on `around` (a marker) when it is not at the start."""
    t = re.sub(r"\s+", " ", str(text or "")).strip()
    if len(t) <= EXCERPT:
        return t
    start = 0
    if around:
        i = t.lower().find(around.lower())
        start = max(0, min(i - 40, len(t) - (EXCERPT - 2))) if i >= 0 else 0
    cut = t[start:start + EXCERPT - 2]
    return ("…" if start else "") + cut + "…"


def plural(n, word):
    return f"{n} {word}" + ("" if n == 1 else "s")


def enc_label(enc):
    return ENCODINGS.get(enc, enc or "plain text")


def secs(ev, ts):
    base = ev.get("install_ts")
    return None if ts is None or base is None else (ts - base) / 1000.0


def span(ev, group):
    ts = [x for x in (secs(ev, g.get("ts")) for g in group) if x is not None]
    if not ts:
        return ""
    return f"+{min(ts):.1f} s" if len(ts) == 1 or max(ts) - min(ts) < 0.05 else f"+{min(ts):.1f} to +{max(ts):.1f} s"


def phases(group):
    return ", ".join(sorted({g.get("phase_ts") for g in group if g.get("phase_ts")}))


def short_path(url):
    """chrome-extension://<id>/path/file.js -> path/file.js (no extension id in the report)."""
    m = re.match(r"chrome-extension://[a-p]{32}/(.*)", url or "")
    return m.group(1) if m else (url or "")


def cs_files(ev):
    return {f for c in (ev.get("manifest") or {}).get("content_scripts") or [] for f in c.get("js") or []}


def component(ev, r):
    """Which part of the extension started the request / created the node."""
    if r.get("via") == "service_worker":
        return "service worker"
    f = short_path(r.get("ext_frame") or "")
    if f in cs_files(ev):
        return "content script"
    if f.endswith(".html"):
        return "extension page"
    return "content script" if not f else "extension script"


def script_of(ev, r):
    if r.get("via") == "service_worker":
        sws = ev.get("service_workers") or []
        return short_path(sws[0].get("url")) if sws else ""
    return short_path(r.get("ext_frame") or "")


def comp_phrase(comps):
    comps = sorted(set(comps)) or ["extension"]
    return "The " + " and the ".join(comps)


def markers_word(markers):
    words = []
    for m in markers:
        u = m.upper()
        w = "password" if "PASSWORD" in u else "one-time code" if ("OTP" in u or "CODE" in u) else None
        if w and w not in words:
            words.append(w)
    return "honeypot " + " and ".join(words) if words else "honeypot data"


def a_markers(markers):
    w = markers_word(markers)
    return w if w.endswith("data") else "a " + w


def groups(items, keyf):
    out = {}
    for it in items:
        out.setdefault(keyf(it), []).append(it)
    return list(out.values())


def row(ev, g, what, dest, frm, data=""):
    return {"What": what, "Destination": dest, "From": frm, "Data (max 120 chars)": data, "Count": f"×{len(g)}",
            "First–last": span(ev, g), "Phase": phases(g)}


EV_COLS = ["What", "Destination", "From", "Data (max 120 chars)", "Count", "First–last", "Phase"]


# ---- evidence per detector: (sentence | None, rows) ----
def ev_credential(ev, res, reqs):
    hits = []
    for r in reqs:
        text = r["url"] + " " + r["body"] + " " + json.dumps(r["headers"])
        markers, enc = S.find_honeypot_any(text)
        if markers:
            hits.append(dict(r, markers=markers, encoding=enc, text=r["body"] or r["url"]))
    if not hits:
        return None, []
    rows = []
    for g in groups(hits, lambda h: (h["host"], h["via"], tuple(h["markers"]), h["encoding"], h.get("ext_frame"))):
        h = g[0]
        mk = next((m for m in h["markers"] if m != "HONEYPOT"), None)
        rows.append(row(ev, g, f"Sent {markers_word(h['markers'])} ({enc_label(h['encoding'])})", h["host"],
                        script_of(ev, h) or component(ev, h), excerpt(h["text"], mk)))
    hosts = sorted({h["host"] for h in hits})
    dest = hosts[0] if len(hosts) == 1 else f"{len(hosts)} hosts ({', '.join(hosts[:3])}{', …' if len(hosts) > 3 else ''})"
    encs = sorted({enc_label(h["encoding"]) for h in hits})
    sent = (f"{comp_phrase([component(ev, h) for h in hits])} sent {a_markers(sorted({m for h in hits for m in h['markers']}))} "
            f"to {dest} ({plural(len(hits), 'request')}, {', '.join(encs)}).")
    return sent, rows


def ev_history(ev, res, reqs):
    hits = S.history_hits(reqs, S.visited_needles(ev))
    if not hits:
        return None, []
    rows = [row(ev, g, f"Sent a visited {'page title' if g[0]['kind'] == 'title' else 'URL'} ({enc_label(g[0]['encoding'])})",
                g[0]["host"], "service worker" if g[0]["via"] == "service_worker" else "content script", excerpt(g[0]["value"]))
            for g in groups(hits, lambda h: (h["host"], h["via"], h["kind"], h["value"], h["encoding"]))]
    hosts = sorted({h["host"] for h in hits})
    comps = ["service worker" if h["via"] == "service_worker" else "content script" for h in hits]
    return (f"{comp_phrase(comps)} sent the {'title or URL' if len({h['kind'] for h in hits}) > 1 else ('title' if hits[0]['kind'] == 'title' else 'URL')} "
            f"of pages the user visited to {', '.join(hosts[:3])} ({plural(len(hits), 'request')}).", rows)


def ev_affiliate(ev, res, reqs):
    hits = S.detect_affiliate(ev)
    if not hits:
        return None, []
    rows = []
    for g in groups(hits, lambda h: (S.host_of(h["url"]), h["kind"], tuple(h["params"]))):
        h = g[0]
        what = "Redirected through an affiliate domain" if h["kind"] == "redirect_domain" else f"Affiliate parameter(s): {', '.join(h['params'])}"
        rows.append({"What": what, "Destination": S.host_of(h["url"]), "From": "", "Data (max 120 chars)": excerpt(h["url"]),
                     "Count": f"×{len(g)}", "First–last": "", "Phase": ""})
    hosts = sorted({S.host_of(h["url"]) for h in hits})
    return (f"The extension changed shopping links or redirects to carry affiliate identifiers for {', '.join(hosts[:3])} "
            f"({plural(len(hits), 'occurrence')}).", rows)


def ev_harvest(ev, res, reqs):
    st = (ev.get("extension_storage") or {}).get("honeypot_hits") or []
    if not st:
        return None, []
    rows = [{"What": "Honeypot value found in the extension's storage", "Destination": "local storage", "From": g[0].get("file", ""),
             "Data (max 120 chars)": excerpt(g[0].get("snippet")), "Count": f"×{len(g)}", "First–last": "", "Phase": ""}
            for g in groups(st, lambda h: (h.get("file"), tuple(h.get("markers") or []), h.get("snippet")))]
    markers = sorted({m for h in st for m in h.get("markers") or []})
    return (f"The extension kept {markers_word(markers)} in its own storage "
            f"({plural(len(st), 'storage hit')}), collected but not necessarily sent.", rows)


def ev_undeclared(ev, res, reqs):
    d = res["signals"]["undeclared_domain_contact"]["details"]
    if not d:
        return None, []
    rows = [{"What": "Contacted a host not declared in the manifest" + (f" ({', '.join(x['user_data'])})" if x["user_data"] else ""),
             "Destination": x["host"], "From": ", ".join(x["via"]).replace("service_worker", "service worker").replace("page_extension", "content script"),
             "Data (max 120 chars)": "", "Count": f"×{x['requests']}", "First–last": "", "Phase": ""} for x in d]
    comps = {("service worker" if v == "service_worker" else "content script") for x in d for v in x["via"]}
    top = ", ".join(f"{x['host']} ({plural(x['requests'], 'request')})" for x in d[:3]) + (", …" if len(d) > 3 else "")
    return f"{comp_phrase(comps)} contacted {plural(len(d), 'host')} not declared in the manifest: {top}.", rows


def ev_tabs(ev, res, reqs):
    tabs = S.detect_tabs(ev)
    if not tabs:
        return None, []
    rows = []
    for t in tabs:
        rows.append({"What": f"Opened a tab via {t.get('opened_by_sw_call') or 'an extension call'}", "Destination": excerpt(t["final_url"] or t["first_url"]),
                     "From": "service worker" if t.get("opened_by_sw_call") else "extension", "Data (max 120 chars)": excerpt(" / ".join(t["titles"][:1])),
                     "Count": "×1", "First–last": f"+{t['t_since_install']:.1f} s after install" if t.get("t_since_install") is not None else "",
                     "Phase": t.get("phase_ts") or ""})
    doms = sorted({d for t in tabs for d in t["registrable_domains"]})
    who = "service worker" if any(t.get("opened_by_sw_call") for t in tabs) else "extension"
    when = [t["t_since_install"] for t in tabs if t.get("t_since_install") is not None]
    return (f"The {who} opened {plural(len(tabs), 'tab')} the user did not ask for, to {', '.join(doms[:3])}"
            f"{f', {min(when):.1f} s after install' if when else ''}.", rows)


def ev_injection(ev, res, reqs):
    nodes = S.detect_injection(ev).get("injected_nodes") or []
    if not nodes:
        return None, []
    inits = {n.get("src"): n for n in ev.get("dom_node_initiators") or [] if n.get("attributed") == "extension"}
    rows = []
    for g in groups(nodes, lambda n: (n.get("tag"), n.get("src"))):
        n = g[0]
        frame = short_path((inits.get(n.get("src")) or {}).get("ext_frames", [""])[0] if inits.get(n.get("src")) and inits[n["src"]].get("ext_frames") else "")
        rows.append({"What": f"Created a <{(n.get('tag') or '').lower()}> element", "Destination": n.get("host") or "", "From": frame,
                     "Data (max 120 chars)": excerpt(n.get("src")), "Count": f"×{len(g)}", "First–last": "", "Phase": ""})
    hosts = sorted({n.get("host") for n in nodes if n.get("host")})
    return (f"The extension's page code injected {plural(len(nodes), 'element')} (script or frame) into web pages"
            f"{', pointing to ' + ', '.join(hosts[:3]) if hosts else ''}.", rows)


def ev_hooks(ev, res, reqs):
    hooks = S.detect_hooks(ev)
    if not hooks:
        return None, []
    rows = [{"What": "Replaced page API(s): " + ", ".join(g[0]["replaced"]), "Destination": "page", "From": "extension",
             "Data (max 120 chars)": excerpt(g[0]["page_url"]), "Count": f"×{len(g)}", "First–last": "", "Phase": phases([{"phase_ts": x.get("phase")} for x in g])}
            for g in groups(hooks, lambda h: tuple(h["replaced"]))]
    apis = sorted({a for h in hooks for a in h["replaced"]})
    return f"The extension replaced built-in page APIs ({', '.join(apis)}) on {plural(len(hooks), 'page check')}.", rows


def ev_beacon(ev, res, reqs):
    b = res["signals"]["beaconing"]["details"]
    if not b:
        return None, []
    rows = [{"What": "Regular requests" + (" to an undeclared host" if x.get("host_undeclared") else ""), "Destination": x["host"],
             "From": "service worker", "Data (max 120 chars)": "", "Count": f"×{x['count']}",
             "First–last": f"every {x['interval_mean_s']:.1f} s on average (cv {x['cv']:.2f})" if x.get("interval_mean_s") is not None and x.get("cv") is not None else "",
             "Phase": ""} for x in b]
    x = b[0]
    every = f" (about every {x['interval_mean_s']:.1f} s)" if x.get("interval_mean_s") is not None else ""
    return f"The extension sent {plural(x['count'], 'request')} to {x['host']} at regular intervals{every}.", rows


def ev_hang(ev, res, reqs):
    n = ev.get("page_hang_count") or 0
    return (f"Web pages stopped responding {plural(n, 'time')} while the extension was active.", []) if n else (None, [])


BUILDERS = {"credential_exfil": ev_credential, "history_exfil": ev_history, "affiliate_hijack": ev_affiliate,
            "local_harvest": ev_harvest, "undeclared_domain_contact": ev_undeclared, "unsolicited_tab": ev_tabs,
            "script_injection": ev_injection, "page_api_hooking": ev_hooks, "beaconing": ev_beacon, "causes_page_hang": ev_hang}


def what_it_did(ev, res):
    """-> [(detector, sentence, rows)] for the detectors that fired, heaviest first."""
    reqs = S.ext_requests(ev)
    out = []
    for k in sorted((k for k, s in res["signals"].items() if s["fired"]), key=lambda k: -res["signals"][k]["weight"]):
        sentence, rows = BUILDERS[k](ev, res, reqs)
        out.append((k, sentence or f"{NAMES[k]} was detected.", rows))
    return out


def sensors(ev):
    load = ev.get("v3_load") or {}
    sw_reqs = [r for r in ev.get("network_requests", []) if r.get("origin") == "service_worker"]
    pe = [r for r in ev.get("page_request_initiators", []) if r.get("attributed") == "extension"]
    nodes = {}
    for d in ev.get("dom_activity", []):
        if d.get("type") == "node_injected":
            k = d.get("node_attributed") or "unmatched"
            nodes[k] = nodes.get(k, 0) + 1
    return [
        {"field": "Extension load", "value": f"{load.get('mode')} error={load.get('error')}"},
        {"field": "Service workers hooked at first statement", "value": len(ev.get("v3_sw_hooked") or [])},
        {"field": "Service-worker tab calls", "value": "; ".join(f"{c.get('api')} {c.get('url')} @{c.get('t_since_install')}s"
                                                               for c in ev.get("sw_tab_calls") or []) or "none"},
        {"field": "Service-worker requests / with response body", "value": f"{len(sw_reqs)} / {sum(1 for r in sw_reqs if r.get('response_body_sha256'))}"},
        {"field": "Page requests by extension / with response body",
         "value": f"{len(pe)} / {sum(1 for r in pe if r.get('response_body_sha256'))}"},
        {"field": "Injected nodes by creator", "value": json.dumps(nodes)},
        {"field": "API hook checks", "value": f"{len(ev.get('page_api_hooks') or [])} checks, replaced: "
                                              f"{sorted({a for h in ev.get('page_api_hooks') or [] for a in h.get('replaced') or []})}"},
        {"field": "Run status", "value": (ev.get("run_status") or {}).get("status")},
    ]


def analyst_sections(ev, res, extra_diag=None):
    """Everything below the headline: what it did, signals, evidence, diagnostics, manifest risk."""
    sig = res["signals"]
    did = what_it_did(ev, res)
    fired = [k for k, _, _ in did]
    p = ["<h2>What the extension did</h2>"]
    p.append("<ul class='did'>" + "".join(f"<li>{e(s)}</li>" for _, s, _ in did) + "</ul>" if did
             else "<p>No notable behavior was observed in the sandbox run.</p>")
    p.append("<h2>Signals</h2>")
    if fired:
        p.append(table([{"Detector": NAMES[k], "Weight": f"+{sig[k]['weight']}"} for k in fired], ["Detector", "Weight"]))
        total = sum(sig[k]["weight"] for k in fired)
        if total > 100:
            p.append(f"<p class='mut'>Weights add up to {total}; the score is capped at 100.</p>")
    p.append("<p class='mut'>Not observed: " + (e(", ".join(NAMES[k] for k in sig if k not in fired)) or "none") + ".</p>")
    p.append("<h2>Evidence</h2>")
    shown = False
    for k, _, rows in did:
        if rows:
            shown = True
            p.append(f"<h3>{e(NAMES[k])}</h3>" + table(rows, EV_COLS))
    if not shown:
        p.append("<p class='mut'>none</p>")
    diag = sensors(ev) + [{"field": k, "value": json.dumps(v, default=str)} for k, v in (extra_diag or {}).items()]
    p.append("<details><summary>Diagnostics</summary>" + table(diag, ["field", "value"]) + "</details>")
    st = res["static_display"]
    p.append("<h2>Manifest risk (shown for information, not scored)</h2>" + table([
        {"static_score": st["static_score"], "dangerous_permissions": st["dangerous_permissions"],
         "suspicious_hosts": st["suspicious_hosts"], "broad_scope": st["broad_content_script_scope"]}],
        ["static_score", "dangerous_permissions", "suspicious_hosts", "broad_scope"]))
    return "".join(p)


def headline(res):
    sc = res["score"]
    return (f"<p><span class='{label_class(sc)}' style='font-size:18px'>{sc} / 100 &mdash; {e(label_of(sc))}</span></p>"
            f"<p class='mut'>{e(NOTE)} Flagged for review = score &ge; {FLAG_AT}; review suggested = {REVIEW_AT}&ndash;{FLAG_AT - 1}.</p>")


def sample_html(name, ev, res):
    return (f'<details><summary>{e(name)} — {e(ev.get("manifest", {}).get("name"))} · '
            f'<span class="{label_class(res["score"])}">{res["score"]} {e(label_of(res["score"]))}</span> · '
            f'{e(", ".join(NAMES[k] for k in res["fired"]) or "no signal")}</summary>'
            + headline(res) + analyst_sections(ev, res) + "</details>")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", required=True)
    ap.add_argument("--samples", default=None)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    root = Path(a.traces)
    rows, blocks = [], []
    for d in sorted(root.iterdir()):
        evp = d / "output" / "events.json"
        if not evp.exists():
            continue
        ev = json.loads(evp.read_text(encoding="utf-8"))
        meta = json.loads((d / "meta.json").read_text(encoding="utf-8")) if (d / "meta.json").exists() else {}
        pkg = S.find_package(meta, a.samples)
        res = S.score_trace(ev, S.package_text(pkg) if pkg else None)
        rows.append({"sample": d.name, "name": ev.get("manifest", {}).get("name"), "score": res["score"],
                     "label": label_of(res["score"]), "signals": ", ".join(NAMES[k] for k in res["fired"])})
        blocks.append(sample_html(d.name, ev, res))
    doc = (f"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
           f"<title>ExtProbe report</title><style>{CSS}</style></head><body><h1>ExtProbe report</h1>"
           f"<p class='mut'>{e(NOTE)}</p>"
           + table(rows, ["sample", "name", "score", "label", "signals"]) + "".join(blocks) + "</body></html>")
    out = Path(a.out) if a.out else root / "report_v3.html"
    out.write_text(doc, encoding="utf-8")
    print(out)


if __name__ == "__main__":
    main()
