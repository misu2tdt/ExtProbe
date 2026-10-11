"""report_v3.py -- HTML report of v3 traces and their Tier-2 scores (score_v3.py).

  py eval/v3/report_v3.py --traces eval/v3/runs/smoke2 [--samples samples] [--out report_v3.html]

Written next to the traces by default (traces and this report stay local: they hold full URLs).
Shows the v3 fields: extension-opened tabs with redirect chains / registrable domains / time
since install / opening SW call, node creators, API hooks, user data in extension requests,
response bodies, the SW hook and CDP load status, and the static part (display only).
"""
import argparse
import html
import json
from pathlib import Path

import score_v3 as S

CSS = """
:root{--bg:#fff;--fg:#1d1d1f;--mut:#6b7280;--line:#e5e7eb;--hi:#b91c1c;--md:#c2410c;--lo:#a16207;--ok:#15803d}
@media (prefers-color-scheme: dark){:root{--bg:#111827;--fg:#e5e7eb;--mut:#9ca3af;--line:#374151}}
body{background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif;margin:0 auto;max-width:1200px;padding:16px}
table{border-collapse:collapse;width:100%;margin:6px 0 14px}th,td{border-bottom:1px solid var(--line);padding:4px 6px;
text-align:left;vertical-align:top}th{color:var(--mut);font-weight:600}code,.u{font:12px ui-monospace,monospace;word-break:break-all}
.CRITICAL,.HIGH{color:var(--hi);font-weight:700}.MEDIUM{color:var(--md);font-weight:700}.LOW{color:var(--lo)}.MINIMAL{color:var(--ok)}
details{border:1px solid var(--line);border-radius:6px;margin:8px 0;padding:6px 10px}summary{cursor:pointer;font-weight:600}
.mut{color:var(--mut)}h3{margin:12px 0 4px;font-size:14px}
"""


def e(x):
    return html.escape(str(x if x is not None else ""))


def table(rows, cols):
    if not rows:
        return '<p class="mut">none</p>'
    head = "".join(f"<th>{e(c)}</th>" for c in cols)
    body = "".join("<tr>" + "".join(f'<td class="u">{e(r.get(c) if not isinstance(r.get(c), list) else " → ".join(map(str, r.get(c))))}</td>'
                                    for c in cols) + "</tr>" for r in rows)
    return f"<table><tr>{head}</tr>{body}</table>"


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
        {"field": "load", "value": f"{load.get('mode')} id={load.get('id')} error={load.get('error')}"},
        {"field": "SW hooked at first statement", "value": len(ev.get("v3_sw_hooked") or [])},
        {"field": "SW tab calls (T1-3)", "value": "; ".join(f"{c.get('api')} {c.get('url')} @{c.get('t_since_install')}s"
                                                         for c in ev.get("sw_tab_calls") or []) or "none"},
        {"field": "SW requests / with response body", "value": f"{len(sw_reqs)} / {sum(1 for r in sw_reqs if r.get('response_body_sha256'))}"},
        {"field": "page requests by extension / with response body",
         "value": f"{len(pe)} / {sum(1 for r in pe if r.get('response_body_sha256'))}"},
        {"field": "injected nodes by creator (A2)", "value": json.dumps(nodes)},
        {"field": "API hook checks (A4)", "value": f"{len(ev.get('page_api_hooks') or [])} checks, replaced: "
                                                  f"{sorted({a for h in ev.get('page_api_hooks') or [] for a in h.get('replaced') or []})}"},
        {"field": "run status", "value": (ev.get("run_status") or {}).get("status")},
    ]


def sample_html(name, ev, res):
    sig = res["signals"]
    parts = [f'<details><summary>{e(name)} — {e(ev.get("manifest", {}).get("name"))} · '
             f'<span class="{e(res["level"])}">{res["score"]} {e(res["level"])}</span> · {e(", ".join(res["fired"]) or "no signal")}</summary>']
    parts.append("<h3>Signals</h3>" + table([{"signal": k, "fired": s["fired"], "weight": s["weight"], "class": s.get("class", "")}
                                             for k, s in sig.items()], ["signal", "fired", "weight", "class"]))
    parts.append("<h3>Extension-opened tabs (T2-4)</h3>" + table(sig["unsolicited_tab"]["details"],
                 ["chain", "n_registrable_domains", "registrable_domains", "final_url", "titles", "t_since_install", "opened_by_sw_call"]))
    parts.append("<h3>History in extension requests (T2-2)</h3>" + table(sig["history_exfil"]["details"],
                 ["host", "via", "kind", "value", "encoding"]))
    parts.append("<h3>Undeclared hosts (T2-3)</h3>" + table(sig["undeclared_domain_contact"]["details"],
                 ["host", "requests", "via", "user_data", "persistent_ids"]))
    parts.append("<h3>Credentials in extension requests (T2-7)</h3>" + table(sig["credential_exfil"]["details"],
                 ["host", "via", "markers", "encoding"]))
    parts.append("<h3>Nodes created by the extension (T2-5)</h3>" + table(sig["script_injection"]["details"], ["tag", "src", "host"]))
    parts.append("<h3>Page API hooking (T2-8)</h3>" + table(sig["page_api_hooking"]["details"], ["page_url", "phase", "replaced"]))
    parts.append("<h3>Affiliate (T2-6)</h3>" + table(sig["affiliate_hijack"]["details"], ["url", "kind", "params", "sources"]))
    parts.append("<h3>Beaconing</h3>" + table(sig["beaconing"]["details"], ["host", "count", "interval_mean_s", "cv", "host_undeclared"]))
    st = res["static_display"]
    parts.append("<h3>Static (display only, T2-1)</h3>" + table([
        {"static_score": st["static_score"], "dangerous_permissions": st["dangerous_permissions"],
         "suspicious_hosts": st["suspicious_hosts"], "broad_scope": st["broad_content_script_scope"]}],
        ["static_score", "dangerous_permissions", "suspicious_hosts", "broad_scope"]))
    parts.append("<h3>v3 sensors</h3>" + table(sensors(ev), ["field", "value"]))
    parts.append("</details>")
    return "".join(parts)


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
                     "level": res["level"], "signals": ", ".join(res["fired"]),
                     "static (display)": res["static_display"]["static_score"]})
        blocks.append(sample_html(d.name, ev, res))
    doc = (f"<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
           f"<title>ExtProbe v3 report</title><style>{CSS}</style></head><body><h1>ExtProbe v3 report</h1>"
           f"<p class='mut'>Scoring: eval/v3/SCORING_v3.md. Flag = score ≥ {S.FLAG_THRESHOLD}. Static is shown, not scored.</p>"
           + table(rows, ["sample", "name", "score", "level", "signals", "static (display)"]) + "".join(blocks) + "</body></html>")
    out = Path(a.out) if a.out else root / "report_v3.html"
    out.write_text(doc, encoding="utf-8")
    print(out)


if __name__ == "__main__":
    main()
