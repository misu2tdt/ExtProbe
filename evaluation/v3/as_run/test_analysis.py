"""test_analysis.py -- results of the held-out benign test set, v2 and v3 side by side.

  py eval/v3/test_analysis.py                    # test set (after run_v3_test.ps1)
  py eval/v3/test_analysis.py --manifest docs/samples_manifest_benign_ext.csv --v3 eval/v3/dev/traces \
        --v2 eval/expanded/V2 --samples samples/benign_ext --out <file>      # dry check on the dev traces

Input : docs/samples_manifest_benign_test.csv (id, name, category, label benign / grey, fixed from the
        store listing before the run); traces of the v3 profile (eval/v3/test/traces_v3) and of the
        v2 profile (eval/v3/test/traces_v2), each <id>/{meta.json, output/events.json}.
Scoring: v3 = eval/v3/score_v3.py (SCORING_v3.md, frozen in FREEZE_v3.md); v2 = worker/risk.py on the
        v2 trace, exactly what eval/rescore.py computes for a v2 trace. Flag = score >= 40 in both.
        Only run_status == complete counts; the others are listed.
Output: eval/v3/test/results.md. Positives do not exist in this set: every number is a false-positive rate.
"""
import argparse
import csv
import json
import re
import statistics as st
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "eval"))
import score_v3 as S  # noqa: E402  (also puts worker/ on the path)
import risk  # noqa: E402
from expanded_analysis import wilson, pct  # noqa: E402

THRESHOLD = 40
THRESHOLDS = [15, 25, 35, 40, 50, 60]
BUCKETS = [(0, 14, "0-14"), (15, 24, "15-24"), (25, 34, "25-34"), (35, 39, "35-39"), (40, 49, "40-49"),
           (50, 59, "50-59"), (60, 79, "60-79"), (80, 100, "80-100")]
V2_DETECTORS = ["credential_exfil", "local_harvest", "undeclared_domain_contact", "beaconing", "script_injection",
                "unsolicited_tab", "affiliate_hijack"]
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def mask_host(h):
    return "<ip>" if IP_RE.match(h or "") else h


def load_events(trace_dir, ext_id):
    d = Path(trace_dir) / ext_id
    meta = json.loads((d / "meta.json").read_text(encoding="utf-8")) if (d / "meta.json").exists() else {}
    evp = d / "output" / "events.json"
    ev = json.loads(evp.read_text(encoding="utf-8")) if evp.exists() else None
    return meta, ev


def score_v3(ev, pkg_text):
    res = S.score_trace(ev, pkg_text)
    und = res["signals"]["undeclared_domain_contact"]
    hosts = [u["host"] for u in und["details"]] if und["fired"] else []
    return res["score"], res["fired"], hosts


def score_v2(ev):
    rep = risk.build_behavioral_report(ev)
    score, _, _ = risk.compute_risk_score(rep)
    dyn = rep["dynamic"]["undeclared_domains"]
    hosts = sorted(set(dyn.get("undeclared_from_sw", [])) | set(dyn.get("undeclared_from_cs", [])))
    fired = [d for d in V2_DETECTORS if rep["indicators"].get(d)]
    return score, fired, hosts


def collect(manifest, trace_dir, profile, samples):
    rows = []
    for m in manifest:
        meta, ev = load_events(trace_dir, m["ext_id"])
        status = (ev or {}).get("run_status", {}).get("status") if ev else (meta.get("run_status") or "missing")
        r = {"ext_id": m["ext_id"], "name": m["name"], "category": m["category"], "label": m["label"],
             "run_status": status or "unknown", "score": None, "fired": [], "hosts": []}
        if ev is not None and r["run_status"] == "complete":
            if profile == "v3":
                crx = Path(samples) / f"{m['ext_id']}.crx"
                r["score"], r["fired"], r["hosts"] = score_v3(ev, S.package_text(crx) if crx.exists() else None)
            else:
                r["score"], r["fired"], r["hosts"] = score_v2(ev)
        rows.append(r)
    return rows


def rate_line(k, n):
    if n == 0:
        return "n/a"
    lo, hi = wilson(k, n)
    return f"{k} / {n} = {pct(k / n)} ({pct(lo)}–{pct(hi)})"


def dev_shares(path):
    cnt = Counter(r["category"] for r in csv.DictReader(open(path, encoding="utf-8")))
    return {c: n / sum(cnt.values()) for c, n in cnt.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default=str(REPO / "docs" / "samples_manifest_benign_test.csv"))
    ap.add_argument("--v3", default=str(HERE / "test" / "traces_v3"))
    ap.add_argument("--v2", default=str(HERE / "test" / "traces_v2"))
    ap.add_argument("--samples", default=str(REPO / "samples" / "benign_test"))
    ap.add_argument("--dev-manifest", default=str(REPO / "docs" / "samples_manifest_benign_ext.csv"))
    ap.add_argument("--out", default=str(HERE / "test" / "results.md"))
    ap.add_argument("--title", default="Held-out benign test set (200): v2 and v3")
    a = ap.parse_args()
    manifest = list(csv.DictReader(open(a.manifest, encoding="utf-8")))
    data = {"v2": collect(manifest, a.v2, "v2", a.samples), "v3": collect(manifest, a.v3, "v3", a.samples)}
    shares = dev_shares(a.dev_manifest)
    cats = list(dict.fromkeys(m["category"] for m in manifest))
    P = ("v2", "v3")

    def ok(rows, label):
        return [r for r in rows if r["run_status"] == "complete" and r["label"] == label and r["score"] is not None]

    L = [f"# {a.title}", "",
         f"Generated by `py eval/v3/test_analysis.py`. {len(manifest)} extensions "
         f"({sum(1 for m in manifest if m['label'] == 'benign')} benign, {sum(1 for m in manifest if m['label'] == 'grey')} grey; "
         "labels presumed from the store listing and fixed before the run). The set has no malicious sample: every figure is "
         "a **false-positive rate** (flag = score ≥ 40). v3 scoring = `score_v3.py` as frozen in `FREEZE_v3.md`; "
         "v2 = `worker/risk.py` on the v2 trace. Only `run_status == complete` counts; 95 % intervals are Wilson.", ""]

    L += ["## Runs", "", "| profile | complete | partial | failed | missing |", "|---|---|---|---|---|"]
    for p in P:
        c = Counter(r["run_status"] for r in data[p])
        L.append(f"| {p} | {c['complete']} | {c['partial']} | {c['failed']} | "
                 f"{sum(v for k, v in c.items() if k not in ('complete', 'partial', 'failed'))} |")
    for p in P:
        bad = [r for r in data[p] if r["run_status"] != "complete"]
        if bad:
            L.append("")
            L.append(f"Not complete in {p}: " + ", ".join(f"{r['name'][:30]} ({r['run_status']})" for r in bad[:30]))

    L += ["", "## False-positive rate at 40 (primary)", "", "| | v2 | v3 |", "|---|---|---|"]
    ben = {p: ok(data[p], "benign") for p in P}
    grey = {p: ok(data[p], "grey") for p in P}
    fp = {p: [r for r in ben[p] if r["score"] >= THRESHOLD] for p in P}
    gf = {p: [r for r in grey[p] if r["score"] >= THRESHOLD] for p in P}
    L.append("| benign: FP @40 | " + " | ".join(rate_line(len(fp[p]), len(ben[p])) for p in P) + " |")
    L.append("| grey (reported apart): flagged @40 | " + " | ".join(rate_line(len(gf[p]), len(grey[p])) for p in P) + " |")
    both = [m["ext_id"] for m in manifest]
    sc = {p: {r["ext_id"]: r for r in data[p]} for p in P}
    pair = Counter()
    for i in both:
        a2, a3 = sc["v2"][i], sc["v3"][i]
        if a2["score"] is not None and a3["score"] is not None and a2["label"] == "benign":
            pair[(a2["score"] >= THRESHOLD, a3["score"] >= THRESHOLD)] += 1
    L += ["", "Benign extensions complete in both profiles, by flag (paired):", "",
          "| v2 \\ v3 | not flagged | flagged |", "|---|---|---|",
          f"| not flagged | {pair[(False, False)]} | {pair[(False, True)]} |",
          f"| flagged | {pair[(True, False)]} | {pair[(True, True)]} |"]

    L += ["", "## FPR by threshold (benign)", "", "| threshold | v2 | v3 | grey v2 | grey v3 |", "|---|---|---|---|---|"]
    for t in THRESHOLDS:
        cells = [rate_line(sum(1 for r in ben[p] if r["score"] >= t), len(ben[p])) for p in P]
        gcells = [f"{sum(1 for r in grey[p] if r['score'] >= t)} / {len(grey[p])}" for p in P]
        L.append(f"| ≥ {t} | " + " | ".join(cells + gcells) + " |")

    L += ["", "## Score distribution (benign, complete)", "", "| score | v2 | v3 |", "|---|---|---|"]
    for lo_, hi_, name in BUCKETS:
        L.append(f"| {name} | " + " | ".join(str(sum(1 for r in ben[p] if lo_ <= r["score"] <= hi_)) for p in P) + " |")
    L.append("| mean / median / 90th pct | " + " | ".join(
        f"{st.fmean(r['score'] for r in ben[p]):.1f} / {st.median(r['score'] for r in ben[p]):g} / "
        f"{sorted(r['score'] for r in ben[p])[int(0.9 * (len(ben[p]) - 1))]}" if ben[p] else "n/a" for p in P) + " |")

    L += ["", "## FPR by category (benign @40)", "", "| category | n (complete) | FP v2 | FP v3 | FPR v2 | FPR v3 |",
          "|---|---|---|---|---|---|"]
    fpr_c = {p: {} for p in P}
    for c in cats:
        cells = []
        for p in P:
            n = sum(1 for r in ben[p] if r["category"] == c)
            k = sum(1 for r in fp[p] if r["category"] == c)
            fpr_c[p][c] = (k / n) if n else None
            cells.append((n, k))
        n3, k3 = cells[1]
        n2, k2 = cells[0]
        L.append(f"| {c} | {n2} / {n3} | {k2} | {k3} | {pct(k2 / n2) if n2 else '—'} | {pct(k3 / n3) if n3 else '—'} |")

    L += ["", "## FPR weighted by the development set's category mix (supplementary)", "",
          "Weights = each category's share of the development set (`docs/samples_manifest_benign_ext.csv`), over the "
          "categories that have complete benign test samples (renormalised). Categories with 1–2 samples make this "
          "figure noisy; it is **not** the primary result.", "", "| | v2 | v3 |", "|---|---|---|"]
    cells = []
    for p in P:
        use = {c: shares.get(c, 0) for c in cats if fpr_c[p][c] is not None and shares.get(c, 0) > 0}
        tot = sum(use.values())
        cells.append(f"{pct(sum(shares[c] * fpr_c[p][c] for c in use) / tot)}" if tot else "n/a")
    L.append("| weighted FPR @40 | " + " | ".join(cells) + " |")

    for p in P:
        L += ["", f"## False positives {p} ({len(fp[p])} of {len(ben[p])} benign)", ""]
        if not fp[p]:
            L.append("None.")
            continue
        L += ["| extension | category | score v2 / v3 | detectors | undeclared hosts |", "|---|---|---|---|---|"]
        for r in sorted(fp[p], key=lambda r: -r["score"]):
            o = sc["v3" if p == "v2" else "v2"][r["ext_id"]]
            s2, s3 = (r["score"], o["score"]) if p == "v2" else (o["score"], r["score"])
            hosts = ", ".join(mask_host(h) for h in r["hosts"][:4]) + (f" (+{len(r['hosts']) - 4})" if len(r["hosts"]) > 4 else "")
            nm = (r["name"] if r["name"] and not r["name"].startswith("__MSG_") else r["ext_id"]).replace("|", "/")
            L.append(f"| {nm} | {r['category']} | {s2 if s2 is not None else '—'} / {s3 if s3 is not None else '—'} | "
                     f"{', '.join(r['fired']) or 'none'} | {hosts or '—'} |")
        dc = Counter(d for r in fp[p] for d in r["fired"])
        L += ["", f"Detectors in the {p} false positives: " + (", ".join(f"{d} {n}" for d, n in dc.most_common()) or "none") + "."]
    for p in P:
        if gf[p]:
            L += ["", f"Grey flagged in {p}: " + ", ".join(f"{r['name'][:28]} ({r['score']})" for r in sorted(gf[p], key=lambda r: -r['score'])) + "."]

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(L) + "\n", encoding="utf-8", newline="\n")
    print("\n".join(L))
    print(f"-> {out}")


if __name__ == "__main__":
    main()
