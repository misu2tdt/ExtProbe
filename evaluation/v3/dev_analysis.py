"""dev_analysis.py -- v3 dev run (610 samples) scored with score_v3.py (eval/v3/SCORING_v3.md),
tables in the format of eval/expanded/results.md (eval/expanded_analysis.py) plus a side-by-side
comparison with the v2 expanded run.

Input : eval/v3/dev/traces/<ext_id>/{meta.json, output/events.json} (run_v3.py --label);
        the sample folders, only to find each package (hard-coded persistent-ID check);
        eval/expanded/V2/summary.csv for the v2 comparison (skipped if absent).
Labels: as expanded_analysis.py -- verified labels for the 354 development samples
        (apply_verified_labels on a copy), manifest labels (presumed) for benign_ext; grey and
        unknown_verify kept out of the main metrics; only run_status == complete counts.
Output: eval/v3/dev/summary_v3.csv, eval/v3/dev/results.md.

Run: py eval/v3/dev_analysis.py [--traces eval/v3/dev/traces] [--out eval/v3/dev/results.md]
"""
import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "eval"))
import score_v3 as S  # noqa: E402
import expanded_analysis as EA  # noqa: E402
import ab_compare  # noqa: E402

DETECTORS = ["credential_exfil", "history_exfil", "affiliate_hijack", "local_harvest", "undeclared_domain_contact",
             "unsolicited_tab", "script_injection", "page_api_hooking", "beaconing", "causes_page_hang"]
SAMPLE_DIRS = ["samples/malware", "samples/benign", "../sample/cws_benign_crx", "samples/benign_ext"]
COLS = (["ext_id", "folder", "name", "label", "run_status", "static_score", "dynamic_score", "risk", "level"]
        + DETECTORS + ["undeclared_class", "undeclared_hosts", "duration_s", "error"])
DASH = "—"


def package_index(dirs):
    idx = {}
    for d in dirs:
        p = (REPO / d).resolve()
        if p.exists():
            for f in p.glob("*.crx"):
                idx.setdefault(f.name, f)
    return idx


def score_all(traces, pkgs):
    rows = []
    for d in sorted(Path(traces).iterdir()):
        mp, evp = d / "meta.json", d / "output" / "events.json"
        if not mp.exists() or d.name == "canary":
            continue
        meta = json.loads(mp.read_text(encoding="utf-8"))
        row = {"ext_id": d.name, "folder": meta.get("folder") or "", "label": meta.get("label") or "",
               "run_status": meta.get("run_status") or "unknown", "duration_s": meta.get("duration_s"),
               "error": (meta.get("error") or "")[:80].replace("\n", " ")}
        if not evp.exists():
            rows.append({**row, "name": "", "risk": 0, "static_score": 0, "dynamic_score": 0, "level": "",
                         **{k: 0 for k in DETECTORS}, "undeclared_hosts": ""})
            continue
        ev = json.loads(evp.read_text(encoding="utf-8"))
        pkg = pkgs.get(meta.get("source_filename", ""))
        res = S.score_trace(ev, S.package_text(pkg) if pkg else None)
        und = res["signals"]["undeclared_domain_contact"]
        rows.append({**row, "name": (ev.get("manifest") or {}).get("name", ""), "risk": res["score"],
                     "static_score": res["static_display"]["static_score"], "dynamic_score": res["score"],
                     "level": res["level"], **{k: int(res["signals"][k]["fired"]) for k in DETECTORS},
                     "undeclared_class": und.get("class") if und["fired"] else "",
                     "undeclared_hosts": ";".join(u["host"] for u in und["details"])})
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", default=str(HERE / "dev" / "traces"))
    ap.add_argument("--out", default=str(HERE / "dev" / "results.md"))
    ap.add_argument("--v2-summary", default=str(REPO / "eval" / "expanded" / "V2" / "summary.csv"))
    a = ap.parse_args()
    out = Path(a.out)
    rows = score_all(a.traces, package_index(SAMPLE_DIRS))
    summary = out.parent / "summary_v3.csv"
    with open(summary, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    rows = ab_compare.labelled_rows(summary)
    manifest = EA.load_manifest()
    for r in rows:
        if r.get("folder") == EA.NEW_FOLDER:
            m = manifest.get(r["ext_id"])
            r["final"] = m["label"] if m else "unlisted"
            r["category"] = m["category"] if m else ""
            r["mname"] = m["name"] if m else r.get("name", "")
        else:
            r["final"] = r.get("verified_label", "") or r.get("label", "")
            r["category"] = ""
            r["mname"] = r.get("name", "")
        r["hosts"] = [h for h in (r.get("undeclared_hosts") or "").split(";") if h]
    complete = [r for r in rows if r.get("run_status") == "complete"]
    new = [r for r in rows if r.get("folder") == EA.NEW_FOLDER]
    dev = [r for r in rows if r.get("folder") != EA.NEW_FOLDER]
    folders = Counter(r.get("folder", "?") for r in rows)

    L = ["# v3 dev evaluation (profile v3, Tier-2 scoring)", "",
         "Generated by `py eval/v3/dev_analysis.py`. Scoring: `eval/v3/SCORING_v3.md` (score = sum of the "
         "fired signals' weights; static shown, not scored). Same rules as `eval/expanded/results.md`: "
         "threshold 40; positive = malicious; only `run_status == complete` counts. Labels: verified "
         "for the 354 development samples, **presumed** (manifest) for the 256 new ones; grey is "
         "reported separately and is not in the main metrics.", "",
         "## Samples", "", "| folder | samples | complete | not complete |", "|---|---|---|---|"]
    for f, n in sorted(folders.items()):
        c = sum(1 for r in rows if r.get("folder") == f and r.get("run_status") == "complete")
        L.append(f"| {f} | {n} | {c} | {n - c} |")
    bad = Counter(r.get("run_status", "?") for r in rows if r.get("run_status") != "complete")
    if bad:
        L += ["", "Not complete: " + ", ".join(f"{k} {v}" for k, v in sorted(bad.items())) + "."]
    unl = [r["ext_id"] for r in new if r["final"] == "unlisted"]
    if unl:
        L += ["", f"**Warning:** {len(unl)} benign_ext trace(s) not in the manifest (skipped): {', '.join(unl)}."]

    ev_all = EA.evaluate(rows, "final", "verified")
    ev_dev_v = EA.evaluate(dev, "final", "verified")
    ev_dev_r = EA.evaluate(dev, "label", "raw")
    L += ["", "## (a) All samples", ""] + EA.CONF_HEAD + [EA.conf_row("all (verified / presumed)", ev_all)]
    L += ["", "## (b) Development set (354)", ""] + EA.CONF_HEAD
    L += [EA.conf_row("354, verified labels", ev_dev_v), EA.conf_row("354, raw labels", ev_dev_r)]

    L += ["", "## (c) New set (256): false positives only", "",
          "| set | complete benign | FP @40 | TN | FPR | 95% Wilson | grey (complete) | grey ≥ 40 |",
          "|---|---|---|---|---|---|---|---|"]
    nb = [r for r in new if r["final"] == "benign" and r.get("run_status") == "complete"]
    fp_new = [r for r in nb if float(r["risk"]) >= 40]
    ng = [r for r in new if r["final"] == "grey" and r.get("run_status") == "complete"]
    lo, hi = EA.wilson(len(fp_new), len(nb))
    fpr = len(fp_new) / len(nb) if nb else float("nan")
    L.append(f"| new 256 | {len(nb)} | {len(fp_new)} | {len(nb) - len(fp_new)} | {EA.pct(fpr)} | "
             f"{EA.pct(lo)} – {EA.pct(hi)} | {len(ng)} | {sum(1 for r in ng if float(r['risk']) >= 40)} |")
    if ng:
        L += ["", "Grey (reported only): " + ", ".join(
            f"{r['mname']} ({r['risk']})" for r in sorted(ng, key=lambda r: -float(r['risk'])))]

    # ---- comparison with v2 (same tables, same label rules) ----
    v2p = Path(a.v2_summary)
    L += ["", "## Comparison with v2 (`eval/expanded/results.md`)", ""]
    if v2p.exists():
        v2rows = ab_compare.labelled_rows(v2p)
        for r in v2rows:
            if r.get("folder") == EA.NEW_FOLDER:
                m = manifest.get(r["ext_id"])
                r["final"] = m["label"] if m else "unlisted"
            else:
                r["final"] = r.get("verified_label", "") or r.get("label", "")
        v2new = [r for r in v2rows if r.get("folder") == EA.NEW_FOLDER]
        v2dev = [r for r in v2rows if r.get("folder") != EA.NEW_FOLDER]
        L += ["| set | profile | " + EA.CONF_HEAD[0].split("| set | ", 1)[1], "|---|---|---|---|---|---|---|---|---|"]
        for name, v2e, v3e in (("all (verified / presumed)", EA.evaluate(v2rows, "final", "verified"), ev_all),
                               ("354, verified labels", EA.evaluate(v2dev, "final", "verified"), ev_dev_v),
                               ("354, raw labels", EA.evaluate(v2dev, "label", "raw"), ev_dev_r)):
            for prof, e in (("v2", v2e), ("v3", v3e)):
                L.append(EA.conf_row(name, e).replace(f"| {name} |", f"| {name} | {prof} |", 1))
        v2nb = [r for r in v2new if r["final"] == "benign" and r.get("run_status") == "complete"]
        v2fp = sum(1 for r in v2nb if float(r["risk"]) >= 40)
        L += ["", f"New set FP @40: v2 {v2fp} / {len(v2nb)} ({EA.pct(v2fp / len(v2nb) if v2nb else float('nan'))}), "
                  f"v3 {len(fp_new)} / {len(nb)} ({EA.pct(fpr)})."]
        v2by = {r["ext_id"]: r for r in v2rows}
        moved = Counter()
        for r in rows:
            o = v2by.get(r["ext_id"])
            if o and r.get("run_status") == "complete" and o.get("run_status") == "complete":
                moved[(r["final"] if r["final"] in ("malicious", "benign") else "other",
                       float(o["risk"]) >= 40, float(r["risk"]) >= 40)] += 1
        L += ["", "| final label | v2 flag → v3 flag | samples |", "|---|---|---|"]
        for (lab, a2, a3), n in sorted(moved.items()):
            L.append(f"| {lab} | {'flag' if a2 else 'no'} → {'flag' if a3 else 'no'} | {n} |")
    else:
        L.append(f"v2 summary not found ({v2p.name}); comparison skipped.")

    L += ["", "## Detector fire counts (complete samples)", "",
          "| detector | malware | benign (30 + 11) | new 256 |", "|---|---|---|---|"]
    groups = [[r for r in complete if r.get("folder") == "malware"],
              [r for r in complete if r.get("folder") in ("benign", "cws_benign_crx")],
              [r for r in complete if r.get("folder") == EA.NEW_FOLDER]]
    L.append("| (complete samples) | " + " | ".join(str(len(g)) for g in groups) + " |")
    for d in DETECTORS:
        L.append(f"| {d} | " + " | ".join(str(sum(1 for r in g if str(r.get(d)) == "1")) for g in groups) + " |")
    L.append("| undeclared_domain_contact (with user data) | " + " | ".join(
        str(sum(1 for r in g if r.get("undeclared_class") == "heavy")) for g in groups) + " |")

    ov_path = out.parent / "fp_cause_overrides.csv"
    overrides = {}
    if ov_path.exists():
        overrides = {r["ext_id"]: r["cause"] for r in csv.DictReader(open(ov_path, encoding="utf-8"))}

    def fp_section(title, fps, with_cat):
        o = ["", f"## {title}", ""]
        if not fps:
            return o + ["No false positive."]
        o += ["| extension | " + ("category | " if with_cat else "") + "risk (static display) | detectors | undeclared hosts | cause (proposed) | cause (final) |",
              "|---|" + ("---|" if with_cat else "") + "---|---|---|---|---|"]
        cnt, corrected = Counter(), 0
        for r in sorted(fps, key=lambda r: -float(r["risk"])):
            det = ", ".join(d for d in DETECTORS if str(r.get(d)) == "1") or "none"
            prop = EA.propose_cause(r["mname"], r["category"], r["hosts"])
            fin = overrides.get(r["ext_id"], prop)
            corrected += fin != prop
            cnt[fin] += 1
            hosts = ", ".join(r["hosts"][:4]) + (f" (+{len(r['hosts']) - 4})" if len(r["hosts"]) > 4 else "")
            nm = r["mname"] if r["mname"] and not r["mname"].startswith("__MSG_") else r["ext_id"]
            nm = nm.replace("|", "/")
            o.append(f"| {nm} | " + (f"{r['category']} | " if with_cat else "") +
                     f"{r['risk']} ({r['static_score']}) | {det} | {hosts or DASH} | {prop} | {fin} |")
        o += ["", "Cause groups (final): " + ", ".join(f"{c} {cnt[c]}" for c in EA.CAUSES) +
              f"; {corrected} corrected by hand (`fp_cause_overrides.csv`)."]
        dc = Counter(d for r in fps for d in DETECTORS if str(r.get(d)) == "1")
        o += ["", "Detectors in the FPs: " + (", ".join(f"{d} {n}" for d, n in dc.most_common()) or "none") + "."]
        return o

    L += fp_section(f"False positives on the new benign set ({len(fp_new)} of {len(nb)})", fp_new, True)
    L += ["", "### By CWS category (new benign set)", "", "| category | complete benign | FP | FPR |", "|---|---|---|---|"]
    cat = defaultdict(lambda: [0, 0])
    for r in nb:
        cat[r["category"]][0] += 1
        cat[r["category"]][1] += float(r["risk"]) >= 40
    for c, (n, f) in sorted(cat.items(), key=lambda kv: (-kv[1][1], kv[0])):
        L.append(f"| {c} | {n} | {f} | {EA.pct(f / n)} |")
    dev_fp = [r for r in dev if r["final"] in ("benign", "benign_mislabel") and r.get("run_status") == "complete"
              and r.get("folder") != "malware" and float(r["risk"]) >= 40]
    L += fp_section(f"False positives on the paper-benign samples (reference, {len(dev_fp)})", dev_fp, False)

    text = "\n".join(L) + "\n"
    out.write_text(text, encoding="utf-8", newline="\n")
    print(text)
    print(f"-> {out}")


if __name__ == "__main__":
    main()
