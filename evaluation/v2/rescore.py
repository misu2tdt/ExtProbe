"""B2 rescore: doc moi events.json da luu, chay risk.py (KHONG can Docker),
xuat summary.csv. Day la vong lap tinh chinh: sua risk.py -> chay lai file nay -> vai giay.

Usage: python eval/rescore.py [RESULTS_DIR] [--scoring auto|legacy] [--out FILE]
  --scoring auto (default): each trace is scored by the rules for the profile that
      recorded it (corpus traces: legacy rules; v2 traces: v2 rules). Writes summary.csv.
  --scoring legacy: every trace is scored with the corpus rules (risk.legacy_view: v2-only
      rules off -- beaconing counts page-initiated requests, affiliate_hijack disabled), e.g.
      to derive run A' from the traces of run B without re-running the sandbox. Writes
      summary_legacy.csv unless --out is given, so the run's summary.csv is left alone.
"""
import argparse, csv, json, sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RESULTS_DIR = Path(__import__("os").environ.get("EXTPROBE_V2_RESULTS") or REPO / "data" / "v2_results")   # recorded traces (release asset) go here
sys.path.insert(0, str(REPO / "scoring"))
from risk import build_behavioral_report, compute_risk_score, legacy_view  # noqa: E402

SIGNALS = ["credential_exfil", "local_harvest", "script_injection",
           "beaconing", "undeclared_domain_contact", "unsolicited_tab"]

def row_for(run_dir: Path, scoring: str = "auto"):
    ev = run_dir / "output" / "events.json"
    meta = {}
    if (run_dir / "meta.json").exists():
        meta = json.loads((run_dir / "meta.json").read_text(encoding="utf-8"))
    if not ev.exists():
        if meta:
            return {"ext_id": meta.get("ext_id", run_dir.name), "label": meta.get("label", ""),
                    "run_status": "no_events", "error": (meta.get("error", "") or "")[:120]}
        return None
    try:
        events = json.loads(ev.read_text(encoding="utf-8"))
        if scoring == "legacy":
            events = legacy_view(events)
        report = build_behavioral_report(events)
        risk, level, bd = compute_risk_score(report)
        ind, findings = report.get("indicators", {}), report.get("findings", [])
        man, summ, rs = events.get("manifest", {}), events.get("summary", {}), events.get("run_status", {})
        row = {
            "ext_id": meta.get("ext_id", run_dir.name),
            "folder": meta.get("source_folder", ""),
            "name": man.get("name", ""),
            "manifest_version": man.get("manifest_version", ""),
            "label": meta.get("label", ""),
            "run_status": rs.get("status", "unknown"),
            "static_score": bd.get("static_score", 0),
            "dynamic_score": bd.get("dynamic_score", 0),
            "risk": risk, "level": level,
            "findings_mitre": "|".join(sorted(f["technique_id"] for f in findings if f.get("technique_id"))),
            "n_findings": len(findings),
            "total_requests": summ.get("total_requests", 0),
            "duration_s": meta.get("duration_s", ""),
            "error": (meta.get("error", "") or "")[:120],
        }
        for s in SIGNALS:
            row[s] = int(bool(ind.get(s)))
        return row
    except Exception as e:
        return {"ext_id": meta.get("ext_id", run_dir.name), "label": meta.get("label", ""),
                "run_status": "rescore_error", "error": str(e)[:120]}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results", nargs="?", default=str(RESULTS_DIR))
    ap.add_argument("--scoring", choices=["auto", "legacy"], default="auto")
    ap.add_argument("--out", help="output CSV (default summary.csv, or summary_legacy.csv for legacy)")
    a = ap.parse_args()
    results = Path(a.results)
    rows = [r for d in sorted(results.iterdir()) if d.is_dir() for r in [row_for(d, a.scoring)] if r]
    if not rows:
        print("khong co ket qua trong", results); return
    cols = ["ext_id", "folder", "name", "manifest_version", "label", "run_status",
            "static_score", "dynamic_score", "risk", "level", *SIGNALS,
            "findings_mitre", "n_findings", "total_requests", "duration_s", "error"]
    out = Path(a.out) if a.out else results / ("summary_legacy.csv" if a.scoring == "legacy" else "summary.csv")
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)
    scored = [r for r in rows if r.get("run_status") not in ("no_events", "rescore_error")]
    flagged = [r for r in scored if isinstance(r.get("risk"), (int, float)) and r["risk"] >= 40]
    print(f"[rescore] {len(rows)} mau -> {out}  (scoring: {a.scoring})")
    print(f"  chay duoc: {len(scored)} | risk>=40 (MEDIUM+): {len(flagged)}"
          + (f" = {len(flagged)/len(scored)*100:.0f}% flag" if scored else ""))
    for s in SIGNALS:
        print(f"    {s}: {sum(r.get(s, 0) for r in scored)}")

if __name__ == "__main__":
    main()
