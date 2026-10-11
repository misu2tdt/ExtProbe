"""
per_stratum_recall.py -- recall @ risk>=40 (verified mode) theo tung STRATUM.

READ-ONLY. Chi doc:
  eval/results/summary.csv                       (risk + verified_label + 6 cot signal, hau-fix)
  eval/results_before_fix1_sw/triage.csv         (map ext_id -> bucket, TIEN-fix, cross-check)
KHONG re-score, KHONG sua summary.csv.

Sinh ra:
  eval/results/per_stratum_recall_from_summary.csv   [PRIMARY - so dung cho paper]
      Stratum suy tu 6 cot signal 0/1 CO SAN trong summary.csv HIEN TAI (hau-fix), theo
      dung dinh nghia bucket cua eval/triage.py:52-60:
        credential_exfil|local_harvest|beaconing  -> hard_malicious
        elif script_injection                     -> injector
        elif unsolicited_tab|undeclared_domain_contact -> adware_or_pup
        else                                      -> silent (khong tach capable/minimal
                                                     duoc tu summary.csv -> gop lam 1)
      Positive = verified_label == "malicious", run_status == "complete".
      Cot: stratum, n, TP, FN, recall

  eval/results/per_stratum_recall_prefix_triage.csv  [CROSS-CHECK ONLY - KHONG phai so paper]
      6 bucket lay tu results_before_fix1_sw/triage.csv (PRE-FIX bucketing).
      Recall tinh bang risk HIEN TAI (summary.csv). Chi de doi chieu robustness.

  eval/results/core_recall.json  [Buoc 5 - truy nguon "0.9298"]

Chay: py -3 eval/per_stratum_recall.py
"""
import csv
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RESULTS_DIR = Path(__import__("os").environ.get("EXTPROBE_V2_RESULTS") or REPO / "data" / "v2_results")   # recorded traces (release asset) go here
SUMMARY = RESULTS_DIR / "summary.csv"
PREFIX_TRIAGE = RESULTS_DIR.parent / "v2_results_before_fix1_sw" / "triage.csv"
RESULTS = RESULTS_DIR

THRESHOLD = 40
SIG_HARD = ("credential_exfil", "local_harvest", "beaconing")
EXCLUDE_VLABEL = ("benign", "benign_mislabel", "grey", "unknown_verify")


def _sig(row, name):
    return str(row.get(name, "") or "").strip() == "1"


def bucket_from_summary(row):
    """Dinh nghia bucket cua triage.py:52-60, chi phan suy duoc tu summary.csv."""
    if any(_sig(row, s) for s in SIG_HARD):
        return "hard_malicious"
    if _sig(row, "script_injection"):
        return "injector"
    if _sig(row, "unsolicited_tab") or _sig(row, "undeclared_domain_contact"):
        return "adware_or_pup"
    return "silent"


def _risk(row):
    try:
        return float(row.get("risk") or 0)
    except ValueError:
        return 0.0


def load_summary():
    with open(SUMMARY, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def recall_table(pairs):
    """pairs = list[(stratum, is_flagged_bool)] -> {stratum: (n, TP, FN, recall)}."""
    out = {}
    for stratum, flagged in pairs:
        n, tp, fn = out.get(stratum, (0, 0, 0))
        n += 1
        if flagged:
            tp += 1
        else:
            fn += 1
        out[stratum] = (n, tp, fn)
    return {s: (n, tp, fn, (tp / n if n else 0.0)) for s, (n, tp, fn) in out.items()}


def write_csv(path, rows_dict, order):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["stratum", "n", "TP", "FN", "recall"])
        seen = set()
        for s in order:
            if s in rows_dict:
                n, tp, fn, rec = rows_dict[s]
                w.writerow([s, n, tp, fn, f"{rec:.4f}"])
                seen.add(s)
        for s, (n, tp, fn, rec) in rows_dict.items():
            if s not in seen:
                w.writerow([s, n, tp, fn, f"{rec:.4f}"])
        tot_n = sum(v[0] for v in rows_dict.values())
        tot_tp = sum(v[1] for v in rows_dict.values())
        tot_fn = sum(v[2] for v in rows_dict.values())
        w.writerow(["TOTAL", tot_n, tot_tp, tot_fn,
                    f"{(tot_tp / tot_n if tot_n else 0.0):.4f}"])


def main():
    rows = load_summary()
    by_id = {r["ext_id"]: r for r in rows}

    # ---------- PRIMARY: stratum tu summary.csv hien tai ----------
    prim_pairs = []
    prim_members = {}
    for r in rows:
        if (r.get("verified_label") or "").strip().lower() != "malicious":
            continue
        if (r.get("run_status") or "").strip() != "complete":
            continue
        b = bucket_from_summary(r)
        flagged = _risk(r) >= THRESHOLD
        prim_pairs.append((b, flagged))
        prim_members.setdefault(b, []).append(
            {"ext_id": r["ext_id"], "risk": _risk(r), "flagged": flagged})
    prim = recall_table(prim_pairs)
    write_csv(RESULTS / "per_stratum_recall_from_summary.csv", prim,
              ["hard_malicious", "injector", "adware_or_pup", "silent"])

    # ---------- CROSS-CHECK: bucket tu prefix triage.csv (PRE-FIX) ----------
    xcheck = None
    if PREFIX_TRIAGE.exists():
        with open(PREFIX_TRIAGE, encoding="utf-8") as f:
            tri = {t["ext_id"]: t for t in csv.DictReader(f)}
        xc_pairs = []
        n_no_summary = 0
        for ext_id, t in tri.items():
            r = by_id.get(ext_id)
            if r is None:
                n_no_summary += 1
                continue
            if (r.get("verified_label") or "").strip().lower() != "malicious":
                continue
            if (r.get("run_status") or "").strip() != "complete":
                continue
            xc_pairs.append((t.get("bucket", "?"), _risk(r) >= THRESHOLD))
        xcheck = recall_table(xc_pairs)
        write_csv(RESULTS / "per_stratum_recall_prefix_triage.csv", xcheck,
                  ["hard_malicious", "injector", "adware_or_pup",
                   "silent_capable", "silent_minimal", "run_incomplete"])

    # ---------- Buoc 5: core_recall.json ----------
    # Cohort "recall loi" = ablation_attribution.py:260-269
    #   label==malicious AND verified_label NOT IN exclude AND bucket in (hard_malicious, injector)
    core = []
    for r in rows:
        if (r.get("label") or "").strip().lower() != "malicious":
            continue
        if (r.get("verified_label") or "").strip().lower() in EXCLUDE_VLABEL:
            continue
        if bucket_from_summary(r) not in ("hard_malicious", "injector"):
            continue
        core.append(r)
    core_complete = [r for r in core if (r.get("run_status") or "").strip() == "complete"]
    core_events_present = [
        r for r in core_complete
        if (RESULTS / r["ext_id"] / "output" / "events.json").exists()
    ]
    fn_rows = [r for r in core_complete if _risk(r) < THRESHOLD]
    tp_n = sum(1 for r in core_complete if _risk(r) >= THRESHOLD)
    n58 = len(core_complete)
    n_events_present = len(core_events_present)
    tp_events_present = sum(1 for r in core_events_present if _risk(r) >= THRESHOLD)

    core_json = {
        "metric": "core recall = fraction of (hard_malicious + injector) verified-malicious "
                  "samples with risk >= 40",
        "mode": "verified",
        "threshold": THRESHOLD,
        "cohort_definition": (
            "label=='malicious' AND verified_label NOT IN "
            f"{list(EXCLUDE_VLABEL)} AND bucket_from_summary IN ('hard_malicious','injector') "
            "AND run_status=='complete'  (bucket theo triage.py:52-60 tren 6 cot signal cua summary.csv)"
        ),
        "PRIMARY": {
            "value": round(tp_n / n58, 4) if n58 else None,
            "n": n58, "TP": tp_n, "FN": n58 - tp_n,
            "explain": "Tinh THANG tu summary.csv hien tai. Moi mau complete deu duoc tinh "
                       "(mau thieu events.json -> van la FN neu risk<40, nhung dieu tra cho "
                       "thay 0 mau thieu events.json).",
        },
        "HISTORICAL_0_9298": {
            "value": 0.9298,
            "source": "CLAUDE.md:214 (commit 79d37e5), cum 'recall loi khong doi (0.9298->0.9298)'",
            "format_match": "khop dinh dang dong ablation_attribution.py:267-269 "
                            "'[Recall loi hard_malicious+injector] ... PROVENANCE=X (0.XXXX)'  (.4f)",
            "arrow_meaning": "0.9298->0.9298 = NAIVE -> PROVENANCE (provenance filter KHONG lam tut recall loi)",
            "would_need": "53/57 = 0.92982  ->  n=57 (khong phai 58)",
            "reproduce_now": "KHONG tai lap chinh xac tu artifact hien tai. Hien co n=%d mau core "
                             "complete, TAT CA deu co output/events.json (0 mau thieu). "
                             "53/58 = 0.9138." % n58,
            "candidate_causes_not_verified": [
                "dataset / verified_label state khac o commit 79d37e5 (full-pool re-run luc do)",
                "ablation_attribution.py re-score TUOI moi (compute_risk_score) -> 1 mau qua "
                "nguong 40 khac voi cot `risk` da luu trong summary.csv",
                "score_both_modes() nem exception tren 1 mau -> bi loai khoi out_rows "
                "(ablation_attribution.py:143)",
            ],
        },
        "events_json_investigation": {
            "core_complete_n": n58,
            "core_complete_with_events_json": n_events_present,
            "core_complete_missing_events_json": n58 - n_events_present,
            "recall_if_drop_missing": (round(tp_events_present / n_events_present, 4)
                                       if n_events_present else None),
            "finding": "0 mau core complete thieu events.json -> gia thuyet 'n=57 do thieu "
                       "events.json' KHONG dung. Chenh lech 0.9298 vs 0.9138 phai den tu "
                       "nguyen nhan khac (xem candidate_causes_not_verified).",
        },
        "core_FN_samples_risk_lt_40": [
            {"ext_id": r["ext_id"], "folder": r.get("folder", ""),
             "risk": _risk(r), "static_score": r.get("static_score", ""),
             "dynamic_score": r.get("dynamic_score", ""),
             "bucket": bucket_from_summary(r)}
            for r in sorted(fn_rows, key=lambda x: _risk(x))
        ],
        "RECOMMENDATION": "Dung PRIMARY 0.9138 (n=58, 53 TP / 5 FN) lam so paper. 0.9298 la so "
                          "lich su chua co artifact va nhay voi 1 mau -> khong dung lam so chinh; "
                          "co the ghi chu 'ban dot truoc bao 0.93' neu can.",
    }
    with open(RESULTS / "core_recall.json", "w", encoding="utf-8") as f:
        json.dump(core_json, f, indent=2, ensure_ascii=False)

    # ---------- stdout ----------
    print("=== PRIMARY per_stratum_recall_from_summary.csv (verified, @40) ===")
    for s in ["hard_malicious", "injector", "adware_or_pup", "silent"]:
        if s in prim:
            n, tp, fn, rec = prim[s]
            print(f"  {s:16s}  n={n:3d}  TP={tp:3d}  FN={fn:3d}  recall={rec:.4f}")
    tn = sum(v[0] for v in prim.values()); ttp = sum(v[1] for v in prim.values())
    print(f"  {'TOTAL':16s}  n={tn:3d}  TP={ttp:3d}  FN={tn - ttp:3d}  recall={ttp / tn:.4f}")

    if xcheck is not None:
        print("\n=== CROSS-CHECK per_stratum_recall_prefix_triage.csv (PRE-FIX bucketing) ===")
        for s in ["hard_malicious", "injector", "adware_or_pup",
                  "silent_capable", "silent_minimal", "run_incomplete"]:
            if s in xcheck:
                n, tp, fn, rec = xcheck[s]
                print(f"  {s:16s}  n={n:3d}  TP={tp:3d}  FN={fn:3d}  recall={rec:.4f}")

    print("\n=== core_recall.json ===")
    print(f"  PRIMARY   : {tp_n}/{n58} = {tp_n / n58:.4f}")
    print(f"  HISTORICAL: 0.9298 (CLAUDE.md:214) -- khong tai lap chinh xac; 0 mau thieu events.json")
    print(f"  FN core   : {[r['ext_id'] for r in fn_rows]}")


if __name__ == "__main__":
    main()
