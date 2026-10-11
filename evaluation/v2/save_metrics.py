"""
save_metrics.py -- CHOT SO cho paper: ghi metric ra FILE (khong chi stdout).

READ-ONLY tren summary.csv. KHONG goi rescore.py, KHONG re-score, KHONG sua summary.csv.
Chi doc eval/results/summary.csv (cot `risk` + `label`/`verified_label` da co san) va
tinh lai duong cong PR/ROC y HET logic pr_roc.py (khong doi cach tinh, chi them phan luu).

Sinh ra:
  eval/results/metrics_summary.json        -- AUC + metric @ threshold 40, ca raw va verified
  eval/results/pr_roc_points_raw.csv       -- ghi lai sach (1 block, threshold 0..100)
  eval/results/pr_roc_points_verified.csv  -- ghi lai sach (1 block)

Doi chieu voi pr_roc.py:
  - AUC: trapezoidal tren sorted(roc_pts) -- pr_roc.py:112-118
  - loc run_status == "complete"           -- pr_roc.py:56-59
  - raw: cot `label`, chi malicious/benign -- pr_roc.py:65-69
  - verified: cot `verified_label`; grey + unknown_verify tach rieng (bao cao so luong,
    KHONG vao duong cong); benign_mislabel -> tinh la benign (False); con lai malicious vs
    benign                                  -- pr_roc.py:70-84

Chay: py -3 eval/save_metrics.py
"""
import csv
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RESULTS_DIR = Path(__import__("os").environ.get("EXTPROBE_V2_RESULTS") or REPO / "data" / "v2_results")   # recorded traces (release asset) go here
CSV = RESULTS_DIR / "summary.csv"
OUT_JSON = RESULTS_DIR / "metrics_summary.json"
OUT_DIR = RESULTS_DIR   # pr_roc_points_{raw,verified}.csv are written here

THRESHOLD_REPORT = 40
THRESHOLDS = list(range(0, 101))


def _load_rows():
    with open(CSV, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise SystemExit("summary.csv rong")
    cols = list(rows[0].keys())
    risk_col = next((c for c in cols if c.lower() in ("risk", "risk_score", "score")), None)
    label_col = next((c for c in cols if c.lower() in ("label", "ground_truth", "truth", "class")), None)
    status_col = next((c for c in cols if c.lower() == "run_status"), None)
    vlab_col = next((c for c in cols if c.lower() == "verified_label"), None)
    if not risk_col or not label_col:
        raise SystemExit(f"Khong tim thay cot risk/label. Header: {cols}")
    return rows, risk_col, label_col, status_col, vlab_col


def _build_data(rows, risk_col, label_col, status_col, vlab_col, mode):
    """Tra ve (data, meta) voi data = list[(risk_float, is_malicious_bool)]."""
    data = []
    n_excluded_status = 0
    n_grey = 0
    n_unknown_verify = 0
    n_skipped_label = 0
    for r in rows:
        if status_col and (r.get(status_col) or "").strip() != "complete":
            n_excluded_status += 1
            continue
        try:
            risk = float(r[risk_col] or 0)
        except ValueError:
            n_skipped_label += 1
            continue
        if mode == "raw":
            lab = (r[label_col] or "").strip().lower()
            if lab not in ("malicious", "benign"):
                n_skipped_label += 1
                continue
            data.append((risk, lab == "malicious"))
        else:
            vlab = (r[vlab_col] or "").strip().lower()
            if vlab == "grey":
                n_grey += 1
                continue
            if vlab == "unknown_verify":
                n_unknown_verify += 1
                continue
            if vlab == "benign_mislabel":
                data.append((risk, False))
                continue
            if vlab not in ("malicious", "benign"):
                n_skipped_label += 1
                continue
            data.append((risk, vlab == "malicious"))
    meta = {
        "n_rows_used": len(data),
        "n_excluded_run_status_not_complete": n_excluded_status,
        "n_excluded_label_unusable": n_skipped_label,
        "n_grey_separated": n_grey,
        "n_unknown_verify_separated": n_unknown_verify,
    }
    return data, meta


def _sweep(data):
    P = sum(1 for _, m in data if m)
    N = sum(1 for _, m in data if not m)
    table = []
    roc_pts = []
    for t in THRESHOLDS:
        TP = sum(1 for risk, m in data if m and risk >= t)
        FP = sum(1 for risk, m in data if (not m) and risk >= t)
        FN = P - TP
        TN = N - FP
        recall = TP / P if P else 0.0
        fpr = FP / N if N else 0.0
        precision = TP / (TP + FP) if (TP + FP) else 1.0
        table.append((t, TP, FP, FN, TN, recall, fpr, precision))
        roc_pts.append((fpr, recall))
    roc_sorted = sorted(roc_pts)
    auc = 0.0
    for i in range(1, len(roc_sorted)):
        x0, y0 = roc_sorted[i - 1]
        x1, y1 = roc_sorted[i]
        auc += (x1 - x0) * (y0 + y1) / 2
    return P, N, table, auc


def _at(table, threshold):
    for (t, TP, FP, FN, TN, recall, fpr, precision) in table:
        if t == threshold:
            return {
                "threshold": t, "TP": TP, "FP": FP, "FN": FN, "TN": TN,
                "recall": recall, "fpr": fpr, "precision": precision,
            }
    return None


def _write_points_csv(path, table):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["threshold", "TP", "FP", "FN", "TN", "recall", "fpr", "precision"])
        w.writerows(table)


def _rel(p):
    try:
        return str(Path(p).relative_to(REPO))
    except ValueError:
        return str(p)


def main():
    rows, risk_col, label_col, status_col, vlab_col = _load_rows()
    result = {
        "source_csv": _rel(CSV),
        "source_csv_rows": len(rows),
        "threshold_reported": THRESHOLD_REPORT,
        "note": ("AUC = trapezoidal tren ROC points (threshold-free). Logic tinh y het "
                 "eval/pr_roc.py; script nay chi THEM phan luu ra file. Khong sua summary.csv."),
        "modes": {},
    }
    for mode in ("raw", "verified"):
        if mode == "verified" and not vlab_col:
            result["modes"][mode] = {"error": "khong co cot verified_label trong summary.csv"}
            continue
        data, meta = _build_data(rows, risk_col, label_col, status_col, vlab_col, mode)
        P, N, table, auc = _sweep(data)
        at40 = _at(table, THRESHOLD_REPORT)
        result["modes"][mode] = {
            "auc_roc": auc,
            "P_malicious": P,
            "N_benign": N,
            "at_threshold_40": at40,
            "dataset_composition": meta,
            "points_csv": f"pr_roc_points_{mode}.csv",
        }
        _write_points_csv(OUT_DIR / f"pr_roc_points_{mode}.csv", table)

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"[save_metrics] -> {_rel(OUT_JSON)}")
    for mode, m in result["modes"].items():
        if "error" in m:
            print(f"  {mode}: {m['error']}")
            continue
        a = m["at_threshold_40"]
        print(f"  {mode:8s}  AUC={m['auc_roc']:.4f}  P={m['P_malicious']} N={m['N_benign']}  "
              f"@40: recall={a['recall']:.4f} precision={a['precision']:.4f} fpr={a['fpr']:.4f} "
              f"(TP={a['TP']} FP={a['FP']} FN={a['FN']} TN={a['TN']})")
    print("  pr_roc_points_raw.csv / pr_roc_points_verified.csv: ghi lai sach (1 block moi file)")


if __name__ == "__main__":
    main()
