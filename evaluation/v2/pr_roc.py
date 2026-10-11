"""
pr_roc.py — Ve PR curve + ROC curve tu summary.csv, tinh AUC.
Chay: python eval/pr_roc.py [--mode raw|verified]
Yeu cau: matplotlib  (pip install matplotlib --break-system-packages)

Quy uoc: malicious = positive, benign = negative.
Quet nguong risk tu 0..100, moi nguong tinh recall / FPR / precision.

--mode raw (mac dinh): dung cot `label` goc (nhu truoc).
--mode verified: dung cot `verified_label` (tu eval/apply_verified_labels.py):
  - loai lop "grey" va "unknown_verify" khoi duong cong chinh (bao cao rieng so luong
    + bao nhieu bi risk>=40 flag).
  - "benign_mislabel" duoc tinh la benign (da verify la lanh, xem
    eval/label_mapping.md).
  - chi con "malicious" vs "benign" (gom ca benign_mislabel) di vao duong cong.
  - van loc run_status == complete (dot 1).
"""
import argparse
import csv, sys
from pathlib import Path
RESULTS_DIR = Path(__import__("os").environ.get("EXTPROBE_V2_RESULTS") or Path(__file__).resolve().parents[2] / "data" / "v2_results")

CSV = str(RESULTS_DIR / "summary.csv")

parser = argparse.ArgumentParser()
parser.add_argument("--mode", choices=["raw", "verified"], default="raw",
                     help="raw = cot label goc; verified = cot verified_label, "
                          "tach lop grey/unknown_verify, gop benign_mislabel vao benign")
args = parser.parse_args()

# --- doc du lieu, tu do cot risk + label ---
rows = list(csv.DictReader(open(CSV, encoding="utf-8")))
if not rows:
    print("summary.csv rong"); sys.exit()

cols = rows[0].keys()
risk_col  = next((c for c in cols if c.lower() in ("risk","risk_score","score")), None)
label_col = next((c for c in cols if c.lower() in ("label","ground_truth","truth","class")), None)
if not risk_col or not label_col:
    print("Khong tim thay cot risk/label. Header:", list(cols)); sys.exit()

status_col = next((c for c in cols if c.lower() == "run_status"), None)
verified_label_col = next((c for c in cols if c.lower() == "verified_label"), None)

if args.mode == "verified" and not verified_label_col:
    print("Khong tim thay cot verified_label. Chay eval/apply_verified_labels.py truoc.")
    sys.exit()

print(f"=== CHE DO: {args.mode} ===")

data = []
n_excluded_status = 0
n_grey = 0
grey_rows = []           # (ext_id, risk, verified_label) — bao cao rieng
n_unknown_verify = 0

for r in rows:
    if status_col and (r.get(status_col) or "").strip() != "complete":
        n_excluded_status += 1
        continue
    try:
        risk = float(r[risk_col] or 0)
    except ValueError:
        continue

    if args.mode == "raw":
        lab = (r[label_col] or "").strip().lower()
        if lab not in ("malicious", "benign"):
            continue
        data.append((risk, lab == "malicious"))
    else:
        vlab = (r[verified_label_col] or "").strip().lower()
        if vlab == "grey":
            n_grey += 1
            grey_rows.append((r.get("ext_id", ""), risk, vlab))
            continue
        if vlab == "unknown_verify":
            n_unknown_verify += 1
            continue
        if vlab == "benign_mislabel":
            data.append((risk, False))     # da verify la lanh -> tinh nhu benign
            continue
        if vlab not in ("malicious", "benign"):
            continue
        data.append((risk, vlab == "malicious"))

print(f"Loc theo run_status=complete: dung {len(data) + n_grey + n_unknown_verify} row "
      f"| loai {n_excluded_status} row (run_status != complete)")
if args.mode == "verified":
    print(f"Tach rieng khoi duong cong: grey={n_grey}  unknown_verify={n_unknown_verify}")

P = sum(1 for _, m in data if m)      # tong malicious
N = sum(1 for _, m in data if not m)  # tong benign
print(f"Dataset: {len(data)} mau  |  malicious(P)={P}  benign(N)={N}")
if P == 0 or N == 0:
    print("Can ca malicious lan benign de ve duong cong"); sys.exit()

# --- quet nguong ---
thresholds = list(range(0, 101))
roc_pts, pr_pts, table = [], [], []
for t in thresholds:
    TP = sum(1 for risk, m in data if m and risk >= t)
    FP = sum(1 for risk, m in data if (not m) and risk >= t)
    FN = P - TP
    TN = N - FP
    recall    = TP / P if P else 0            # = TPR
    fpr       = FP / N if N else 0
    precision = TP / (TP + FP) if (TP + FP) else 1.0
    roc_pts.append((fpr, recall))
    pr_pts.append((recall, precision))
    table.append((t, TP, FP, FN, TN, recall, fpr, precision))

# --- AUC (trapezoidal) cho ROC: sap theo fpr tang ---
roc_sorted = sorted(roc_pts)
auc = 0.0
for i in range(1, len(roc_sorted)):
    x0, y0 = roc_sorted[i-1]; x1, y1 = roc_sorted[i]
    auc += (x1 - x0) * (y0 + y1) / 2
print(f"ROC AUC = {auc:.3f}")

# --- in bang vai nguong quan trong ---
print("\nnguong | TP  FP  FN  TN | recall  FPR   precision")
for t, TP, FP, FN, TN, rec, fpr, prec in table:
    if t % 10 == 0 or t in (15, 40, 70, 90):
        print(f"  {t:3}  | {TP:3} {FP:3} {FN:3} {TN:3} |  {rec:.2f}   {fpr:.2f}   {prec:.2f}")

# --- lop grey: bao nhieu bi he flag (risk>=40) ---
if args.mode == "verified" and grey_rows:
    grey_flagged = [g for g in grey_rows if g[1] >= 40]
    print(f"\nLop grey (n={len(grey_rows)}): {len(grey_flagged)}/{len(grey_rows)} "
          f"bi he flag risk>=40")
    for eid, risk, _ in sorted(grey_rows, key=lambda x: -x[1]):
        flag = "FLAGGED" if risk >= 40 else "-"
        print(f"    {eid:28s} risk={risk:5.1f}  {flag}")

# --- ve ---
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    xs = [p[0] for p in roc_sorted]; ys = [p[1] for p in roc_sorted]
    ax1.plot(xs, ys, "-o", ms=2)
    ax1.plot([0,1],[0,1],"--",color="gray",lw=0.8)
    ax1.set_xlabel("False Positive Rate"); ax1.set_ylabel("Recall (TPR)")
    ax1.set_title(f"ROC (AUC={auc:.3f}) [{args.mode}]"); ax1.grid(alpha=0.3)

    rs = [p[0] for p in pr_pts]; ps = [p[1] for p in pr_pts]
    ax2.plot(rs, ps, "-o", ms=2)
    ax2.set_xlabel("Recall"); ax2.set_ylabel("Precision")
    ax2.set_title(f"Precision-Recall [{args.mode}]"); ax2.grid(alpha=0.3)

    out = str(RESULTS_DIR / f"pr_roc_{args.mode}.png")
    plt.tight_layout(); plt.savefig(out, dpi=130)
    print(f"\nDa luu bieu do: {out}")
except ImportError:
    print("\n(Chua co matplotlib — chi in bang. Cai: pip install matplotlib --break-system-packages)")

# --- luu diem duong cong ra csv de tu ve neu can ---
out_csv = str(RESULTS_DIR / f"pr_roc_points_{args.mode}.csv")
with open(out_csv, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["threshold","TP","FP","FN","TN","recall","fpr","precision"])
    w.writerows(table)
print(f"Da luu diem: {out_csv}")
