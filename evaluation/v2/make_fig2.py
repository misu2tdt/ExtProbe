"""
make_fig2.py -- Figure 2 cho paper: ROC + PR, raw vs verified CHONG LEN 1 truc.
Doc eval/results/pr_roc_points_{raw,verified}.csv (do eval/pr_roc.py ghi).
Xuat (dpi=300, den-trang in duoc):
  eval/results/fig_roc_raw_vs_verified.png
  eval/results/fig_pr_raw_vs_verified.png

Chay: py -3 eval/make_fig2.py   (can matplotlib)
"""
import csv
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

REPO = Path(__file__).resolve().parents[2]
RESULTS_DIR = Path(__import__("os").environ.get("EXTPROBE_V2_RESULTS") or REPO / "data" / "v2_results")   # recorded traces (release asset) go here
RESULTS = RESULTS_DIR
DPI = 300

# den-trang: khac nhau bang linestyle + marker + do dam xam, KHONG dua vao mau
STYLE = {
    "raw":      dict(color="0.55", linestyle="--", marker="s", markersize=3, linewidth=1.4),
    "verified": dict(color="0.0",  linestyle="-",  marker="o", markersize=3, linewidth=1.6),
}
LABEL = {"raw": "raw labels", "verified": "audited labels"}


def load_points(mode):
    p = RESULTS / f"pr_roc_points_{mode}.csv"
    rows = list(csv.DictReader(open(p, encoding="utf-8")))
    return {
        "threshold": [float(r["threshold"]) for r in rows],
        "fpr": [float(r["fpr"]) for r in rows],
        "recall": [float(r["recall"]) for r in rows],
        "precision": [float(r["precision"]) for r in rows],
    }


def auc_trapz(xy):
    s = sorted(xy)
    a = 0.0
    for i in range(1, len(s)):
        x0, y0 = s[i - 1]
        x1, y1 = s[i]
        a += (x1 - x0) * (y0 + y1) / 2
    return a


def fig_roc(data):
    fig, ax = plt.subplots(figsize=(5.2, 5.0))
    for mode in ("verified", "raw"):
        d = data[mode]
        pts = sorted(zip(d["fpr"], d["recall"]))
        xs = [x for x, _ in pts]
        ys = [y for _, y in pts]
        a = auc_trapz(pts)
        ax.plot(xs, ys, label=f"{LABEL[mode]} (AUC = {a:.3f})", **STYLE[mode])
    ax.plot([0, 1], [0, 1], ":", color="0.7", linewidth=0.9, label="chance")
    ax.set_xlim(-0.02, 1.02)
    ax.set_ylim(-0.02, 1.02)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("Recall (True Positive Rate)")
    ax.set_title("ROC — dynamic-first risk score (threshold sweep 0–100)")
    ax.grid(alpha=0.35, linewidth=0.5)
    ax.legend(loc="lower right", framealpha=0.95, fontsize=9)
    fig.tight_layout()
    outs = []
    for ext in ("png", "pdf"):
        out = RESULTS / f"fig_roc_raw_vs_verified.{ext}"
        fig.savefig(out, dpi=DPI)
        outs.append(out)
    plt.close(fig)
    return outs


def fig_pr(data):
    fig, ax = plt.subplots(figsize=(5.2, 5.0))
    for mode in ("verified", "raw"):
        d = data[mode]
        # sap theo recall tang de duong lien mach (locus threshold-sweep, KHONG phai AP chuan)
        pts = sorted(zip(d["recall"], d["precision"]))
        xs = [x for x, _ in pts]
        ys = [y for _, y in pts]
        ax.plot(xs, ys, label=f"{LABEL[mode]}", **STYLE[mode])
    ax.set_xlim(-0.02, 1.02)
    ax.set_ylim(0, 1.02)
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision–Recall — dynamic-first risk score")
    ax.grid(alpha=0.35, linewidth=0.5)
    ax.legend(loc="lower left", framealpha=0.95, fontsize=9)
    fig.tight_layout()
    outs = []
    for ext in ("png", "pdf"):
        out = RESULTS / f"fig_pr_raw_vs_verified.{ext}"
        fig.savefig(out, dpi=DPI)
        outs.append(out)
    plt.close(fig)
    return outs


def main():
    data = {m: load_points(m) for m in ("raw", "verified")}
    outs = fig_roc(data) + fig_pr(data)
    for o in outs:
        print(f"  wrote {o}  ({o.stat().st_size // 1024} KB, dpi={DPI})")


if __name__ == "__main__":
    main()
