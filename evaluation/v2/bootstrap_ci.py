"""bootstrap_ci.py -- 95% stratified-bootstrap CI cho recall/precision/FPR/AUC @ nguong 40.

Doc lai eval/results/summary.csv (KHONG chay lai sandbox/risk.py), loc dung population
dung cho so paper: run_status=="complete" VA verified_label in
{malicious} (positive) / {benign, benign_mislabel} (negative). grey/unknown_verify
BI LOAI (giong quy uoc pr_roc.py --mode verified / ablation_stimulus.py classify()).

Stratified bootstrap: resample RIENG 280 positive va 49 negative (voi hoan lai,
random.Random(seed).randrange), 1000 lan, tinh recall/precision/FPR/AUC (Mann-Whitney U)
tren MOI resample, roi lay percentile 2.5/97.5 lam CI.

Chay: python eval/bootstrap_ci.py
"""
import csv
import math
import random
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RESULTS_DIR = Path(__import__("os").environ.get("EXTPROBE_V2_RESULTS") or REPO / "data" / "v2_results")   # recorded traces (release asset) go here
CSV_PATH = RESULTS_DIR / "summary.csv"
THRESHOLD = 40
N_BOOT = 1000
SEED = 42


def load_population():
    pos, neg = [], []  # risk score cua tung mau
    with open(CSV_PATH, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["run_status"] != "complete":
                continue
            vlabel = row["verified_label"]
            risk = float(row["risk"])
            if vlabel == "malicious":
                pos.append(risk)
            elif vlabel in ("benign", "benign_mislabel"):
                neg.append(risk)
            # grey / unknown_verify: loai, giong pr_roc.py --mode verified
    return pos, neg


def confusion(pos, neg, thr):
    tp = sum(1 for r in pos if r >= thr)
    fn = len(pos) - tp
    fp = sum(1 for r in neg if r >= thr)
    tn = len(neg) - fp
    return tp, fp, fn, tn


def recall_precision_fpr(pos, neg, thr):
    tp, fp, fn, tn = confusion(pos, neg, thr)
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    fpr = fp / (fp + tn) if (fp + tn) else float("nan")
    return recall, precision, fpr


def auc_mannwhitney(pos, neg):
    """AUC = P(score_pos > score_neg), tinh qua Mann-Whitney U (ties chia deu rank)."""
    if not pos or not neg:
        return float("nan")
    combined = sorted([(v, 0) for v in neg] + [(v, 1) for v in pos])
    n = len(combined)
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j < n and combined[j][0] == combined[i][0]:
            j += 1
        avg_rank = (i + 1 + j) / 2.0
        for k in range(i, j):
            ranks[k] = avg_rank
        i = j
    rank_sum_pos = sum(r for r, (_, lab) in zip(ranks, combined) if lab == 1)
    n_pos, n_neg = len(pos), len(neg)
    u = rank_sum_pos - n_pos * (n_pos + 1) / 2.0
    return u / (n_pos * n_neg)


def percentile(sorted_vals, pct):
    n = len(sorted_vals)
    idx = pct / 100.0 * (n - 1)
    lo, hi = math.floor(idx), math.ceil(idx)
    if lo == hi:
        return sorted_vals[int(idx)]
    frac = idx - lo
    return sorted_vals[lo] * (1 - frac) + sorted_vals[hi] * frac


def ci95(vals):
    s = sorted(vals)
    return percentile(s, 2.5), percentile(s, 97.5)


def main():
    pos, neg = load_population()
    n_pos, n_neg = len(pos), len(neg)
    print(f"population: n_positive(verified malicious)={n_pos} "
          f"n_negative(benign+benign_mislabel)={n_neg} total={n_pos + n_neg}")

    point_recall, point_precision, point_fpr = recall_precision_fpr(pos, neg, THRESHOLD)
    point_auc = auc_mannwhitney(pos, neg)
    tp, fp, fn, tn = confusion(pos, neg, THRESHOLD)
    print(f"confusion @ threshold {THRESHOLD}: TP={tp} FP={fp} FN={fn} TN={tn}")

    rng = random.Random(SEED)
    boot = {"recall": [], "precision": [], "fpr": [], "auc": []}
    for _ in range(N_BOOT):
        bpos = [pos[rng.randrange(n_pos)] for _ in range(n_pos)]
        bneg = [neg[rng.randrange(n_neg)] for _ in range(n_neg)]
        r, p, f = recall_precision_fpr(bpos, bneg, THRESHOLD)
        a = auc_mannwhitney(bpos, bneg)
        for key, val in (("recall", r), ("precision", p), ("fpr", f), ("auc", a)):
            if not math.isnan(val):
                boot[key].append(val)

    print(f"\n95% stratified bootstrap CI (n_boot={N_BOOT}, seed={SEED}, percentile):")
    points = {"recall": point_recall, "precision": point_precision,
              "fpr": point_fpr, "auc": point_auc}
    for key in ("recall", "precision", "fpr", "auc"):
        lo, hi = ci95(boot[key])
        print(f"  {key:10s}: {points[key]:.4f} [{lo:.4f}, {hi:.4f}]  "
              f"(n_valid_resamples={len(boot[key])})")


if __name__ == "__main__":
    main()
