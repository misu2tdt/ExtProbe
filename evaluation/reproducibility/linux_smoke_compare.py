"""Compare the Linux smoke re-run with the original run and the Windows re-run.

  python evaluation/reproducibility/linux_smoke_compare.py BUNDLE_DIR/expected.csv extprobe-out/linux_smoke/results.csv

expected.csv: label, sha256, original_score/flag/detectors, windows_rerun_score/flag/detectors (labels only, no extension ids)
results.csv : label, score, level, detectors, exit_code, seconds   (written by linux_smoke_run.sh)
Flag = score >= 40. Detectors are compared as sets.
"""
import csv
import sys


def read(path):
    with open(path, encoding="utf-8", newline="") as f:
        return {r["label"]: r for r in csv.DictReader(f)}


def det(s):
    return {d for d in (s or "").split(";") if d}


def main(argv):
    if len(argv) != 3:
        print(__doc__)
        return 2
    exp, res = read(argv[1]), read(argv[2])
    head = ["label", "original", "Windows re-run", "Linux re-run", "same flag as Windows?", "same detectors as Windows?"]
    rows, n = [], {"compared": 0, "failed": 0, "missing": 0, "flag_win": 0, "det_win": 0, "score_win": 0, "flag_orig": 0, "det_orig": 0}
    for label, e in exp.items():
        r = res.get(label)
        orig = f"{'FLAG' if e['original_flag'] == 'yes' else 'no'} {e['original_score']}"
        win = f"{'FLAG' if e['windows_rerun_flag'] == 'yes' else 'no'} {e['windows_rerun_score']}"
        if r is None:
            n["missing"] += 1
            rows.append([label, orig, win, "(not run)", "-", "-"])
            continue
        if r["score"] == "":
            n["failed"] += 1
            rows.append([label, orig, win, f"FAILED (exit {r['exit_code']})", "-", "-"])
            continue
        n["compared"] += 1
        sc = int(float(r["score"]))
        flag = sc >= 40
        lin = f"{'FLAG' if flag else 'no'} {sc}"
        same_flag = flag == (e["windows_rerun_flag"] == "yes")
        same_det = det(r["detectors"]) == det(e["windows_rerun_detectors"])
        n["flag_win"] += same_flag
        n["det_win"] += same_det
        n["score_win"] += sc == int(float(e["windows_rerun_score"]))
        n["flag_orig"] += flag == (e["original_flag"] == "yes")
        n["det_orig"] += det(r["detectors"]) == det(e["original_detectors"])
        rows.append([label, orig, win, lin, "yes" if same_flag else "NO", "yes" if same_det else "NO"])
    widths = [max(len(str(x[i])) for x in [head] + rows) for i in range(len(head))]
    for k, row in enumerate([head] + rows):
        print("  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row)).rstrip())
        if k == 0:
            print("  ".join("-" * w for w in widths))
    c = n["compared"]
    print(f"\nsummary: {len(exp)} labels in expected.csv, {c} compared, {n['failed']} failed, {n['missing']} not run")
    print(f"  same flag as the Windows re-run:      {n['flag_win']}/{c}")
    print(f"  same detectors as the Windows re-run: {n['det_win']}/{c}")
    print(f"  same score as the Windows re-run:     {n['score_win']}/{c}")
    print(f"  same flag as the original run:        {n['flag_orig']}/{c}")
    print(f"  same detectors as the original run:   {n['det_orig']}/{c}")
    return 1 if n["failed"] or n["missing"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
