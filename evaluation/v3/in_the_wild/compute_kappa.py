"""compute_kappa.py -- agreement and Cohen's kappa of two raters (stdlib only).

  python evaluation/v3/in_the_wild/compute_kappa.py --ratings ratings.csv
  python evaluation/v3/in_the_wild/compute_kappa.py --matrix matrix.csv

--ratings  CSV with one row per dossier and the columns  dossier_id, rater_a, rater_b  (an optional column `final` is only echoed for the label counts).
           `dossier_id` is an anonymous code (for example L-001), never an extension id or name.
--matrix   square CSV of counts: first row = header ("", label1, label2, ...), then one row per rater-A label: label, n(A=label,B=label1), ...
           (rows = rater A, columns = rater B, same label order in rows and columns).
Prints n, exact agreement k/n, expected chance agreement, Cohen's kappa (unweighted, over the labels that occur) and the confusion matrix.
The per-dossier labels of the in-the-wild audit are NOT in this repository (the rater sheets name developer domains and stay in the private
development repository); see evaluation/v3/in_the_wild/labeling.md for the published aggregates (24/26 agreement, kappa 0.862).
"""
import argparse
import csv
import sys
from collections import Counter


def kappa_from_matrix(labels, m):
    n = sum(sum(r) for r in m)
    if n == 0:
        raise ValueError("no ratings")
    agree = sum(m[i][i] for i in range(len(labels)))
    row = [sum(r) for r in m]
    col = [sum(m[i][j] for i in range(len(labels))) for j in range(len(labels))]
    po = agree / n
    pe = sum(row[i] * col[i] for i in range(len(labels))) / (n * n)
    k = 1.0 if pe == 1 else (po - pe) / (1 - pe)
    return {"n": n, "agree": agree, "po": po, "pe": pe, "kappa": k, "labels": labels, "matrix": m}


def from_ratings(pairs):
    labels = sorted({a for a, _ in pairs} | {b for _, b in pairs})
    ix = {l: i for i, l in enumerate(labels)}
    m = [[0] * len(labels) for _ in labels]
    for a, b in pairs:
        m[ix[a]][ix[b]] += 1
    return kappa_from_matrix(labels, m)


def read_ratings(path):
    with open(path, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    need = {"dossier_id", "rater_a", "rater_b"}
    if not rows or not need <= set(rows[0]):
        raise SystemExit(f"{path}: expected the columns {sorted(need)}")
    return [(r["rater_a"].strip(), r["rater_b"].strip()) for r in rows]


def read_matrix(path):
    with open(path, encoding="utf-8", newline="") as f:
        rows = [r for r in csv.reader(f) if r]
    labels = [c.strip() for c in rows[0][1:]]
    body = rows[1:]
    if [r[0].strip() for r in body] != labels:
        raise SystemExit(f"{path}: row labels must equal column labels (same order)")
    return labels, [[int(x) for x in r[1:]] for r in body]


def report(res):
    L = res["labels"]
    out = [f"n = {res['n']}", f"exact agreement = {res['agree']} / {res['n']} = {100 * res['po']:.1f}%",
           f"expected by chance = {res['pe']:.3f}", f"Cohen's kappa (unweighted) = {res['kappa']:.3f}", "",
           "rows = rater A, columns = rater B", "\t".join([""] + L)]
    out += ["\t".join([L[i]] + [str(x) for x in res["matrix"][i]]) for i in range(len(L))]
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--ratings")
    g.add_argument("--matrix")
    a = ap.parse_args(argv)
    res = from_ratings(read_ratings(a.ratings)) if a.ratings else kappa_from_matrix(*read_matrix(a.matrix))
    print(report(res))
    return 0


if __name__ == "__main__":
    sys.exit(main())
