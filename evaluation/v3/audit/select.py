"""select.py -- the audit sample (AUDIT_CRITERIA.md): all v3 TP + 40 random FN (seed 42).

  py eval/v3/audit/select.py     # -> eval/v3/audit/sample.csv (ext_id, kind, v3_score)

Labels and scores as eval/v3/dev/results.md: summary_v3.csv (dev_analysis.py) with
apply_verified_labels on a copy.
"""
import csv
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO / "eval"))
import ab_compare  # noqa: E402

rows = ab_compare.labelled_rows(HERE.parent / "dev" / "summary_v3.csv")
pos = [r for r in rows if r.get("folder") == "malware" and r.get("run_status") == "complete"
       and (r.get("verified_label") or r.get("label")) == "malicious"]
tp = sorted(r["ext_id"] for r in pos if float(r["risk"]) >= 40)
fn_all = sorted(r["ext_id"] for r in pos if float(r["risk"]) < 40)
fn = random.Random(42).sample(fn_all, 40)
score = {r["ext_id"]: r["risk"] for r in pos}
with open(HERE / "sample.csv", "w", encoding="utf-8", newline="") as f:
    w = csv.writer(f)
    w.writerow(["ext_id", "kind", "v3_score"])
    for i in tp:
        w.writerow([i, "TP", score[i]])
    for i in fn:
        w.writerow([i, "FN", score[i]])
print(f"positives {len(pos)}, TP {len(tp)}, FN {len(fn_all)} -> sample TP {len(tp)} + FN {len(fn)}")
