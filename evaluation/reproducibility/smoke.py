"""Live smoke rerun: canary + 5 flagged + 5 unflagged benign extensions of the held-out test set (order of the old per-sample scores)."""
import csv, json, subprocess, sys, time, shutil
from pathlib import Path
import argparse
NEW = Path(__file__).resolve().parents[2]
_ap = argparse.ArgumentParser(description="Live smoke rerun: canary + 5 flagged + 5 unflagged benign extensions of the held-out test set.")
_ap.add_argument("--old-repo", required=True, help="checkout of the development repository (read-only; packages in samples/benign_test)")
_ap.add_argument("--scores", required=True, help="folder with test_v3_old.json from run_scores.py")
_ap.add_argument("--out", required=True, help="output folder (traces, reports, smoke_results.json)")
_a = _ap.parse_args()
OLD = Path(_a.old_repo).resolve()
HERE = Path(_a.out).resolve()
HERE.mkdir(parents=True, exist_ok=True)
SCORES = Path(_a.scores).resolve()
man = {r["ext_id"]: r for r in csv.DictReader(open(NEW / "evaluation/manifests/samples_manifest_benign_test.csv", encoding="utf-8", newline=""))}
old = json.loads((SCORES / "test_v3_old.json").read_text(encoding="utf-8"))
ben = [k for k in old if man.get(k, {}).get("label") == "benign"]
fl = [k for k in ben if old[k]["score"] >= 40][:5]
un = [k for k in ben if old[k]["score"] < 40][:5]
jobs = [("canary", NEW / "examples/canary", None)]
jobs += [(f"F{i+1}", OLD / "samples/benign_test" / f"{k}.crx", k) for i, k in enumerate(fl)]
jobs += [(f"U{i+1}", OLD / "samples/benign_test" / f"{k}.crx", k) for i, k in enumerate(un)]
(HERE / "smoke").mkdir(exist_ok=True)
res = []
for label, target, k in jobs:
    assert Path(target).exists(), label
    out = HERE / "smoke" / label
    shutil.rmtree(out, ignore_errors=True)
    t0 = time.time()
    p = subprocess.run([sys.executable, "-m", "extprobe", "analyze", str(target), "--out", str(out)], capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=str(NEW))
    rj = out / "report.json"
    r = json.loads(rj.read_text(encoding="utf-8")) if rj.exists() else {}
    row = {"label": label, "rc": p.returncode, "secs": round(time.time() - t0, 1), "new_score": r.get("score"), "new_fired": r.get("detectors_fired"),
           "old_score": old[k]["score"] if k else 100, "old_fired": old[k]["fired"] if k else ["credential_exfil", "local_harvest", "unsolicited_tab"],
           "signals_new": {n: s["weight"] for n, s in (r.get("signals") or {}).items() if s["fired"]}, "signals_old": {n: s["weight"] for n, s in old[k]["signals"].items() if s["fired"]} if k else None,
           "err": p.stderr.strip()[-200:]}
    res.append(row)
    print(label, row["rc"], row["secs"], row["old_score"], "->", row["new_score"], row["old_fired"], "->", row["new_fired"], flush=True)
    (HERE / "smoke_results.json").write_text(json.dumps(res, indent=1), encoding="utf-8")

