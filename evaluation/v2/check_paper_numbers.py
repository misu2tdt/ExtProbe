"""check_paper_numbers.py -- regression test for the SOICT paper's headline numbers.

  python evaluation/v2/check_paper_numbers.py --precomputed   # from evaluation/v2/precomputed/summary.csv (no traces)
  python evaluation/v2/check_paper_numbers.py                 # full: re-scores the 354 recorded traces in data/v2_results/

Expected (paper):
  verified: AUC 0.6955, @40 TP=196 FP=11 FN=84 TN=38
  raw:      AUC 0.4854, @40 TP=199 FP=14 FN=111 TN=17

Full mode re-runs rescore.py -> apply_verified_labels.py -> save_metrics.py on a TEMPORARY copy of the traces
(<data/v2_results>/<ext_id>/{meta.json, output/events.json}) and also checks that the regenerated summary.csv is identical to the
one in data/v2_results/ (line endings are ignored: csv.writer always writes CRLF, git may store LF). It needs the trace archive (release asset) and data/verdicts_local.json (manual verdicts that name benign
extensions; available on request).

--precomputed re-derives the 10 metric checks (AUC and TP/FP/FN/TN, raw and verified) from the shipped summary.csv with the same
save_metrics.py code; the two trace-dependent checks are reported as SKIPPED ("requires Zenodo traces"). The shipped
metrics_summary.json and pr_roc_points_*.csv are compared with the regenerated ones as additional consistency lines (CSV: line endings ignored,
see above).
In the shipped summary.csv the ids and names of benign extensions are replaced by pseudonyms; the metrics use only label, verified_label,
risk and run_status.

Exit code 0 = every check that ran passed, 1 = any FAIL.
"""
import argparse
import contextlib
import hashlib
import io
import json
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RESULTS = Path(__import__("os").environ.get("EXTPROBE_V2_RESULTS") or REPO / "data" / "v2_results")
PRECOMPUTED = REPO / "evaluation" / "v2" / "precomputed"
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(REPO / "scoring"))

EXPECTED = {
    "verified": {"auc": 0.6955, "TP": 196, "FP": 11, "FN": 84, "TN": 38},
    "raw": {"auc": 0.4854, "TP": 199, "FP": 14, "FN": 111, "TN": 17},
}
GUARDED = ["summary.csv", "metrics_summary.json", "pr_roc_points_raw.csv", "pr_roc_points_verified.csv"]
SKIP_NOTE = "requires Zenodo traces"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def lf(data: bytes) -> bytes:
    """CRLF -> LF. save_metrics / apply_verified_labels write CSV with csv.writer (CRLF on every OS); a checkout may hold LF (Linux CI,
    .gitattributes eol=lf) or CRLF (Windows autocrlf). The comparison is about the content, not the line endings."""
    return data.replace(b"\r\n", b"\n")


def sha256_lf(path: Path) -> str:
    return hashlib.sha256(lf(path.read_bytes())).hexdigest()


def copy_traces(dst: Path) -> None:
    for d in sorted(p for p in RESULTS.iterdir() if p.is_dir()):
        out = dst / d.name
        out.mkdir(parents=True)
        if (d / "meta.json").exists():
            shutil.copy2(d / "meta.json", out / "meta.json")
        if (d / "output" / "events.json").exists():
            (out / "output").mkdir()
            shutil.copy2(d / "output" / "events.json", out / "output" / "events.json")


def run_save_metrics(tmp_results: Path) -> dict:
    import save_metrics
    save_metrics.REPO = tmp_results.parent
    save_metrics.CSV = tmp_results / "summary.csv"
    save_metrics.OUT_JSON = tmp_results / "metrics_summary.json"
    save_metrics.OUT_DIR = tmp_results
    with contextlib.redirect_stdout(io.StringIO()):
        save_metrics.main()
    return json.loads((tmp_results / "metrics_summary.json").read_text(encoding="utf-8"))


def metric_checks(metrics: dict) -> list:
    checks = []
    for mode, exp in EXPECTED.items():
        m = metrics["modes"][mode]
        got_auc = round(m["auc_roc"], 4)
        checks.append((f"{mode} AUC", f"{exp['auc']:.4f}", f"{got_auc:.4f}", got_auc == exp["auc"]))
        at = m["at_threshold_40"]
        for k in ("TP", "FP", "FN", "TN"):
            checks.append((f"{mode} @40 {k}", str(exp[k]), str(at[k]), at[k] == exp[k]))
    return checks


def run_full(tmpdir: Path) -> list:
    import rescore
    import apply_verified_labels
    tmp_results = tmpdir / "results"
    copy_traces(tmp_results)
    argv = sys.argv
    sys.argv = ["rescore.py", str(tmp_results)]
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            rescore.main()
    finally:
        sys.argv = argv
    apply_verified_labels.CSV = tmp_results / "summary.csv"
    with contextlib.redirect_stdout(io.StringIO()):
        apply_verified_labels.main()
    checks = metric_checks(run_save_metrics(tmp_results))
    ref, new = sha256_lf(RESULTS / "summary.csv"), sha256_lf(tmp_results / "summary.csv")
    checks.append(("summary.csv SHA-256", ref[:16], new[:16], ref == new))
    return checks


def run_precomputed(tmpdir: Path):
    tmp_results = tmpdir / "results"
    tmp_results.mkdir(parents=True)
    shutil.copy2(PRECOMPUTED / "summary.csv", tmp_results / "summary.csv")
    metrics = run_save_metrics(tmp_results)
    checks = metric_checks(metrics)
    checks.append(("summary.csv SHA-256 (regenerated from traces)", "-", "-", None))
    checks.append(("traces untouched", "-", "-", None))
    extra = []
    shipped = json.loads((PRECOMPUTED / "metrics_summary.json").read_text(encoding="utf-8"))
    for mode in EXPECTED:
        a, b = shipped["modes"][mode], metrics["modes"][mode]
        extra.append((f"shipped metrics_summary.json == regenerated ({mode})",
                      a["auc_roc"] == b["auc_roc"] and a["at_threshold_40"] == b["at_threshold_40"]))
        sp, rp = PRECOMPUTED / f"pr_roc_points_{mode}.csv", tmp_results / f"pr_roc_points_{mode}.csv"
        extra.append((f"shipped pr_roc_points_{mode}.csv == regenerated", lf(sp.read_bytes()) == lf(rp.read_bytes())))
    return checks, extra


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--precomputed", action="store_true", help="use evaluation/v2/precomputed/summary.csv; no traces needed")
    args = ap.parse_args()
    tmpdir = Path(tempfile.mkdtemp(prefix="extprobe_check_"))
    extra, restored = [], []
    backup = {n: (RESULTS / n).read_bytes() for n in GUARDED if (RESULTS / n).exists()} if not args.precomputed else {}
    before = {n: hashlib.sha256(b).hexdigest() for n, b in backup.items()}
    try:
        if args.precomputed:
            checks, extra = run_precomputed(tmpdir)
        else:
            if not RESULTS.exists():
                print(f"{RESULTS} not found: the recorded traces are a release asset; use --precomputed, or put them there.")
                return 2
            checks = run_full(tmpdir)
    finally:
        for n, data in backup.items():
            if sha256(RESULTS / n) != before[n]:
                (RESULTS / n).write_bytes(data)
                restored.append(n)
        shutil.rmtree(tmpdir, ignore_errors=True)
    if not args.precomputed:
        checks.append(("traces untouched", "yes", "yes" if not restored else "no", not restored))

    w = max(len(c[0]) for c in checks)
    print(f"{'check':<{w}}  {'expected':<16}  {'got':<16}  result")
    for name, exp, got, ok in checks:
        res = "SKIPPED (" + SKIP_NOTE + ")" if ok is None else ("PASS" if ok else "FAIL")
        print(f"{name:<{w}}  {exp:<16}  {got:<16}  {res}")
    if extra:
        print("\nconsistency of the shipped result files:")
        for name, ok in extra:
            print(f"  {name}: {'PASS' if ok else 'FAIL'}")
    ran = [c for c in checks if c[3] is not None]
    n_fail = sum(not c[3] for c in ran) + sum(not e[1] for e in extra)
    skipped = len(checks) - len(ran)
    print(f"\n{sum(c[3] for c in ran)}/{len(checks)} PASS" + (f", {skipped} SKIPPED ({SKIP_NOTE})" if skipped else "") + (f", {n_fail} FAIL" if n_fail else ""))
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
