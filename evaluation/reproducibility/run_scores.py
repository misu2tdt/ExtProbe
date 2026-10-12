"""Re-score archived traces of the development repository with its own (old) scorer and with this repository's CLI, and compare.

  python evaluation/reproducibility/run_scores.py --old-repo <dev repo checkout> --itw <folder with A/ and B/ packages> --out <dir> [SET ...]

SET: test_v3 dev_v3 itw_A itw_B probe_a probe_b (default: all). Reads the archived traces and packages (read-only); writes JSON into <dir>:
<set>_old.json (old scorer: eval/v3/score_v3.py or eval/v3_1_probe/score_v31.py of the development repository) and <set>_new.json
(`extprobe score-v3` / `score-v31` of this repository). Nothing is written into the development repository.
The archived traces are not part of this repository (release asset / private); see evaluation/reproducibility.md.
"""
import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

NEW = Path(__file__).resolve().parents[2]


def sets(old, itw):
    return {  # name: (traces, package folder, probe?)
        "test_v3": (old / "eval/v3/test/traces_v3", old / "samples/benign_test", False),
        "dev_v3": (old / "eval/v3/dev/traces", old / "samples", False),
        "itw_A": (old / "eval/v3/in_the_wild/traces_A", itw / "A", False),
        "itw_B": (old / "eval/v3/in_the_wild/traces_B", itw / "B", False),
        "probe_a": (old / "eval/v3_1_probe/traces_a", itw / "A", True),
        "probe_b": (old / "eval/v3_1_probe/traces_b", old / "samples/benign_test", True),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--old-repo", required=True, help="checkout of the development repository (read-only)")
    ap.add_argument("--itw", required=True, help="folder with A/ and B/ (the in-the-wild packages)")
    ap.add_argument("--out", required=True, help="output folder for the JSON results")
    ap.add_argument("sets", nargs="*")
    a = ap.parse_args(argv)
    old, itw, out = Path(a.old_repo).resolve(), Path(a.itw).resolve(), Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")
    table = sets(old, itw)
    for name in a.sets or list(table):
        traces, samples, probe = table[name]
        old_script = old / "eval" / ("v3_1_probe/score_v31.py" if probe else "v3/score_v3.py")
        for which, cmd, cwd in (("old", [sys.executable, "-B", str(old_script)], old),
                                ("new", [sys.executable, "-B", "-m", "extprobe", "score-v31" if probe else "score-v3"], NEW)):
            t0 = time.time()
            r = subprocess.run([*cmd, "--traces", str(traces), "--samples", str(samples), "--out", str(out / f"{name}_{which}.json")],
                               capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, cwd=str(cwd))
            print(f"{name:8s} {which}: rc={r.returncode} {time.time() - t0:5.1f}s lines={len(r.stdout.splitlines())} {r.stderr.strip()[-200:]}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
