"""select_trial.py -- trial sets of the v3.1-probe experiment (eval/v3_1_probe/CRITERIA.md).

  py eval/v3_1_probe/select_trial.py      # writes the id lists OUTSIDE the repository (..\\itw\\probe\\), prints counts
                                          # and the SHA-256 of each sorted list only (no id is printed)

(a) set A: package in ..\\itw\\A, NOT in ..\\itw\\labeling\\mapping.csv, a complete v3 trace, the manifest declares a
    popup or an options page, and no score_v3 detector fired on the v3 trace; random.Random(2026).sample of 60
    over the sorted ids (all of them if fewer)
(b) 50 of the 192 benign extensions of the held-out test set (docs/samples_manifest_benign_test.csv, label benign),
    random.Random(2026).sample over the sorted ids
(c) T2 samples of set A whose id is in the saved Socket report page, NOT in mapping.csv (case study)
"""
import csv
import hashlib
import json
import random
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
ITW = REPO.parent / "itw"
OUT = ITW / "probe"
sys.path.insert(0, str(REPO / "eval" / "v3"))
sys.path.insert(0, str(REPO / "sandbox_v3_1_probe"))
import score_v3 as S  # noqa: E402
from v31_policy import ext_pages  # noqa: E402

SEED = 2026


def ids_sha(ids):
    return hashlib.sha256(("\n".join(sorted(ids)) + "\n").encode()).hexdigest()


def main():
    with open(ITW / "labeling" / "mapping.csv", encoding="utf-8") as f:
        excl = {r["ext_id"] for r in csv.DictReader(f)}           # only the id column is used
    counts = {}
    # (a)
    pool = sorted(p.stem for p in (ITW / "A").glob("*.crx"))
    counts["a_packages"] = len(pool)
    pool = [i for i in pool if i not in excl]
    counts["a_not_in_dossiers"] = len(pool)
    elig = []
    for i in pool:
        ev = REPO / "eval" / "v3" / "in_the_wild" / "traces_A" / i / "output" / "events.json"
        if not ev.exists():
            continue
        e = json.loads(ev.read_text(encoding="utf-8"))
        if (e.get("run_status") or {}).get("status") != "complete":
            continue
        if not ext_pages(e.get("manifest") or {}):
            continue
        if S.score_trace(e, S.package_text(ITW / "A" / f"{i}.crx"))["fired"]:
            continue
        elig.append(i)
    counts["a_eligible"] = len(elig)
    a = random.Random(SEED).sample(elig, min(60, len(elig)))
    # (b)
    ben = sorted(r["ext_id"] for r in csv.DictReader(open(REPO / "docs" / "samples_manifest_benign_test.csv", encoding="utf-8"))
                 if r["label"] == "benign")
    b = random.Random(SEED).sample(ben, 50)
    # (c)
    html = (ITW / "socket_vpn_2026-08-11.html").read_text(encoding="utf-8", errors="ignore")
    listed = set(re.findall(r"(?<![a-p])[a-p]{32}(?![a-p])", html))
    t2 = {r["ext_id"] for r in csv.DictReader(open(REPO / "eval" / "v3" / "in_the_wild" / "label_tiers_A.csv", encoding="utf-8"))
          if r["tier"] == "T2"}
    c_all = sorted(t2 & listed)
    c = [i for i in c_all if i not in excl]
    counts.update(c_t2_in_socket_list=len(c_all), c_not_in_dossiers=len(c))
    OUT.mkdir(parents=True, exist_ok=True)
    for name, ids in (("a", a), ("b", b), ("c", c)):
        (OUT / f"selected_{name}.txt").write_text("\n".join(sorted(ids)) + ("\n" if ids else ""), encoding="utf-8")
        counts[f"{name}_selected"] = len(ids)
        counts[f"{name}_sha256"] = ids_sha(ids) if ids else None
    assert not (set(a) | set(b) | set(c)) & excl
    print(json.dumps(counts, indent=1))


if __name__ == "__main__":
    main()
