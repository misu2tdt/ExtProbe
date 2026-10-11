"""prepare_lists.py -- package lists for run_probe.ps1 (no id is printed).

  py eval/v3_1_probe/prepare_lists.py --official <dir>     # list_{a,b,c}.txt: .crx paths of the selected ids, after
                                                           # checking the id-list SHA-256 (CRITERIA.md), the package
                                                           # SHA-256 (committed manifests) and the dossier exclusion
  py eval/v3_1_probe/prepare_lists.py --dev-trial <dir>    # list_trial.txt: 2 development packages for the pipeline
                                                           # test (1 malware, 1 benign_ext, popup declared, not in the
                                                           # dossiers), seed 2026
Exit code 1 on any mismatch; the message names the check, never an id.
"""
import argparse
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
sys.path.insert(0, str(REPO / "sandbox_v3_1_probe"))
from v31_policy import ext_pages  # noqa: E402

PKG = {"a": (ITW / "A", REPO / "docs/samples_manifest_itw_A.csv"),
       "b": (REPO / "samples/benign_test", REPO / "docs/samples_manifest_benign_test.csv"),
       "c": (ITW / "A", REPO / "docs/samples_manifest_itw_A.csv")}


def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def mapping_ids():
    with open(ITW / "labeling" / "mapping.csv", encoding="utf-8") as f:
        return {r["ext_id"] for r in csv.DictReader(f)}


def official(out):
    crit = (HERE / "CRITERIA.md").read_text(encoding="utf-8")
    want = dict(re.findall(r"\|\s*\(([abc])\)\s*\|.*?\|\s*`([0-9a-f]{64})`\s*\|", crit))
    excl = mapping_ids()
    ok = True
    for key in ("a", "b", "c"):                      # a stale list must never survive a failed check
        (out / f"list_{key}.txt").unlink(missing_ok=True)
    for key in ("a", "b", "c"):
        ids = [l.strip() for l in (ITW / "probe" / f"selected_{key}.txt").read_text(encoding="utf-8").splitlines() if l.strip()]
        got = hashlib.sha256(("\n".join(sorted(ids)) + "\n").encode()).hexdigest()
        if got != want.get(key):
            print(f"CHECK FAIL: id list ({key}) does not match the SHA-256 in CRITERIA.md")
            ok = False
            continue
        if set(ids) & excl:
            print(f"CHECK FAIL: id list ({key}) contains dossier samples")
            ok = False
            continue
        folder, manifest = PKG[key]
        rec = {r["ext_id"]: (r.get("sha256") or "").lower() for r in csv.DictReader(open(manifest, encoding="utf-8"))}
        bad = sum(1 for i in ids if not (folder / f"{i}.crx").exists() or sha_file(folder / f"{i}.crx") != rec.get(i))
        if bad:
            print(f"CHECK FAIL: set ({key}): {bad} package(s) missing or with a SHA-256 different from the manifest")
            ok = False
            continue
        print(f"check: set ({key}) {len(ids)} packages, id list and package SHA-256 match")
        (out / f"list_{key}.txt").write_text("\n".join(str(folder / f"{i}.crx") for i in ids) + "\n", encoding="utf-8")
    if not ok:                                       # all or nothing
        for key in ("a", "b", "c"):
            (out / f"list_{key}.txt").unlink(missing_ok=True)
    return ok


def dev_trial(out):
    excl = mapping_ids()
    tiers = {r["ext_id"]: r for r in csv.DictReader(open(REPO / "eval/v3/labels/labels_tiers.csv", encoding="utf-8"))}
    man_b = {r["ext_id"]: r for r in csv.DictReader(open(REPO / "docs/samples_manifest_benign_ext.csv", encoding="utf-8"))}
    mal, ben = [], []
    for d in sorted((REPO / "eval/v3/dev/traces").iterdir()):
        if d.name in excl or not (d / "output/events.json").exists():
            continue
        e = json.loads((d / "output/events.json").read_text(encoding="utf-8"))
        if (e.get("run_status") or {}).get("status") != "complete" or not ext_pages(e.get("manifest") or {}):
            continue
        if d.name in tiers and tiers[d.name]["label_verified"] == "malicious":
            mal.append(REPO / "samples/malware" / f"{d.name}.crx")
        elif d.name in man_b and man_b[d.name]["label"] == "benign":
            ben.append(REPO / "samples/benign_ext" / f"{d.name}.crx")
    rng = random.Random(2026)
    pick = [rng.choice(mal), rng.choice(ben)]
    (out / "list_trial.txt").write_text("\n".join(str(p) for p in pick) + "\n", encoding="utf-8")
    print("check: 2 development packages picked for the trial (1 malware, 1 benign)")
    return True


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--official")
    g.add_argument("--dev-trial")
    a = ap.parse_args()
    out = Path(a.official or a.dev_trial)
    out.mkdir(parents=True, exist_ok=True)
    sys.exit(0 if (official(out) if a.official else dev_trial(out)) else 1)


if __name__ == "__main__":
    main()
