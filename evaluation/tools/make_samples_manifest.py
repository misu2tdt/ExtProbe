"""make_samples_manifest.py -- write docs/samples_manifest.csv: one row per evaluation sample
(ext_id, file name, raw label, verified label, source, SHA-256). No sample file is copied.

The 354 samples = samples/malware (313) + samples/benign (30) + ../sample/cws_benign_crx (11).
Labels come from eval/results/summary.csv (+ eval/apply_verified_labels.py on a copy), the
source from each run's meta.json, the hashes from the two SHA256SUMS files written by
eval/verify_samples.py. Needs the samples and eval/results locally (both outside git).

Run: python eval/make_samples_manifest.py
"""
import csv
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "eval"))
from ab_compare import labelled_rows  # noqa: E402
from batch_run import ext_id_from  # noqa: E402
from verify_samples import SETS  # noqa: E402

OUT = REPO / "docs" / "samples_manifest.csv"
# source = the folder the sample came from in the authors' collection (meta.json source_folder),
# reported verbatim; see SAMPLES.md for what is known about each.


def hashes():
    """ext_id -> (location, file name, sha256) from every SHA256SUMS."""
    out = {}
    for name, (root, _, _) in SETS.items():
        sums = root / "SHA256SUMS"
        for line in sums.read_text(encoding="utf-8").splitlines():
            digest, rel = line.split(None, 1)
            rel = rel.strip()
            loc = f"samples/{Path(rel).parent.as_posix()}" if name == "samples" else "../sample/cws_benign_crx"
            out[ext_id_from(Path(rel))] = (loc, Path(rel).name, digest)
    return out


def main():
    rows = {r["ext_id"]: r for r in labelled_rows(REPO / "eval" / "results" / "summary.csv")}
    hs = hashes()
    out, missing = [], []
    for eid in sorted(rows):
        r = rows[eid]
        meta = json.loads((REPO / "eval" / "results" / eid / "meta.json").read_text(encoding="utf-8"))
        folder = meta.get("source_folder", "")
        if eid not in hs:
            missing.append(eid)
            continue
        loc, fname, digest = hs[eid]
        out.append({"ext_id": eid, "file": fname, "location": loc,
                    "label_raw": r.get("label", ""), "label_verified": r.get("verified_label", ""),
                    "source": folder,
                    "sha256": digest})
    if missing:
        sys.exit(f"no SHA-256 for {len(missing)} sample(s): {missing[:5]}")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0]))
        w.writeheader()
        w.writerows(out)
    by = {}
    for o in out:
        by[(o["location"], o["label_raw"])] = by.get((o["location"], o["label_raw"]), 0) + 1
    print(f"{len(out)} rows -> {OUT}")
    for k, v in sorted(by.items()):
        print(f"  {k[0]:<26} {k[1]:<10} {v}")


if __name__ == "__main__":
    main()
