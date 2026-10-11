"""verify-freeze: the files that were frozen before the evaluations are unchanged (sha256 of content, not git ids).

Manifest: PROVENANCE/frozen_files.tsv  (sha256 <TAB> path in this repository <TAB> original path <TAB> original git blob id)
          plus "# NOT CARRIED: <original path> <blob id>" lines for frozen files that were deliberately left out.
Text files are hashed after CRLF -> LF normalisation (the manifest holds the hash of the LF form).
"""
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "PROVENANCE" / "frozen_files.tsv"


def digest(path):
    data = path.read_bytes()
    if b"\0" not in data[:8192]:
        data = data.replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def main(argv=None):
    if not MANIFEST.exists():
        print(f"missing {MANIFEST}")
        return 2
    ok = bad = 0
    not_carried = []
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        if line.startswith("# NOT CARRIED:"):
            not_carried.append(line[len("# NOT CARRIED:"):].strip())
            continue
        if not line.strip() or line.startswith("#"):
            continue
        sha, new, orig, blob = line.split("\t")
        p = ROOT / new
        got = digest(p) if p.exists() else None
        if got == sha:
            ok += 1
        else:
            bad += 1
            print(f"FAIL  {new}  ({'missing' if got is None else 'content differs'}; originally {orig})")
    print(f"{ok} frozen file(s) match their recorded sha256, {bad} differ or are missing; {len(not_carried)} frozen file(s) deliberately not carried")
    for n in not_carried:
        print(f"  not carried: {n}")
    return 1 if bad else 0
