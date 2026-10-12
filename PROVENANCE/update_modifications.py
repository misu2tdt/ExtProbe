"""Recompute the "published sha256" column of PROVENANCE/modifications.tsv from the files in this repository.

  python PROVENANCE/update_modifications.py           # update the file in place, report every row that changed
  python PROVENANCE/update_modifications.py --check   # change nothing; exit 1 if any row is stale (for a release check)

Columns: path in this repository, original path, original sha256 (private repository, never touched here), published sha256, reason.
The hash is the one `extprobe verify-freeze` uses: sha256 of the content, text files after CRLF -> LF normalisation.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from extprobe.verify_freeze import digest  # noqa: E402

TSV = ROOT / "PROVENANCE" / "modifications.tsv"


def main(argv=None):
    check = "--check" in (sys.argv[1:] if argv is None else argv)
    lines = TSV.read_bytes().decode("utf-8").split("\n")
    out, changed, missing = [], [], []
    for line in lines:
        cols = line.rstrip("\r").split("\t")
        if line.startswith("#") or len(cols) != 5:
            out.append(line)
            continue
        path = ROOT / cols[0]
        if not path.exists():
            missing.append(cols[0])
            out.append(line)
            continue
        new = digest(path)
        if new != cols[3]:
            changed.append(cols[0])
            cols[3] = new
            line = "\t".join(cols) + ("\r" if line.endswith("\r") else "")
        out.append(line)
    for p in missing:
        print(f"missing file (row left as is): {p}")
    for p in changed:
        print(f"{'stale' if check else 'updated'}: {p}")
    print(f"{len(changed)} change(s)")
    if changed and not check:
        TSV.write_bytes("\n".join(out).encode("utf-8"))
    return 1 if (changed and check) or missing else 0


if __name__ == "__main__":
    sys.exit(main())
