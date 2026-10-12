"""sys.path set-up for the repository layout. The frozen files (scoring/v3/score_v3.py ...) are byte-identical to the
evaluated ones and look for their siblings in the original layout; these entries supply them."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRIES = ("scoring", "scoring/v3", "scoring/probe", "sandbox/base", "sandbox/v3", "sandbox/probe", "evaluation/v2")


def setup():
    if not (ROOT / "scoring").is_dir():
        raise SystemExit("extprobe: scoring/ is not next to the extprobe package. Install from a clone of the repository in editable mode "
                         "(git clone ..., then pip install -e .); a plain `pip install .` does not copy scoring/, report/ and sandbox/.")
    for rel in reversed(ENTRIES):
        p = str(ROOT / rel)
        if p not in sys.path:
            sys.path.insert(0, p)
    return ROOT
