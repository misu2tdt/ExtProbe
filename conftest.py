"""pytest/launcher path set-up. The frozen files keep their original text, so they find their sibling modules through these
entries (score_v3.py inserts <repo>/worker and <repo>/sandbox, which do not exist in this layout; that is harmless)."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for rel in ("evaluation/v2", "sandbox/probe", "sandbox/v3", "sandbox/base", "scoring/probe", "scoring/v3", "scoring"):
    p = str(ROOT / rel)
    if p not in sys.path:
        sys.path.insert(0, p)
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
