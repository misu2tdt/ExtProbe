"""v3 storage sensor: identifiers the extension keeps in chrome.storage (LevelDB under the
profile), so the scorer can tell a stored, persistent identifier from a per-request random one.

Same files as the v2 storage sensor (sandbox/sensors/storage.py, unchanged). Records only UUID
tokens (8-4-4-4-12 hex) found in printable runs, with their version digit; values are not kept
otherwise.
"""
import re
from pathlib import Path

from config import PROFILE_DIR

UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-([0-9a-fA-F])[0-9a-fA-F]{3}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
MAX_TOKENS = 50


def storage_ids_v3(events):
    profile = Path(PROFILE_DIR)
    out = {"uuid_tokens": [], "files_scanned": 0}
    for base in (profile / "Default" / "Local Extension Settings", profile / "Local Extension Settings",
                 profile / "Default" / "Sync Extension Settings"):
        if not base.exists():
            continue
        for ext_dir in base.iterdir():
            if not ext_dir.is_dir():
                continue
            for f in ext_dir.glob("*"):
                if not f.is_file():
                    continue
                try:
                    data = f.read_bytes()
                except OSError:
                    continue
                out["files_scanned"] += 1
                for raw in re.findall(rb"[\x20-\x7e]{36,}", data):
                    for m in UUID_RE.finditer(raw.decode("ascii", "ignore")):
                        tok = m.group(0).lower()
                        if tok not in (t["token"] for t in out["uuid_tokens"]) and len(out["uuid_tokens"]) < MAX_TOKENS:
                            out["uuid_tokens"].append({"token": tok, "version": m.group(1), "store": base.name})
    events["extension_storage_v3"] = out
