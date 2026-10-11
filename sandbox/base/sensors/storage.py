import logging
import re
from pathlib import Path

from config import PROFILE_DIR
from honeypot import _find_honeypot

logger = logging.getLogger(__name__)


# ============ CAM BIEN 5: STORAGE CUA EXTENSION ============
def dump_extension_storage(events):
    """
    Doc chrome.storage.local (LevelDB trong profile).
    Malware thuong cat tam du lieu harvest o day truoc khi gui di
    => thay honeypot o day = bang chung DA THU THAP (du chua kip gui).
    """
    profile = Path(PROFILE_DIR)
    candidates = [profile / "Default" / "Local Extension Settings",
                  profile / "Local Extension Settings"]
    base = next((c for c in candidates if c.exists()), None)
    if base is None:
        return

    total_bytes, hits = 0, []
    for ext_dir in base.iterdir():
        if not ext_dir.is_dir():
            continue
        for f in ext_dir.glob("*"):
            try:
                data = f.read_bytes()
            except Exception as e:
                if f.is_dir():
                    logger.debug("storage sensor: skipping subdirectory %s", f)
                else:
                    logger.warning("storage sensor: unreadable file %s for ext %s, "
                                   "not scanned for honeypot markers: %s", f.name, ext_dir.name, e)
                continue
            total_bytes += len(data)
            for raw in re.findall(rb"[\x20-\x7e]{8,}", data):
                s = raw.decode("ascii", "ignore")
                found = _find_honeypot(s)
                if found:
                    hits.append({"ext_id": ext_dir.name, "file": f.name,
                                 "markers": found, "snippet": s[:200]})

    events["extension_storage"] = {
        "total_bytes": total_bytes,
        "honeypot_hits": hits[:20],
        "honeypot_found": len(hits) > 0,
    }
    if hits:
        events["honeypot_stored"] = True
        print(f"[Analyze] !!! HONEYPOT IN STORAGE: {len(hits)} hits", flush=True)
