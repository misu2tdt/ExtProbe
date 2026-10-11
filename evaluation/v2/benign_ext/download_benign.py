"""download_benign.py -- download and check the selected benign extensions (CRITERIA.md).

Takes the candidates exactly as select_list.py selects them (all 256 qualifying), downloads
each .crx through the public Chrome update endpoint into samples/benign_ext/<ext_id>.crx
(gitignored: the files are never committed), at most one request every 2 s. A failed
download is retried twice; a file that is still missing or fails a check is recorded with its
reason and NOT replaced by another extension (CRITERIA.md decision 4).

Checks per file: starts with the CRX magic; a manifest.json can be read from the archive;
manifest_version == 3; the id computed from the .crx header equals the listing id; SHA-256.
A file that fails a check is deleted from samples/benign_ext/ (its reason stays in the report).

Writes (committed):
  docs/samples_manifest_benign_ext.csv   accepted files: ext_id, name, version, users, rating,
                                         rating_count, category, label, downloaded, sha256, source_url
  eval/benign_ext/download_report.csv    one row per candidate: status, reason, attempts, bytes
Resumable: a valid file already in samples/benign_ext/ is checked, not downloaded again.

Run: python eval/benign_ext/download_benign.py [--limit N]
"""
import argparse
import csv
import hashlib
import io
import json
import sys
import time
import urllib.error
import urllib.request
import zipfile
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
sys.path.insert(0, str(HERE))
import select_list as S  # noqa: E402
from build_list import crx_id  # noqa: E402

DEST = REPO / "samples" / "benign_ext"
MANIFEST_CSV = REPO / "docs" / "samples_manifest_benign_ext.csv"
REPORT_CSV = HERE / "download_report.csv"
PRODVERSION = "150.0.7871.187"
URL = ("https://clients2.google.com/service/update2/crx?response=redirect&acceptformat=crx2,crx3"
       f"&prodversion={PRODVERSION}&x=id%3D{{id}}%26installsource%3Dondemand%26uc")
UA = "Mozilla/5.0 (compatible; extprobe-research/1.0; benign-extension survey; +<REPO_URL>)"
DELAY_S, RETRIES = 2.0, 2
MAX_BYTES = 120 * 2**20


def fetch(ext_id):
    req = urllib.request.Request(URL.format(id=ext_id), headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=90) as r:
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"larger than {MAX_BYTES // 2**20} MB")
    return data


def read_manifest(path):
    """manifest.json of a .crx (CRX2 / CRX3 header skipped)."""
    b = path.read_bytes()
    z = zipfile.ZipFile(io.BytesIO(b[b.index(b"PK\x03\x04"):]))
    return json.loads(z.read("manifest.json").decode("utf-8-sig"))


def check(path, ext_id):
    """(ok, reason, info)"""
    b = path.read_bytes()
    if b[:4] != b"Cr24":
        return False, "not a CRX file (no Cr24 magic)", {}
    try:
        m = read_manifest(path)
    except Exception as e:
        return False, f"manifest.json unreadable: {type(e).__name__}", {}
    if m.get("manifest_version") != 3:
        return False, f"manifest_version {m.get('manifest_version')} (not MV3)", {}
    hid = crx_id(path)
    if hid != ext_id:
        return False, f"id in .crx header ({hid}) differs from listing id", {}
    return True, "", {"version": m.get("version", ""), "sha256": hashlib.sha256(b).hexdigest(), "size": len(b)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="only the first N candidates (testing)")
    a = ap.parse_args()
    rows, existing = S.load()
    eligible, _ = S.waterfall(rows, existing)
    chosen, _ = S.select(eligible, 300)          # = all qualifying (256 on 2026-10-07)
    if a.limit:
        chosen = chosen[:a.limit]
    DEST.mkdir(parents=True, exist_ok=True)
    today = date.today().isoformat()
    report, accepted = [], []
    last_request = 0.0
    for n, r in enumerate(chosen, 1):
        ext_id, path = r["ext_id"], DEST / f"{r['ext_id']}.crx"
        status, reason, attempts, info = "ok", "", 0, {}
        if path.exists():
            ok, reason, info = check(path, ext_id)
            if not ok:
                path.unlink()
        else:
            ok = False
        while not ok and attempts <= RETRIES:
            attempts += 1
            wait = DELAY_S - (time.monotonic() - last_request)
            if wait > 0:
                time.sleep(wait)
            last_request = time.monotonic()
            try:
                data = fetch(ext_id)
                if not data:
                    reason = "empty response (extension not served)"
                    continue
                path.write_bytes(data)
                ok, reason, info = check(path, ext_id)
                if not ok:
                    path.unlink(missing_ok=True)
                    if "not MV3" in reason or "differs" in reason:
                        break            # a retry would give the same file
            except urllib.error.HTTPError as e:
                reason = f"HTTP {e.code}"
            except Exception as e:
                reason = f"{type(e).__name__}: {str(e)[:80]}"
        if ok:
            reason = ""
            accepted.append((r, info))
        else:
            status = "failed"
        report.append({"ext_id": ext_id, "name": r["name"], "category": r["category"], "status": status,
                       "reason": reason, "attempts": attempts, "bytes": info.get("size", "")})
        print(f"[{n:>3}/{len(chosen)}] {status:<6} {ext_id} {r['name'][:34]:<34} {reason}", flush=True)

    with open(REPORT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(report[0]))
        w.writeheader()
        w.writerows(report)
    cols = ["ext_id", "name", "version", "users", "rating", "rating_count", "category", "label",
            "downloaded", "sha256", "source_url"]
    with open(MANIFEST_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r, info in accepted:
            w.writerow({"ext_id": r["ext_id"], "name": r["name"], "version": info["version"], "users": r["users"],
                        "rating": round(float(r["rating"]), 3), "rating_count": r["rating_count"],
                        "category": r["category"], "label": S.label_of(r), "downloaded": today,
                        "sha256": info["sha256"], "source_url": r["source_url"]})
    size = sum(i["size"] for _, i in accepted)
    print(f"\naccepted {len(accepted)} / {len(chosen)}; failed {len(chosen) - len(accepted)}; "
          f"{size / 2**20:.1f} MB; grey {sum(1 for r, _ in accepted if S.label_of(r) == 'grey')}")
    print(f"-> {MANIFEST_CSV}\n-> {REPORT_CSV}")


if __name__ == "__main__":
    main()
