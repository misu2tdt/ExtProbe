"""download_test.py -- download and check the held-out benign test set (eval/v3/TEST_SET_CRITERIA.md).

Takes exactly the ids of eval/v3/test_set/selected_test.csv (labels already fixed there), downloads
each .crx through the public update endpoint into samples/benign_test/<ext_id>.crx (gitignored: the
files are never committed), at most one request every 2 s. Mechanics and checks are those of
eval/benign_ext/download_benign.py (imported): 3 attempts; CRX magic, readable manifest.json,
manifest_version 3, header id equals the listing id. A file that fails is deleted, recorded with
its reason and NOT replaced. Nothing is run in the sandbox.

Writes (committed):
  docs/samples_manifest_benign_test.csv   accepted files: ext_id, name, version, users, rating,
                                          rating_count, category, label, downloaded, sha256, source_url
  eval/v3/test_set/download_report.csv    one row per selected id: status, reason, attempts, bytes
Resumable: a valid file already in samples/benign_test/ is checked, not downloaded again.

Run: py eval/v3/test_set/download_test.py [--limit N]
"""
import argparse
import csv
import hashlib
import sys
import time
import urllib.error
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO / "eval" / "benign_ext"))
import download_benign as D  # noqa: E402

DEST = REPO / "samples" / "benign_test"
MANIFEST_CSV = REPO / "docs" / "samples_manifest_benign_test.csv"
REPORT_CSV = HERE / "download_report.csv"
SELECTED = HERE / "selected_test.csv"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="only the first N ids (testing)")
    a = ap.parse_args()
    chosen = list(csv.DictReader(open(SELECTED, encoding="utf-8")))
    ids_sha = hashlib.sha256(("\n".join(sorted(r["ext_id"] for r in chosen)) + "\n").encode()).hexdigest()
    recorded = (HERE / "selected_test.sha256").read_text(encoding="utf-8").split()[0]
    if ids_sha != recorded:
        sys.exit(f"selected_test.csv does not match selected_test.sha256 ({ids_sha} != {recorded})")
    if a.limit:
        chosen = chosen[:a.limit]
    DEST.mkdir(parents=True, exist_ok=True)
    today = date.today().isoformat()
    report, accepted = [], []
    last_request = 0.0
    for n, r in enumerate(chosen, 1):
        ext_id, path = r["ext_id"], DEST / f"{r['ext_id']}.crx"
        status, reason, attempts, info = "ok", "", 0, {}
        ok = False
        if path.exists():
            ok, reason, info = D.check(path, ext_id)
            if not ok:
                path.unlink()
        while not ok and attempts <= D.RETRIES:
            attempts += 1
            wait = D.DELAY_S - (time.monotonic() - last_request)
            if wait > 0:
                time.sleep(wait)
            last_request = time.monotonic()
            try:
                data = D.fetch(ext_id)
                if not data:
                    reason = "empty response (extension not served)"
                    continue
                path.write_bytes(data)
                ok, reason, info = D.check(path, ext_id)
                if not ok:
                    path.unlink(missing_ok=True)
                    if "not MV3" in reason or "differs" in reason:
                        break
            except urllib.error.HTTPError as e:
                reason = f"HTTP {e.code}"
            except Exception as e:
                reason = f"{type(e).__name__}: {str(e)[:80]}"
        if ok:
            reason = ""
            accepted.append((r, info))
        else:
            status = "failed"
        report.append({"ext_id": ext_id, "name": r["name"], "category": r["category"], "label": r["label"],
                       "status": status, "reason": reason, "attempts": attempts, "bytes": info.get("size", "")})
        print(f"[{n:>3}/{len(chosen)}] {status:<6} {ext_id} {r['name'][:34]:<34} {reason}", flush=True)

    with open(REPORT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(report[0]))
        w.writeheader()
        w.writerows(report)
    cols = ["ext_id", "name", "version", "users", "rating", "rating_count", "category", "label", "downloaded",
            "sha256", "source_url"]
    with open(MANIFEST_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r, info in accepted:
            w.writerow({"ext_id": r["ext_id"], "name": r["name"], "version": info["version"], "users": r["users"],
                        "rating": r["rating"], "rating_count": r["rating_count"], "category": r["category"],
                        "label": r["label"], "downloaded": today, "sha256": info["sha256"],
                        "source_url": r["source_url"]})
    size = sum(i["size"] for _, i in accepted)
    print(f"\naccepted {len(accepted)} / {len(chosen)}; failed {len(chosen) - len(accepted)}; {size / 2**20:.1f} MB; "
          f"grey {sum(1 for r, _ in accepted if r['label'] == 'grey')}")
    print(f"-> {MANIFEST_CSV}\n-> {REPORT_CSV}")


if __name__ == "__main__":
    main()
