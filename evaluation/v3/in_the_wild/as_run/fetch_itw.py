"""fetch_itw.py -- select and download the in-the-wild sets exactly as eval/v3/in_the_wild/CRITERIA.md fixes them.

  py -I eval/v3/in_the_wild/fetch_itw.py A --work <dir outside the repo> --sentry <malicious_extensions_detailed.csv>
  py -I eval/v3/in_the_wild/fetch_itw.py B --work <dir outside the repo> --sitemap <dir with shard_N.txt, one ID per line>

Packages go to <work>/A and <work>/B (never into the repository). Writes docs/samples_manifest_itw_A.csv or _B.csv
(ID, sha256, download time UTC, version, manifest_version, background; A adds Sentry reason / date / source and the
state of the Chrome Web Store page) and eval/v3/in_the_wild/selection_A.md / selection_B.md (counts per exclusion reason).
Checks the input hashes recorded in CRITERIA.md before doing anything. Does not run the sandbox.
"""
import argparse
import csv
import datetime
import glob
import hashlib
import importlib.util
import io
import json
import random
import re
import struct
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SENTRY_SHA = "c560a18ad879aeaca38758116acae1b41e6de096eadb7d89d6d8c07824cad2a0"
SITEMAP_SHA = "5c896d5dff3a4f6221b52adb142a41fc3155fe0f2bc696bee6bf49064cb5521d"
WIN_FROM, WIN_TO = datetime.date(2026, 8, 26), datetime.date(2026, 10, 9)
SEED = 2026
CRX = "https://clients2.google.com/service/update2/crx?response=redirect&prodversion=153.0&acceptformat=crx2,crx3&x=id%3D{}%26uc"
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0 Safari/537.36"}


def http(url, limit, timeout=90):
    for attempt in range(3):
        try:
            r = urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout)
            return r.status, r.geturl(), r.read(limit)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(30 * (attempt + 1))
                continue
            return e.code, url, b""
        except Exception:
            time.sleep(5)
    return "ERR", url, b""


def crx_zip(b):
    v = struct.unpack("<I", b[4:8])[0]
    if v == 3:
        return b[12 + struct.unpack("<I", b[8:12])[0]:]
    if v == 2:
        pl, sl = struct.unpack("<II", b[8:16])
        return b[16 + pl + sl:]
    raise ValueError("crx version")


def try_download(i, dst_dir):
    """-> dict(id, http, status in {ok, no_package, not_crx, unreadable}, sha256, time, version, mv, background)"""
    t = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    code, _, b = http(CRX.format(i), 300 * 10**6)
    r = {"ext_id": i, "http": code, "downloaded_utc": t, "status": "no_package", "sha256": "", "version": "",
         "manifest_version": "", "background": ""}
    if code == 200 and b[:4] == b"Cr24":
        r["sha256"] = hashlib.sha256(b).hexdigest()
        try:
            mf = json.loads(zipfile.ZipFile(io.BytesIO(crx_zip(b))).read("manifest.json").decode("utf-8-sig"))
            r["version"] = str(mf.get("version", ""))
            r["manifest_version"] = mf.get("manifest_version")
            bg = mf.get("background") or {}
            r["background"] = "service_worker" if bg.get("service_worker") else ("page_or_scripts" if bg else "none")
            r["status"] = "ok"
        except Exception:
            r["status"] = "unreadable"
        (dst_dir / f"{i}.crx").write_bytes(b)
    elif code == 200:
        r["status"] = "not_crx"
    return r


def cws_state(i):
    code, final, b = http(f"https://chromewebstore.google.com/detail/{i}", 3_000_000, 60)
    if code != 200:
        return "unknown"
    empty = "/detail/empty-title/" in final
    alive = b"Add to Chrome" in b and not empty
    return "alive" if alive else ("dead" if empty else "page_not_alive")


def known_ids():
    """dev malware, dev benign, benign test, MADWeb: the ID sets the CRITERIA exclude."""
    spec = importlib.util.spec_from_file_location("bl", REPO / "eval" / "v3" / "labels" / "build_labels.py")
    sys.path.insert(0, str(REPO / "eval" / "v3"))
    sys.path.insert(0, str(REPO / "eval"))
    bl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bl)

    def rd(p):
        return list(csv.DictReader(open(REPO / p, encoding="utf-8-sig")))
    out = {"dev malware": set(), "dev benign": set(), "test benign": set(), "MADWeb": set()}
    for r in rd("docs/samples_manifest.csv"):
        if r["label_raw"] == "malicious":
            out["dev malware"].add(r["ext_id"])
        else:
            p = (REPO / r["location"] / r["file"]).resolve()
            out["dev benign"].add((bl.crx_id(p) if p.exists() else None) or r["ext_id"])
    out["dev benign"] |= {r["ext_id"] for r in rd("docs/samples_manifest_benign_ext.csv")}
    out["test benign"] = {r["ext_id"] for r in rd("docs/samples_manifest_benign_test.csv")}
    out["MADWeb"] = {r["ext_id"] for r in rd("docs/samples_manifest_malware_test.csv")}
    return out


def sha_file(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def write_manifest(path, rows, cols):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, cols)
        w.writeheader()
        w.writerows(sorted(rows, key=lambda r: r["ext_id"]))


def set_a(work, sentry):
    if sha_file(sentry) != SENTRY_SHA:
        raise SystemExit("Sentry CSV hash differs from CRITERIA.md")
    rows = list(csv.DictReader(open(sentry, encoding="utf-8-sig")))
    inwin = [r for r in rows if WIN_FROM <= datetime.date.fromisoformat(r["insert_date_fmt"]) <= WIN_TO]
    pool = [r for r in inwin if r["store"] in ("Google Chrome", "Chrome")]
    by_id = {r["extension_id"]: r for r in pool}
    known = known_ids()
    allknown = set().union(*known.values())
    dst = work / "A"
    dst.mkdir(parents=True, exist_ok=True)
    cache = work / "attempts_A.json"
    done = json.loads(cache.read_text(encoding="utf-8")) if cache.exists() else {}
    for n, i in enumerate(sorted(by_id)):
        if i in done and (done[i]["status"] != "ok" or (dst / f"{i}.crx").exists()):
            continue
        done[i] = try_download(i, dst)
        time.sleep(0.5)
        if n % 50 == 0:
            cache.write_text(json.dumps(done), encoding="utf-8")
            print(n, "of", len(by_id), flush=True)
    cache.write_text(json.dumps(done), encoding="utf-8")
    ids = sorted(by_id)
    no_pkg = [i for i in ids if done[i]["status"] != "ok"]
    pkg = [i for i in ids if done[i]["status"] == "ok"]
    not_mv3 = [i for i in pkg if done[i]["manifest_version"] != 3]
    mv3 = [i for i in pkg if done[i]["manifest_version"] == 3]
    overlap = {k: [i for i in mv3 if i in v] for k, v in known.items()}
    kept = [i for i in mv3 if i not in allknown]
    # cap per insert_date: sorted ascending, shuffle with Random(2026), first 40
    per_day = {}
    for i in kept:
        per_day.setdefault(by_id[i]["insert_date_fmt"], []).append(i)
    capped, over_cap = [], 0
    for d in sorted(per_day):
        g = sorted(per_day[d])
        random.Random(SEED).shuffle(g)
        capped += g[:40]
        over_cap += max(0, len(g) - 40)
    capped = sorted(capped)
    cut300 = 0
    final = capped
    if len(capped) > 300:
        final = sorted(random.Random(SEED).sample(capped, 300))
        cut300 = len(capped) - 300
    for i in ids:                                  # leave only the selected packages in <work>/A
        if i not in final and (dst / f"{i}.crx").exists():
            (dst / f"{i}.crx").unlink()
    out = []
    for i in final:
        d = done[i]
        r = by_id[i]
        out.append({"ext_id": i, "sha256": d["sha256"], "downloaded_utc": d["downloaded_utc"], "version": d["version"],
                    "manifest_version": d["manifest_version"], "background": d["background"],
                    "sentry_reason": r["reason"], "sentry_date": r["insert_date_fmt"], "sentry_source": r["source"],
                    "cws_page": cws_state(i)})
        time.sleep(0.5)
    write_manifest(REPO / "docs" / "samples_manifest_itw_A.csv", out,
                   ["ext_id", "sha256", "downloaded_utc", "version", "manifest_version", "background", "sentry_reason",
                    "sentry_date", "sentry_source", "cws_page"])
    from collections import Counter
    L = ["# Set A (Sentry-recent): selection counts", "",
         f"Generated by `fetch_itw.py A`. Sentry CSV SHA-256 `{SENTRY_SHA}`; window {WIN_FROM}..{WIN_TO}.", "",
         "| step | n |", "|---|---|",
         f"| Sentry rows in the window | {len(inwin)} |",
         f"| of which Chrome (kept as population) | {len(pool)} |",
         f"| excluded: store other than Chrome | {len(inwin) - len(pool)} |",
         f"| excluded: no package from update2 | {len(no_pkg)} |",
         f"| downloaded | {len(pkg)} |",
         f"| excluded: manifest_version != 3 | {len(not_mv3)} |",
         f"| MV3 packages | {len(mv3)} |"]
    L += [f"| excluded: ID also in {k} | {len(v)} |" for k, v in overlap.items()]
    L += [f"| left after set exclusions | {len(kept)} |",
          f"| excluded: over 40 per insert_date | {over_cap} |",
          f"| left after the daily cap | {len(capped)} |",
          f"| excluded: random cut to 300 | {cut300} |",
          f"| **final Set A** | **{len(final)}** |", "",
          "Final set by Sentry reason: " + ", ".join(f"{k} {v}" for k, v in Counter(r["sentry_reason"] for r in out).most_common()) + ".",
          "Final set by background: " + ", ".join(f"{k} {v}" for k, v in Counter(r["background"] for r in out).most_common()) + ".",
          "Final set by CWS page: " + ", ".join(f"{k} {v}" for k, v in Counter(r["cws_page"] for r in out).most_common()) + ".",
          "Download HTTP codes (all attempts): " + ", ".join(f"{k} {v}" for k, v in Counter(str(done[i]["http"]) for i in ids).most_common()) + ".",
          f"Download window (UTC): {min(r['downloaded_utc'] for r in out)} .. {max(r['downloaded_utc'] for r in out)}."]
    (HERE / "selection_A.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))


def set_b(work, sitemap, sentry):
    ids = set()
    for f in glob.glob(str(Path(sitemap) / "shard_*.txt")):
        ids |= set(Path(f).read_text(encoding="utf-8").split())
    if hashlib.sha256("\n".join(sorted(ids)).encode()).hexdigest() != SITEMAP_SHA:
        raise SystemExit("sitemap ID list hash differs from CRITERIA.md")
    sentry_ids = {r["extension_id"] for r in csv.DictReader(open(sentry, encoding="utf-8-sig"))}
    known = known_ids()
    allknown = set().union(*known.values())
    cand = sorted(ids - sentry_ids - allknown)
    random.Random(SEED).shuffle(cand)
    dst = work / "B"
    dst.mkdir(parents=True, exist_ok=True)
    cache = work / "attempts_B.json"
    done = json.loads(cache.read_text(encoding="utf-8")) if cache.exists() else {}
    kept, attempts = [], []
    for n, i in enumerate(cand):
        if len(kept) >= 200:
            break
        if i not in done or (done[i]["status"] == "ok" and not (dst / f"{i}.crx").exists()):
            done[i] = try_download(i, dst)
            time.sleep(0.5)
        d = done[i]
        attempts.append(i)
        if d["status"] == "ok" and d["manifest_version"] == 3:
            kept.append(i)
        elif d["status"] == "ok" and (dst / f"{i}.crx").exists():
            (dst / f"{i}.crx").unlink()
        if n % 50 == 0:
            cache.write_text(json.dumps(done), encoding="utf-8")
            print(n, len(kept), flush=True)
    cache.write_text(json.dumps(done), encoding="utf-8")
    out = [{k: done[i][k] for k in ("ext_id", "sha256", "downloaded_utc", "version", "manifest_version", "background")} for i in kept]
    write_manifest(REPO / "docs" / "samples_manifest_itw_B.csv", out,
                   ["ext_id", "sha256", "downloaded_utc", "version", "manifest_version", "background"])
    from collections import Counter
    st = Counter(done[i]["status"] for i in attempts)
    mv = Counter(done[i]["manifest_version"] for i in attempts if done[i]["status"] == "ok")
    L = ["# Set B (CWS-random): selection counts", "",
         f"Generated by `fetch_itw.py B`. Sitemap ID list SHA-256 `{SITEMAP_SHA}`; Sentry CSV SHA-256 `{SENTRY_SHA}`.", "",
         "| step | n |", "|---|---|",
         f"| IDs in the sitemap snapshot | {len(ids)} |",
         f"| excluded before the draw: in the Sentry CSV | {len(ids & sentry_ids)} |"]
    L += [f"| excluded before the draw: in {k} | {len(ids & v)} |" for k, v in known.items()]
    L += [f"| draw population | {len(cand)} |",
          f"| download attempts (in shuffle order) | {len(attempts)} |",
          f"| no package from update2 | {st['no_package'] + st['not_crx']} |",
          f"| unreadable package | {st['unreadable']} |",
          f"| downloaded and readable | {st['ok']} |",
          f"| of which manifest_version != 3 | {st['ok'] - len(kept)} ({', '.join(f'MV{k}: {v}' for k, v in sorted(mv.items(), key=str))}) |",
          f"| **final Set B (MV3)** | **{len(kept)}** |", "",
          "Final set by background: " + ", ".join(f"{k} {v}" for k, v in Counter(r["background"] for r in out).most_common()) + ".",
          f"Download window (UTC): {min(r['downloaded_utc'] for r in out)} .. {max(r['downloaded_utc'] for r in out)}."]
    (HERE / "selection_B.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("which", choices=["A", "B"])
    ap.add_argument("--work", required=True)
    ap.add_argument("--sentry", required=True)
    ap.add_argument("--sitemap")
    a = ap.parse_args()
    work = Path(a.work)
    work.mkdir(parents=True, exist_ok=True)
    if a.which == "A":
        set_a(work, a.sentry)
    else:
        set_b(work, a.sitemap, a.sentry)


if __name__ == "__main__":
    main()
