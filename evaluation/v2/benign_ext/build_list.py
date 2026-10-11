"""build_list.py -- list candidate benign extensions from the public Chrome Web Store category pages.

Step 1 of the benign-extension expansion (criteria: eval/benign_ext/CRITERIA.md). It only
reads the public category pages -- no .crx is downloaded here.

Source: https://chromewebstore.google.com/category/extensions/<category>. Each of the 18
leaf categories (read from the page itself) is served with its top 32 extensions ordered by
number of users, and every entry carries the id, name, rating, number of ratings, category,
users and the manifest. robots.txt of the site does not disallow /category/. Requests are
spaced 2 s apart and identify themselves.

Also computes the real extension id of every file in the 354 evaluation samples (from the
.crx header), so that those can be excluded (benign samples are named by product, not id).

Writes (committed): eval/benign_ext/candidates_listing.csv  (all listed entries, with the
                    leaf category, rank in that category and fetch date)
Run: python eval/benign_ext/build_list.py
"""
import csv
import hashlib
import json
import re
import struct
import time
import urllib.request
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent / "candidates_listing.csv"
BASE = "https://chromewebstore.google.com/category/extensions/"
UA = "Mozilla/5.0 (compatible; extprobe-research/1.0; benign-extension survey; +<REPO_URL>)"
DELAY_S = 2.0
ID_RE = re.compile(r"[a-p]{32}")


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"})
    with urllib.request.urlopen(req, timeout=40) as r:
        return r.read().decode("utf-8")


def ds_blocks(html):
    return {m.group(1): json.loads(m.group(2)) for m in
            re.finditer(r"AF_initDataCallback\(\{key: .(ds:\d+).*?data:(.*?), sideChannel", html, re.S)}


def leaf_categories(html):
    """Leaf category slugs listed on any category page (e.g. 'productivity/tools')."""
    return [c[5] for c in ds_blocks(html)["ds:0"][0][4] if isinstance(c, list) and len(c) > 5 and "/" in str(c[5])]


def listed_items(html):
    def walk(o):
        if isinstance(o, list):
            if o and isinstance(o[0], str) and ID_RE.fullmatch(o[0]):
                yield o
            for x in o:
                yield from walk(x)
    return list(walk(ds_blocks(html)["ds:1"]))


def parse_item(it):
    manifest = next((x for x in it if isinstance(x, str) and "manifest_version" in x), "")
    mv = re.search(r'"manifest_version"\s*:\s*(\d)', manifest)
    ver = re.search(r'"version"\s*:\s*"([^"]+)"', manifest)
    return {"ext_id": it[0], "name": it[2], "rating": it[3], "rating_count": it[4], "users": it[14],
            "description": re.sub(r"\s+", " ", it[6] or "").strip() if isinstance(it[6], str) else "",
            "manifest_version": int(mv.group(1)) if mv else "", "version": ver.group(1) if ver else "",
            "enterprise_perm": bool(re.search(r'"enterprise\.', manifest))}


# ---- ids of the files already in the evaluation set -----------------------------------
def crx_id(path):
    """Chrome extension id of a .crx (CRX2 public key, or CRX3 signed header's crx_id)."""
    b = path.read_bytes()
    if b[:4] != b"Cr24":
        return None
    ver = struct.unpack("<I", b[4:8])[0]
    if ver == 2:
        klen = struct.unpack("<I", b[8:12])[0]
        key = b[16:16 + klen]
        raw = hashlib.sha256(key).digest()[:16]
    elif ver == 3:
        hlen = struct.unpack("<I", b[8:12])[0]
        raw = _crx3_id(b[12:12 + hlen])
    else:
        return None
    return "".join(chr(ord("a") + (c >> 4)) + chr(ord("a") + (c & 15)) for c in raw) if raw else None


def _varint(buf, i):
    n = shift = 0
    while True:
        c = buf[i]
        i += 1
        n |= (c & 0x7F) << shift
        if not c & 0x80:
            return n, i
        shift += 7


def _fields(buf):
    i = 0
    while i < len(buf):
        key, i = _varint(buf, i)
        field, wt = key >> 3, key & 7
        if wt == 2:
            n, i = _varint(buf, i)
            yield field, buf[i:i + n]
            i += n
        elif wt == 0:
            _, i = _varint(buf, i)
        elif wt == 1:
            i += 8
        elif wt == 5:
            i += 4
        else:
            return


def _crx3_id(header):
    for f, v in _fields(header):
        if f == 10000:                       # signed_header_data
            for g, w in _fields(v):
                if g == 1:                   # crx_id (16 bytes)
                    return w
    return None


def existing_ids():
    ids = {}
    dirs = [REPO / "samples" / "malware", REPO / "samples" / "benign", REPO.parent / "sample" / "cws_benign_crx"]
    for d in dirs:
        for p in sorted(d.glob("*.crx")):
            i = crx_id(p)
            ids[i or f"?{p.name}"] = p.name
    return ids


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(OUT), help="CSV to write (default: candidates_listing.csv)")
    ap.add_argument("--no-existing", action="store_true", help="skip the existing_ids.txt step")
    args = ap.parse_args()
    out_path = Path(args.out)
    today = date.today().isoformat()
    first = fetch(BASE + "productivity/tools")
    cats = leaf_categories(first)
    print(f"{len(cats)} leaf categories: {cats}")
    rows, seen = [], {}
    for n, cat in enumerate(cats):
        html = first if cat == "productivity/tools" else None
        if html is None:
            time.sleep(DELAY_S)
            html = fetch(BASE + cat)
        items = listed_items(html)
        print(f"  {cat:<34} {len(items)} listed")
        for rank, it in enumerate(items, 1):
            d = parse_item(it)
            d.update(category=cat, group=cat.split("/")[0], rank_in_category=rank, fetched=today,
                     source_url=f"https://chromewebstore.google.com/detail/{it[0]}")
            if it[0] in seen:
                d["duplicate_of"] = seen[it[0]]
            else:
                seen[it[0]] = cat
            rows.append(d)
    # The category card hides the user count of some extensions (the rank still reflects it).
    # For exactly those entries read it from the public detail page ("12,000,000 users").
    for d in rows:
        d["users_source"] = "listing"
        if d["users"] in ("", None) and d["rating"] not in ("", None) and not d.get("duplicate_of"):
            time.sleep(DELAY_S)
            try:
                page = fetch(d["source_url"])
                m = re.search(r"([\d,]+)\+?\s*users", page)
                d["users"] = int(m.group(1).replace(",", "")) if m else ""
                d["users_source"] = "detail page" if m else "not shown"
            except Exception as e:
                d["users_source"] = f"detail page error: {type(e).__name__}"
            print(f"  users from detail page: {d['name'][:34]:<34} -> {d['users']!r} ({d['users_source']})")
    cols = ["ext_id", "name", "category", "group", "rank_in_category", "users", "users_source", "rating",
            "rating_count", "manifest_version", "version", "enterprise_perm", "description", "fetched",
            "source_url", "duplicate_of"]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} entries ({len(seen)} distinct ids) -> {out_path}")
    if args.no_existing:
        return
    ex = existing_ids()
    unknown = [k for k in ex if k.startswith("?")]
    print(f"existing samples: {len(ex)} ids computed ({len(unknown)} unreadable); "
          f"in listing: {sorted(set(ex) & set(seen))}")
    (Path(__file__).resolve().parent / "existing_ids.txt").write_text(
        "\n".join(f"{i}\t{n}" for i, n in sorted(ex.items())) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
