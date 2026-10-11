"""build_test_list.py -- candidate list and selection of the held-out benign test set
(eval/v3/TEST_SET_CRITERIA.md, procedure of eval/benign_ext/CRITERIA.md).

Why the whole category: the development listing read the top 32 of each category page, and its 256
qualifying extensions are all in the development set. A fresh top-32 listing adds only 12 unseen
ones, so, as TEST_SET_CRITERIA.md allows, the pool is extended "with the same listing
procedure": the same 18 category pages, the same data request the page itself issues
(RPC `zTyKYc`, declared in the page's AF_dataServiceRequests as `[[null,[[3,<category>,null,null,2,[32]]]]]`),
with the page size 32 replaced by 1000 and the continuation token followed to the end (a category has
up to tens of thousands of entries; the store's order is NOT by users beyond the first ~30, entries with >= 100,000 users
appear all the way down, so any fixed depth would truncate the pool). The category is read page by page with the continuation token the store returns
(the token goes into the size array: [size, token]). Fields, fetch fixes and filters are those of
build_list.py / select_list.py. robots.txt does not disallow it; requests are 2 s apart.

Steps
 1. list   : the 18 categories, every entry the store lists (rank kept).
             Entries whose card hides the user count and that pass every other rule get the count
             from the detail page, as in build_list.py; if it is not shown there, they are excluded.
 2. filter : select_list.waterfall (users >= 100,000, rating >= 4.0 unrounded, MV3, not enterprise),
             plus exclusion of every id in the 313 malware, the 41 older benign files, and the
             256-extension development set (listing-eligible ids of candidates_listing.csv, whether
             or not their download succeeded, and the accepted manifest).
 3. select : stratified by category, seeded (2027), target 200 (minimum 150):
             quota_c = largest-remainder share of the target in proportion to the development
             set's category counts (docs/samples_manifest_benign_ext.csv), at most 25 % of the
             target per category; a category with fewer eligible than its quota gives all it has
             and the shortfall is re-distributed by the same proportions to categories with
             capacity. Inside a category: random.Random(2027).sample over ids sorted ascending.
 4. label  : benign / grey from the listing description with select_list.label_of (coupon /
             cash back / cashback), BEFORE any download or run.

Writes (committed): candidates_listing_test.csv (entries whose store card shows >= 100,000 users),
                    selected_test.csv, selected_test.sha256, SELECTION.md.
Local, gitignored: candidates_listing_test_full.csv (every listed entry; its SHA-256 is in SELECTION.md),
candidates_listing_test_raw.csv (checkpoint written right after the listing, before the detail pages).
Committed: detail_page_users.json (user counts read from detail pages for entries whose card hides them).
Run: py eval/v3/test_set/build_test_list.py [--target 200]
"""
import argparse
import csv
import hashlib
import json
import random
import re
import sys
import threading
import time
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO / "eval" / "benign_ext"))
import build_list as B  # noqa: E402
import select_list as S  # noqa: E402

RPC = "zTyKYc"
SEED = 2027
CAP_FRACTION = 0.25
MIN_TARGET = 150
DEV_MANIFEST = REPO / "docs" / "samples_manifest_benign_ext.csv"
COLS = ["ext_id", "name", "category", "group", "rank_in_category", "users", "users_source", "rating", "rating_count",
        "manifest_version", "version", "enterprise_perm", "description", "fetched", "source_url", "duplicate_of"]


def rpc_page(cat, size, token, bl, sid):
    """One page of a category: ([items], next_token or None). The token sits in the size array: [size, token]."""
    inner = [[None, [[3, cat, None, None, 2, [size] if token is None else [size, token]]]]]
    freq = json.dumps([[[RPC, json.dumps(inner), None, "generic"]]])
    url = ("https://chromewebstore.google.com/_/ChromeWebStoreConsumerFeUi/data/batchexecute?" +
           urllib.parse.urlencode({"rpcids": RPC, "source-path": "/category/extensions/" + cat, "bl": bl,
                                   "f.sid": sid, "hl": "en", "_reqid": "100001", "rt": "c"}))
    req = urllib.request.Request(url, data=urllib.parse.urlencode({"f.req": freq}).encode(),
                                 headers={"User-Agent": B.UA, "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"})
    raw = urllib.request.urlopen(req, timeout=180).read().decode("utf-8")
    frame = next(json.loads(l) for l in raw.split("\n") if l.startswith('[["wrb.fr"'))
    data = json.loads(frame[0][2])
    items = []

    def walk(o):
        if isinstance(o, list):
            if o and isinstance(o[0], str) and B.ID_RE.fullmatch(o[0]):
                items.append(o)
            for x in o:
                walk(x)
    walk(data)
    nxt = data[2][0] if isinstance(data, list) and len(data) > 2 and isinstance(data[2], list) and data[2] else None
    return items, (nxt if isinstance(nxt, str) and nxt else None)


def rpc_items(cat, bl, sid, page=1000):
    """Every entry of a category, page by page (~2 s apart)."""
    out, seen, token = [], set(), None
    while True:
        items, token = rpc_page(cat, page, token, bl, sid)
        new = [i for i in items if i[0] not in seen]
        seen.update(i[0] for i in new)
        out += new
        if not token or not new:
            return out
        time.sleep(B.DELAY_S)


def build_listing(page):
    today = date.today().isoformat()
    first = B.fetch(B.BASE + "productivity/tools")
    cats = B.leaf_categories(first)
    bl = re.search(r'"cfb2h":"([^"]+)"', first).group(1)
    sid = re.search(r'"FdrFJe":"([^"]+)"', first).group(1)
    rows, seen = [], {}
    for cat in cats:
        time.sleep(B.DELAY_S)
        items = rpc_items(cat, bl, sid, page)
        print(f"  {cat:<34} {len(items)} listed", flush=True)
        for rank, it in enumerate(items, 1):
            d = B.parse_item(it)
            d.update(category=cat, group=cat.split("/")[0], rank_in_category=rank, fetched=today,
                     source_url=f"https://chromewebstore.google.com/detail/{it[0]}")
            if it[0] in seen:
                d["duplicate_of"] = seen[it[0]]
            else:
                seen[it[0]] = cat
            rows.append(d)
    return rows


def fill_hidden_users(rows, excluded_ids, cache_path):
    """Detail-page user count for entries that would otherwise qualify (as build_list.py does).

    Resumable: results are cached in cache_path (id -> users or "" when the page does not show them).
    Requests start at least 2 s apart overall (a few overlap in flight)."""
    cache = json.loads(cache_path.read_text(encoding="utf-8")) if cache_path.exists() else {}
    todo = [d for d in rows if d["users"] in ("", None) and d["rating"] not in ("", None) and not d.get("duplicate_of")
            and d["ext_id"] not in excluded_ids and d["manifest_version"] == 3 and float(d["rating"]) >= S.MIN_RATING]
    pending = [d for d in todo if d["ext_id"] not in cache]
    print(f"detail pages needed: {len(todo)} ({len(todo) - len(pending)} cached, {len(pending)} to fetch)", flush=True)
    lock, state = threading.Lock(), {"next": time.monotonic(), "n": 0}

    def one(d):
        with lock:
            wait = state["next"] - time.monotonic()
            state["next"] = max(state["next"], time.monotonic()) + B.DELAY_S
        if wait > 0:
            time.sleep(wait)
        try:
            page = B.fetch(d["source_url"])
            m = re.search(r"(\d[\d,]*)\+?\s*users", page)         # needs a digit: prose like ", users" is not a count
            res = int(m.group(1).replace(",", "")) if m else ""
        except Exception as e:
            res = f"error:{type(e).__name__}"
        with lock:
            cache[d["ext_id"]] = res
            state["n"] += 1
            if state["n"] % 50 == 0:
                cache_path.write_text(json.dumps(cache), encoding="utf-8")
                print(f"  detail pages {state['n']}/{len(pending)}", flush=True)

    if pending:
        with ThreadPoolExecutor(3) as ex:
            list(ex.map(one, pending))
        cache_path.write_text(json.dumps(cache), encoding="utf-8")
    for d in rows:
        d["users_source"] = "listing"
        if d["ext_id"] in cache and d["users"] in ("", None):
            v = cache[d["ext_id"]]
            if isinstance(v, int):
                d["users"], d["users_source"] = v, "detail page"
            else:
                d["users_source"] = "not shown" if v == "" else f"detail page {v}"
    return rows


def excluded_ids():
    ex = set(B.existing_ids())                                    # 313 malware + 41 benign (ids from .crx headers)
    dev_rows = list(csv.DictReader(open(REPO / "eval" / "benign_ext" / "candidates_listing.csv", encoding="utf-8")))
    dev_existing = {l.split("\t")[0] for l in (REPO / "eval/benign_ext/existing_ids.txt").read_text(encoding="utf-8").splitlines() if l}
    dev_elig, _ = S.waterfall(dev_rows, dev_existing)
    ex |= {r["ext_id"] for r in dev_elig}                         # the 256 development extensions
    ex |= {r["ext_id"] for r in csv.DictReader(open(DEV_MANIFEST, encoding="utf-8"))}
    return {i for i in ex if not i.startswith("?")}


def quotas(eligible_by_cat, dev_counts, target):
    cats = list(eligible_by_cat)
    cap = int(CAP_FRACTION * target)
    q = {c: 0 for c in cats}
    room = {c: min(len(eligible_by_cat[c]), cap) for c in cats}
    left = min(target, sum(room.values()))
    while left > 0:
        active = [c for c in cats if q[c] < room[c]]
        w = {c: dev_counts.get(c, 0) or 0.5 for c in active}          # a category absent from the dev set still gets a tiny weight
        tot = sum(w.values())
        want = {c: left * w[c] / tot for c in active}
        base = {c: min(int(want[c]), room[c] - q[c]) for c in active}
        for c in active:
            q[c] += base[c]
        left -= sum(base.values())
        if left <= 0:
            break
        rest = sorted((c for c in active if q[c] < room[c]), key=lambda c: (-(want[c] - int(want[c])), c))
        for c in rest[:left]:
            q[c] += 1
            left -= 1
            if left <= 0:
                break
    return q


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--page", type=int, default=1000, help="entries per request")
    ap.add_argument("--target", type=int, default=200)
    ap.add_argument("--reuse", action="store_true", help="re-select from the local candidates_listing_test_full.csv")
    a = ap.parse_args()
    ex = excluded_ids()
    print(f"excluded ids (malware + older benign + development set): {len(ex)}")
    lst = HERE / "candidates_listing_test_full.csv"
    if a.reuse and lst.exists():
        rows = list(csv.DictReader(open(lst, encoding="utf-8")))
    else:
        raw_path = HERE / "candidates_listing_test_raw.csv"
        if raw_path.exists():                                         # checkpoint of an interrupted run
            rows = list(csv.DictReader(open(raw_path, encoding="utf-8")))
            for d in rows:
                d["manifest_version"] = int(d["manifest_version"]) if d["manifest_version"] else ""
                d["users"] = int(d["users"]) if d["users"] else ""
                d["rating"] = float(d["rating"]) if d["rating"] else ""
        else:
            rows = build_listing(a.page)
            with open(raw_path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=COLS, extrasaction="ignore")
                w.writeheader()
                w.writerows(rows)
        rows = fill_hidden_users(rows, ex, HERE / "detail_page_users.json")
        with open(lst, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=COLS, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        rows = list(csv.DictReader(open(lst, encoding="utf-8")))          # same types as a later --reuse run
    fetched = rows[0]["fetched"]
    eligible, steps = S.waterfall(rows, ex)
    full_sha = hashlib.sha256(lst.read_bytes()).hexdigest()
    total_by_cat = Counter(r["category"] for r in rows)
    big = [r for r in rows if r["users"] != "" and int(r["users"]) >= S.MIN_USERS]
    with open(HERE / "candidates_listing_test.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLS, extrasaction="ignore")
        w.writeheader()
        w.writerows(big)
    print(f"listing: {len(rows)} entries (fetched {fetched}); {len(big)} show >= {S.MIN_USERS:,} users")
    for name, dropped, left in steps:
        print(f"  - {name}: -{dropped} -> {left}")
    dev_counts = Counter(r["category"] for r in csv.DictReader(open(DEV_MANIFEST, encoding="utf-8")))
    cats = list(dict.fromkeys(r["category"] for r in rows))
    by_cat = {c: sorted((r for r in eligible if r["category"] == c), key=lambda r: r["ext_id"]) for c in cats}
    q = quotas(by_cat, dev_counts, a.target)
    rng = random.Random(SEED)
    chosen = []
    for c in cats:
        chosen += rng.sample(by_cat[c], q[c]) if q[c] else []
    chosen.sort(key=lambda r: (cats.index(r["category"]), r["ext_id"]))
    total = len(chosen)
    print(f"eligible {len(eligible)}; selected {total} (target {a.target}, minimum {MIN_TARGET})")
    if total < MIN_TARGET:
        print("BELOW THE MINIMUM: the pool must be extended before this set can be used")
    with open(HERE / "selected_test.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ext_id", "name", "category", "label", "users", "rating", "rating_count", "rank_in_category",
                    "listing_fetched", "source_url"])
        for r in chosen:
            w.writerow([r["ext_id"], r["name"], r["category"], S.label_of(r), r["users"], round(float(r["rating"]), 3),
                        r["rating_count"], r["rank_in_category"], r["fetched"], r["source_url"]])
    ids = "\n".join(sorted(r["ext_id"] for r in chosen)) + "\n"
    digest = hashlib.sha256(ids.encode()).hexdigest()
    (HERE / "selected_test.sha256").write_text(f"{digest}  sorted ids of selected_test.csv ({total}, one per line, LF)\n",
                                               encoding="utf-8", newline="\n")
    cnt = Counter(r["category"] for r in chosen)
    grey = Counter(r["category"] for r in chosen if S.label_of(r) == "grey")
    L = [f"# Held-out benign test set: listing and selection ({fetched})", "",
         "Generated by `build_test_list.py`; criteria in `../TEST_SET_CRITERIA.md`. Labels come from the listing "
         "description (coupon / cash back / cashback → grey) and were assigned before any download or run.", "",
         f"- Listing: every entry of the 18 category pages, {len(rows)} entries, fetched {fetched} "
         "(SHA-256 of the local full listing `{full_sha}`; `candidates_listing_test.csv` keeps the {len(big)} entries "
         "that show at least 100,000 users). The development listing read the top 32 of each page; a fresh top-32 "
         "listing adds only 12 unseen eligible extensions, so the pool was extended with the same data request at a "
         "page size and the continuation token followed to the end (see the script header).",
         f"- Selection: seed {SEED}, target {a.target}, selected **{total}**; "
         f"SHA-256 of the sorted id list: `{digest}`.", "", "## Exclusion waterfall", "",
         "| step | dropped | left |", "|---|---|---|"]
    L += [f"| {n} | {d} | {l} |" for n, d, l in steps]
    L += ["", f"Excluded ids (malware, older benign, development set): {len(ex)}.", "",
          "## Per category", "", "| category | listed | development set | eligible | quota | selected | grey |", "|---|---|---|---|---|---|---|"]
    for c in cats:
        L.append(f"| {c} | {total_by_cat[c]} | {dev_counts.get(c, 0)} | {len(by_cat[c])} | {q[c]} | {cnt[c]} | {grey[c]} |")
    L.append(f"| **total** | {len(rows)} | {sum(dev_counts.values())} | {len(eligible)} | {sum(q.values())} | **{total}** | **{sum(grey.values())}** |")
    (HERE / "SELECTION.md").write_text("\n".join(L) + "\n", encoding="utf-8", newline="\n")
    print("\n".join(L[-(len(cats) + len(steps) + 8):]))


if __name__ == "__main__":
    main()
