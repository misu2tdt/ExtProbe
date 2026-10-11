"""add_descriptions.py -- add the store's short description to the committed candidates_listing.csv
WITHOUT changing which extensions are candidates.

The grey label (CRITERIA.md section 4) needs the listing description, which the first listing
run did not store. The store's ranking drifts day to day, so re-running build_list.py would
change the candidate set; instead this reads a fresh listing (build_list.py --out FILE) and
copies only the description of the ids already in candidates_listing.csv. An id that is no
longer in the top 32 gets its description from the meta description of its public detail
page (2 s apart). The column description_source records which.

Run: python eval/benign_ext/build_list.py --out refresh.csv --no-existing
     python eval/benign_ext/add_descriptions.py --from refresh.csv
"""
import argparse
import csv
import html
import re
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
CSV_PATH = HERE / "candidates_listing.csv"
UA = "Mozilla/5.0 (compatible; extprobe-research/1.0; benign-extension survey; +<REPO_URL>)"


def detail_description(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"})
    page = urllib.request.urlopen(req, timeout=40).read().decode("utf-8")
    m = re.search(r'<meta[^>]+(?:name|property)="(?:og:)?description"[^>]+content="([^"]*)"', page) or \
        re.search(r'<meta[^>]+content="([^"]*)"[^>]+(?:name|property)="(?:og:)?description"', page)
    return re.sub(r"\s+", " ", html.unescape(m.group(1))).strip() if m else ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--from", dest="src", required=True, help="fresh listing CSV from build_list.py --out")
    a = ap.parse_args()
    rows = list(csv.DictReader(open(CSV_PATH, encoding="utf-8")))
    fresh = {r["ext_id"]: r for r in csv.DictReader(open(a.src, encoding="utf-8"))}
    n_list = n_detail = n_none = 0
    for r in rows:
        f = fresh.get(r["ext_id"])
        if f and f.get("description"):
            r["description"], r["description_source"] = f["description"], "listing (re-read)"
            n_list += 1
        else:
            time.sleep(2)
            d = detail_description(r["source_url"])
            r["description"], r["description_source"] = d, "detail page meta" if d else "not available"
            n_detail += bool(d)
            n_none += not d
            print(f"  detail page: {r['name'][:40]} -> {len(d)} chars")
    cols = list(rows[0].keys())
    cols = [c for c in cols if c not in ("description", "description_source")]
    cols[cols.index("fetched"):cols.index("fetched")] = ["description", "description_source"]
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    print(f"descriptions: {n_list} from the re-read listing, {n_detail} from detail pages, {n_none} missing -> {CSV_PATH}")


if __name__ == "__main__":
    main()
