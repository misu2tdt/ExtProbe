"""select_list.py -- apply the fixed criteria (CRITERIA.md) to candidates_listing.csv.

Deterministic, no hand picking. Prints the exclusion waterfall and the per-category result of
a dry run (assuming every download succeeds). The downloader (download_benign.py) walks the
same order and moves on to the next candidate of a category whenever one fails.

Order (CRITERIA.md section 3): categories round-robin in the order CWS lists them; inside a
category, users desc, then number of ratings desc, then ext_id asc; a category never exceeds
25% of the target.

Run: python eval/benign_ext/select_list.py [--target 300]
"""
import argparse
import csv
import math
import re
from collections import Counter, OrderedDict
from pathlib import Path

HERE = Path(__file__).resolve().parent
MIN_USERS, MIN_RATING, CAP_FRACTION = 100_000, 4.0, 0.25


def load():
    rows = list(csv.DictReader(open(HERE / "candidates_listing.csv", encoding="utf-8")))
    existing = {l.split("\t")[0] for l in open(HERE / "existing_ids.txt", encoding="utf-8").read().splitlines() if l}
    return rows, existing


def waterfall(rows, existing):
    left = rows
    steps = []

    def step(name, pred):
        nonlocal left
        kept = [r for r in left if pred(r)]
        steps.append((name, len(left) - len(kept), len(kept)))
        left = kept
    step("duplicate listing of an id already seen in another category", lambda r: not r["duplicate_of"])
    step(f"already in the 354 evaluation samples (by extension id)", lambda r: r["ext_id"] not in existing)
    step("no rating shown (too few ratings)", lambda r: r["rating"] != "")
    step("user count not shown anywhere", lambda r: r["users"] != "")
    step(f"users < {MIN_USERS:,}", lambda r: int(r["users"]) >= MIN_USERS)
    step(f"rating < {MIN_RATING} (unrounded value from the listing)", lambda r: float(r["rating"]) >= MIN_RATING)
    step("manifest_version != 3 (per listing; re-checked after download)", lambda r: r["manifest_version"] == "3")
    step("needs enterprise policy (manifest uses enterprise.* APIs)", lambda r: r["enterprise_perm"] != "True")
    return left, steps


GREY_RE = re.compile(r"coupon|cash\s?back", re.I)


def label_of(r):
    """CRITERIA.md decision 3: grey when the listing description mentions coupon / cash back / cashback."""
    return "grey" if GREY_RE.search(r.get("description", "")) else "benign"


def order_key(r):
    return (-int(r["users"]), -int(r["rating_count"] or 0), r["ext_id"])


def select(eligible, target):
    cats = list(OrderedDict.fromkeys(r["category"] for r in eligible))
    per = {c: sorted([r for r in eligible if r["category"] == c], key=order_key) for c in cats}
    cap = math.floor(CAP_FRACTION * target)
    chosen, i = [], 0
    while len(chosen) < target:
        progressed = False
        for c in cats:
            if len(chosen) >= target:
                break
            taken = sum(1 for r in chosen if r["category"] == c)
            if i < len(per[c]) and taken < cap:
                chosen.append(per[c][i])
                progressed = True
        if not progressed:
            break
        i += 1
    return chosen, per


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", type=int, default=300)
    a = ap.parse_args()
    rows, existing = load()
    eligible, steps = waterfall(rows, existing)
    print(f"listing: {len(rows)} entries")
    for name, dropped, left in steps:
        print(f"  - {name}: -{dropped} -> {left}")
    chosen, per = select(eligible, a.target)
    print(f"\neligible after filters: {len(eligible)}; dry-run selection for target {a.target}: {len(chosen)}")
    print(f"{'category':<34}{'listed':>7}{'eligible':>9}{'selected':>9}{'  users range (selected)'}")
    cnt = Counter(r["category"] for r in chosen)
    for c in per:
        sel = [r for r in chosen if r["category"] == c]
        rng = f"{int(sel[-1]['users']):,} .. {int(sel[0]['users']):,}" if sel else "-"
        print(f"{c:<34}{sum(1 for r in rows if r['category'] == c):>7}{len(per[c]):>9}{cnt[c]:>9}  {rng}")
    grp = Counter(r["group"] for r in chosen)
    print("by group:", dict(grp), "| largest category share:", f"{max(cnt.values()) / max(1, len(chosen)):.0%}")
    print("grey candidates (coupon/cashback by name):",
          [r["name"][:30] for r in chosen if any(k in r["name"].lower() for k in ("coupon", "cashback", "honey", "deal", "rakuten", "price"))])


if __name__ == "__main__":
    main()
