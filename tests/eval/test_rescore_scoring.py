"""eval/rescore.py --scoring auto|legacy on a throw-away results folder.

Two traces of the same extension behaviour: one recorded by the corpus profile, one by v2
(page-initiated regular requests + an affiliate tag added to a served shopping link).
auto   -> corpus trace: beaconing; v2 trace: no beaconing (v2 rule), affiliate_hijack (+40).
legacy -> both traces scored like the corpus one; written to summary_legacy.csv, and the
          run's summary.csv is not touched.

Run: python tests/eval/test_rescore_scoring.py   or   pytest tests/eval
"""
import csv
import json
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "eval"))
import rescore  # noqa: E402

SHOP = "shop.bench.test"


def trace(profile):
    ev = {"manifest": {"name": "bench", "manifest_version": 3},
          "run_status": {"status": "complete"},
          "network_requests": [{"url": f"https://video.bench.test/v?n={i}", "method": "POST",
                                "origin": "page", "t": t} for i, t in enumerate([3.0, 10.0, 17.0, 24.0])],
          "target_matched_hosts": [SHOP], "target_matched_visited": [SHOP],
          "target_page_probe": [{"host": SHOP, "hrefs_served": [f"https://{SHOP}/dp/TEST0001"],
                                 "hrefs": [f"https://{SHOP}/dp/TEST0001?tag=x-20"], "clicks": []}]}
    if profile:
        ev["startup"] = {"profile": profile}
    return ev


def run(results, *args):
    argv = sys.argv
    sys.argv = ["rescore.py", str(results), *args]
    try:
        rescore.main()
    finally:
        sys.argv = argv


def read(path):
    return {r["ext_id"]: r for r in csv.DictReader(open(path, encoding="utf-8"))}


def test_rescore_scoring_modes():
    tmp = Path(tempfile.mkdtemp())
    try:
        for name, profile in (("a_corpus", None), ("b_v2", "v2")):
            (tmp / name / "output").mkdir(parents=True)
            (tmp / name / "output" / "events.json").write_text(json.dumps(trace(profile)), encoding="utf-8")
        run(tmp)
        auto = read(tmp / "summary.csv")
        assert auto["a_corpus"]["beaconing"] == "1" and auto["a_corpus"]["dynamic_score"] == "8"
        assert auto["b_v2"]["beaconing"] == "0" and auto["b_v2"]["dynamic_score"] == "40"  # affiliate_hijack
        before = (tmp / "summary.csv").read_bytes()

        run(tmp, "--scoring", "legacy")
        legacy = read(tmp / "summary_legacy.csv")
        for eid in ("a_corpus", "b_v2"):
            assert legacy[eid]["beaconing"] == "1" and legacy[eid]["dynamic_score"] == "8", legacy[eid]
        assert legacy["a_corpus"]["risk"] == auto["a_corpus"]["risk"]   # corpus trace: same either way
        assert (tmp / "summary.csv").read_bytes() == before                # B's summary untouched
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    test_rescore_scoring_modes()
    print("PASS test_rescore_scoring_modes")
