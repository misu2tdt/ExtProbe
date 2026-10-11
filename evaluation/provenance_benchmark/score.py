"""score.py -- score eval/provenance_benchmark/output/events.json against
ground_truth.json using the REAL pipeline's provenance decision (already computed at
collection time by sandbox/sensors/cdp_sw.py's CDP async-initiator call-stack walk,
_initiator_is_extension). This script does NOT re-derive attribution from raw CDP
data; it only joins two ALREADY-DECIDED fields exactly the way production code does.

The join rule below is not new logic - it is worker/risk.py:317-359
(detect_undeclared_domains)'s own rule, reproduced here only because that function
returns aggregate host SETS (from_sw | from_cs), not a per-request boolean, so it
cannot be called directly for a row-by-row results.csv. The DECISION (chrome-extension
present in the initiator stack, yes/no) still comes entirely from request_provenance /
origin, both produced upstream by the real sensor - nothing here inspects a CDP
initiator or a call stack.

  predicted_origin(request) =
    "extension" if request.origin == "service_worker"                            (risk.py:335-345)
    "extension" if request.origin == "page" and request_provenance[host] is True  (risk.py:347-351)
    "page"      otherwise

Run (offline, on the host - no Docker/Playwright needed):
    python eval/provenance_benchmark/score.py
"""
import csv
import json
from pathlib import Path

BENCH = Path(__file__).resolve().parent
GT_PATH = BENCH / "ground_truth.json"
EVENTS_PATH = BENCH / "output" / "events.json"
RESULTS_CSV = BENCH / "results.csv"
SUMMARY_JSON = BENCH / "summary.json"


def predicted_origin(req: dict, request_provenance: dict) -> str:
    """Mirrors worker/risk.py:317-359 exactly (see module docstring)."""
    if req.get("origin") == "service_worker":
        return "extension"
    if req.get("origin") == "page":
        host = req.get("host", "")
        if request_provenance.get(host) is True:
            return "extension"
    return "page"


def main():
    if not GT_PATH.exists():
        print(f"Khong thay {GT_PATH}")
        return
    if not EVENTS_PATH.exists():
        print(f"Khong thay {EVENTS_PATH}. Chay run_benchmark.py qua Docker truoc "
              f"(xem REPRODUCE.md muc 'Provenance attribution benchmark').")
        return

    ground_truth = json.loads(GT_PATH.read_text(encoding="utf-8"))
    ground_truth = {k: v for k, v in ground_truth.items() if not k.startswith("_")}
    events = json.loads(EVENTS_PATH.read_text(encoding="utf-8"))
    requests = events.get("network_requests", [])
    request_provenance = events.get("request_provenance", {}) or {}

    # Index observed requests by exact URL (ground truth is by-construction unique per URL).
    by_url = {}
    for r in requests:
        by_url.setdefault(r.get("url", ""), []).append(r)

    rows = []
    for url, gt in ground_truth.items():
        matches = by_url.get(url, [])
        if not matches:
            rows.append({
                "url": url, "source_type": gt["source_type"],
                "true_origin": gt["true_origin"], "predicted_origin": "NOT_OBSERVED",
                "correct": "", "note": "request never appeared in network_requests - "
                                        "see errors[] in events.json",
            })
            continue
        # Ground truth is by construction 1 GET per URL; if the sensor recorded more
        # than one (e.g. a retry), score the first and report the rest honestly.
        r = matches[0]
        pred = predicted_origin(r, request_provenance)
        rows.append({
            "url": url, "source_type": gt["source_type"],
            "true_origin": gt["true_origin"], "predicted_origin": pred,
            "correct": int(pred == gt["true_origin"]),
            "note": f"{len(matches)} observations" if len(matches) > 1 else "",
        })

    with open(RESULTS_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["url", "source_type", "true_origin",
                                           "predicted_origin", "correct", "note"])
        w.writeheader()
        w.writerows(rows)

    # ---- Binary task: "is this request extension-initiated?" ----
    scored = [r for r in rows if r["predicted_origin"] != "NOT_OBSERVED"]
    not_observed = [r for r in rows if r["predicted_origin"] == "NOT_OBSERVED"]

    def is_ext(v):
        return v == "extension"

    TP = sum(1 for r in scored if is_ext(r["true_origin"]) and is_ext(r["predicted_origin"]))
    FN = sum(1 for r in scored if is_ext(r["true_origin"]) and not is_ext(r["predicted_origin"]))
    FP = sum(1 for r in scored if not is_ext(r["true_origin"]) and is_ext(r["predicted_origin"]))
    TN = sum(1 for r in scored if not is_ext(r["true_origin"]) and not is_ext(r["predicted_origin"]))

    precision = TP / (TP + FP) if (TP + FP) else float("nan")
    recall = TP / (TP + FN) if (TP + FN) else float("nan")

    per_type = []
    gt_by_type = {v["source_type"]: v for v in ground_truth.values()}
    row_by_type = {r["source_type"]: r for r in rows}
    for source_type, gt in gt_by_type.items():
        r = row_by_type[source_type]
        matches_51 = (r["predicted_origin"] == gt["expected_prediction"]) \
            if r["predicted_origin"] != "NOT_OBSERVED" else None
        per_type.append({
            "source_type": source_type,
            "true_origin": gt["true_origin"],
            "predicted_origin": r["predicted_origin"],
            "expected_prediction_section_5_1": gt["expected_prediction"],
            "matches_5_1_expectation": matches_51,
        })

    summary = {
        "population": {"n_ground_truth": len(rows), "n_scored": len(scored),
                        "n_not_observed": len(not_observed)},
        "confusion": {"TP": TP, "FP": FP, "FN": FN, "TN": TN},
        "precision": None if precision != precision else round(precision, 4),
        "recall": None if recall != recall else round(recall, 4),
        "per_source_type": per_type,
        "not_observed": [r["url"] for r in not_observed],
    }
    with open(SUMMARY_JSON, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"\n[provenance_benchmark] n_ground_truth={len(rows)} n_scored={len(scored)} "
          f"n_not_observed={len(not_observed)}")
    if not_observed:
        print(f"  NOT_OBSERVED: {[r['url'] for r in not_observed]}")
    print(f"  confusion: TP={TP} FP={FP} FN={FN} TN={TN}")
    print(f"  precision={summary['precision']}  recall={summary['recall']}")

    print(f"\n{'source_type':<18} {'true':<10} {'predicted':<10} "
          f"{'matches 5.1 expectation?':<25}")
    for row in per_type:
        m = row["matches_5_1_expectation"]
        m_str = "N/A (not observed)" if m is None else ("YES" if m else "NO (surprise)")
        print(f"{row['source_type']:<18} {row['true_origin']:<10} "
              f"{row['predicted_origin']:<10} {m_str:<25}")

    print(f"\nOutput: {RESULTS_CSV}  |  {SUMMARY_JSON}")


if __name__ == "__main__":
    main()
