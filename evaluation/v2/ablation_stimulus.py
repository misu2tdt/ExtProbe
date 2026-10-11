"""
ablation_stimulus.py -- OFFLINE-SLICE ablation do dong gop BIEN cua stimulus phase
`target_matched` (contribution C2, paper Sec 5.3).

PHUONG PHAP: khong re-collect. Voi moi mau da co eval/results/<id>/output/events.json,
dung lai file DA COLLECT MOT LAN, tao 4 cau hinh TICH LUY bang cach LOC events theo
prefix cua PHASE_NAMES (xem sandbox/config.py):
  A = {load}
  B = {load, honeypot_pages}
  C = {load, honeypot_pages, target_matched}
  D = {load, honeypot_pages, target_matched, extension_pages, delayed_observation} (=full)
Roi goi THANG worker/risk.py (KHONG sua file do) tren moi cau hinh.

Prefix-filter hop le vi 3 kenh co phase-tag THAT trong data:
  - network_requests: 100% entries co field "phase"
    (sandbox/sensors/network.py:17, sandbox/sensors/cdp_sw.py:115)
  - new_tabs:          100% entries co field "phase"
    (sandbox/sensors/network.py:86)
  - dom_activity:      co field "phase" + "t" SAU khi va sandbox/sensors/dom.py
    (metadata-only patch, KHONG doi logic bat node). _slice_events tu phat hien:
    neu dom_activity co phase-tag -> loc theo phase (script_injection VAO duoc ablation);
    neu KHONG (events.json cu, tien-va) -> fallback loai han khoi CA 4 config + in canh bao.

GIOI HAN DA BIET:
  - dom_activity (script_injection): CHI slice duoc neu events.json thu tu image DA VA
    (dom.py ghi phase+t). Voi pool cu (tien-va) van la CAN DUOI (lower bound). Sau khi
    chay lai pool bang image moi -> so nay la FULL (gom script_injection channel).
  - request_provenance (undeclared_from_cs): la dict phang {host: bool} tich luy TOAN RUN,
    khong co timeline (sandbox/sensors/cdp_sw.py:261-263) -> cung loai khoi CA 4 cau hinh
    voi ly do tuong tu.
  - extension_storage / local_harvest: chi dump 1 lan SAU KHI browser dong
    (sandbox/analyze.py:154), khong tach duoc theo phase. Chi 1/354 mau toan pool co
    honeypot_hits nen anh huong khong dang ke, nhung van loai khoi CA 4 cau hinh cho
    NHAT QUAN voi quyet dinh tren.
  - page_hang_count: la counter vo huong, KHONG co phase-tag tung lan, NHUNG code
    (sandbox/phases/actions.py:116-157, ham _visit_pages) chi tang bien nay o dung 1 noi,
    goi TRONG phase honeypot_pages -- day la suy luan tu CAU TRUC CODE (khong phai tu
    phase-tag trong DATA), nen o config A (chi co "load") ta chu dong ZERO no de tranh
    "ro ri" tin hieu chua the xay ra ve mat logic; giu nguyen o B/C/D.
  - static-only indicators (overprivileged, has_suspicious_host, broad_injection) doc tu
    manifest, khong doi theo phase -- giu nguyen moi config (dung, vi day la thuoc tinh
    TINH, khong phai quan sat dong).

RANG BUOC: KHONG sua worker/risk.py -- chi IMPORT ham build_behavioral_report/
compute_risk_score va goi tren cac dict events{} da loc rieng.

Chay: python eval/ablation_stimulus.py
Yeu cau: eval/results/summary.csv da co (chay eval/rescore.py) va co cot verified_label
(chay eval/apply_verified_labels.py) -- CHI DOC, khong chay lai 2 script do.
"""
import argparse
import csv
import json
import sys
from copy import deepcopy
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "worker"))
import risk  # noqa: E402  (chi doc/goi ham, KHONG sua file)

# --results: thu muc chua <ext_id>/output/events.json de slice (mac dinh eval/results).
# summary.csv (nhan verified_label + run_status) LUON lay tu eval/results de nhat quan.
_ap = argparse.ArgumentParser()
_ap.add_argument("--results", default=str(REPO / "eval" / "results"),
                 help="thu muc events.json de slice (vd eval/pool_c2_new cho pool da va dom.py)")
_ap.add_argument("--out", default=None, help="thu muc output (mac dinh <results>/ablation_stimulus)")
_args = _ap.parse_args()

RESULTS = Path(_args.results)
SUMMARY_CSV = REPO / "eval" / "results" / "summary.csv"   # nhan luon tu pool goc
OUT_DIR = Path(_args.out) if _args.out else RESULTS / "ablation_stimulus"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# Dung PHASE_NAMES that tu sandbox/config.py de khong hard-code trung lap thu tu.
sys.path.insert(0, str(REPO / "sandbox"))
from config import PHASE_NAMES  # noqa: E402  ["load","honeypot_pages","target_matched",
                                  #              "extension_pages","delayed_observation"]

CONFIGS = {
    "A": {"load"},
    "B": {"load", "honeypot_pages"},
    "C": {"load", "honeypot_pages", "target_matched"},
    "D": set(PHASE_NAMES),
}
CONFIG_ORDER = ["A", "B", "C", "D"]

# 6 detector dong (giong SIGNALS trong eval/rescore.py) -- dung de bao cao "signal moi".
DYNAMIC_SIGNALS = ["credential_exfil", "local_harvest", "script_injection",
                    "beaconing", "undeclared_domain_contact", "unsolicited_tab"]
LEVEL_ORDER = {"MINIMAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _dom_activity_has_phase(events: dict) -> bool:
    """True neu events.json den tu image DA VA (dom.py ghi field 'phase' cho node)."""
    return any("phase" in d for d in events.get("dom_activity", []) if isinstance(d, dict))


def _slice_events(events: dict, phases_included: set) -> dict:
    """Tao ban events{} rieng cho 1 cau hinh: loc network_requests/new_tabs/dom_activity
    theo phase (dom_activity chi khi co phase-tag; neu khong -> loai han). Loai han
    request_provenance/extension_storage (khong the loc trung thuc), zero page_hang_count
    o config chua co honeypot_pages."""
    sliced = deepcopy(events)

    reqs = [r for r in sliced.get("network_requests", [])
            if r.get("phase") in phases_included]
    sliced["network_requests"] = reqs

    sliced["new_tabs"] = [t for t in sliced.get("new_tabs", [])
                           if t.get("phase") in phases_included]

    # dom_activity (script_injection): loc theo phase NEU co phase-tag (image da va);
    # neu khong -> loai han khoi CA 4 config (nhat quan, tranh thien vi) = hanh vi cu.
    if _dom_activity_has_phase(events):
        sliced["dom_activity"] = [d for d in sliced.get("dom_activity", [])
                                  if d.get("phase") in phases_included]
    else:
        sliced["dom_activity"] = []

    # Kenh khong the loc trung thuc theo phase (xem docstring dau file) -> loai het,
    # NHAT QUAN o ca 4 cau hinh.
    sliced["request_provenance"] = {}
    sliced["extension_storage"] = {}

    # Suy lai honeypot_exfil/_details TU network_requests DA LOC (field goc la OR tren
    # toan run, khong dung truc tiep duoc).
    details = [r for r in reqs if r.get("honeypot_markers")]
    sliced["honeypot_exfil"] = bool(details)
    sliced["honeypot_exfil_details"] = [
        {"url": r.get("url"), "method": r.get("method"), "markers": r.get("honeypot_markers")}
        for r in details
    ]
    sliced["honeypot_stored"] = False  # phu thuoc extension_storage, da loai o tren

    if "honeypot_pages" not in phases_included:
        sliced["page_hang_count"] = 0

    return sliced


def _score(events: dict) -> dict:
    report = risk.build_behavioral_report(events)
    risk_score, level, bd = risk.compute_risk_score(report)
    ind = report["indicators"]
    active_signals = sorted(s for s in DYNAMIC_SIGNALS if ind.get(s))
    return {"risk": risk_score, "level": level, "signals": active_signals}


def classify(vlabel):
    """malicious=True positive; benign/benign_mislabel=False negative; grey/unknown_verify
    loai (giong quy uoc pr_roc.py --mode verified / ablation_attribution.py)."""
    if vlabel in ("grey", "unknown_verify"):
        return None
    if vlabel == "malicious":
        return True
    if vlabel in ("benign", "benign_mislabel"):
        return False
    return None


def main():
    if not SUMMARY_CSV.exists():
        print(f"Khong thay {SUMMARY_CSV}. Chay eval/rescore.py + eval/apply_verified_labels.py truoc.")
        return
    meta_rows = list(csv.DictReader(open(SUMMARY_CSV, encoding="utf-8")))
    if meta_rows and "verified_label" not in meta_rows[0]:
        print("summary.csv chua co cot verified_label. Chay eval/apply_verified_labels.py truoc.")
        return

    per_sample_rows = []
    n_missing_events, n_not_complete = 0, 0
    n_target_active = 0
    n_dom_phase_tagged = 0        # so mau co dom_activity gan phase (image DA VA)
    n_dom_present = 0             # so mau co it nhat 1 entry dom_activity

    # Dem dong gop bien tung buoc chuyen (A->B, B->C, C->D): mau nao GAIN >=1 signal moi.
    gained_transition = {"A->B": 0, "B->C": 0, "C->D": 0}
    # Recall@40 tung cau hinh, tren toan bo mau complete (khong chi subset target-active).
    recall_data = {c: [] for c in CONFIG_ORDER}   # list[(is_mal, risk)]

    n_woken_signal = 0
    n_woken_level = 0

    for meta in meta_rows:
        ext_id = meta.get("ext_id", "")
        if meta.get("run_status") != "complete":
            n_not_complete += 1
            continue
        ev_path = RESULTS / ext_id / "output" / "events.json"
        if not ev_path.exists():
            n_missing_events += 1
            continue
        events = json.loads(ev_path.read_text(encoding="utf-8"))

        target_active = bool(events.get("target_matched_hosts"))
        if target_active:
            n_target_active += 1
        if events.get("dom_activity"):
            n_dom_present += 1
            if _dom_activity_has_phase(events):
                n_dom_phase_tagged += 1

        scored = {}
        for cfg in CONFIG_ORDER:
            sliced = _slice_events(events, CONFIGS[cfg])
            scored[cfg] = _score(sliced)

        vlabel = meta.get("verified_label", meta.get("label", ""))
        cls = classify(vlabel)
        if cls is not None:
            for cfg in CONFIG_ORDER:
                recall_data[cfg].append((cls, scored[cfg]["risk"]))

        # Dong gop bien tung transition (tren TAT CA mau, khong chi target-active --
        # mau khong co target_matched_hosts se dung nhien co gained_B_C rong, dung y).
        prev = None
        for i, cfg in enumerate(CONFIG_ORDER):
            if i == 0:
                prev = cfg
                continue
            trans = f"{prev}->{cfg}"
            gained = sorted(set(scored[cfg]["signals"]) - set(scored[prev]["signals"]))
            if gained:
                gained_transition[trans] += 1
            prev = cfg

        gained_at_C = sorted(set(scored["C"]["signals"]) - set(scored["B"]["signals"]))
        woken_signal = bool(gained_at_C)
        woken_level = (LEVEL_ORDER.get(scored["C"]["level"], 0)
                       > LEVEL_ORDER.get(scored["B"]["level"], 0)) or \
                      (scored["B"]["risk"] < 40 <= scored["C"]["risk"])
        if woken_signal:
            n_woken_signal += 1
        if woken_level:
            n_woken_level += 1

        row = {
            "sample_id": ext_id,
            "verified_label": vlabel,
            "target_matched_active": int(target_active),
        }
        for cfg in CONFIG_ORDER:
            row[f"signals_{cfg}"] = "|".join(scored[cfg]["signals"])
            row[f"level_{cfg}"] = scored[cfg]["level"]
            row[f"risk_{cfg}"] = scored[cfg]["risk"]
        row["woken_signal"] = int(woken_signal)
        row["woken_level"] = int(woken_level)
        row["detectors_gained_at_C"] = "|".join(gained_at_C)
        per_sample_rows.append(row)

    # ---- ghi per_sample.csv ----
    cols = ["sample_id", "verified_label", "target_matched_active"]
    for cfg in CONFIG_ORDER:
        cols += [f"signals_{cfg}", f"level_{cfg}", f"risk_{cfg}"]
    cols += ["woken_signal", "woken_level", "detectors_gained_at_C"]
    with open(OUT_DIR / "per_sample.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(per_sample_rows)

    # ---- recall@40 tung cau hinh ----
    recall_at_40 = {}
    for cfg in CONFIG_ORDER:
        data = recall_data[cfg]
        P = sum(1 for m, _ in data if m)
        TP = sum(1 for m, r in data if m and r >= 40)
        recall_at_40[cfg] = (TP / P if P else 0.0, TP, P)

    n_scored = len(per_sample_rows)
    marginal_biggest = max(gained_transition, key=gained_transition.get)

    summary_rows = [
        {"metric": "n_samples_scored (run_status=complete, events.json co)", "value": n_scored},
        {"metric": "n_excluded_not_complete", "value": n_not_complete},
        {"metric": "n_excluded_missing_events", "value": n_missing_events},
        {"metric": "n_target_matched_active (target_matched_hosts non-empty)", "value": n_target_active},
        {"metric": "n_woken_signal (B->C, signal moi nho target_matched)", "value": n_woken_signal},
        {"metric": "n_woken_level (B->C, tang band hoac vuot nguong 40)", "value": n_woken_level},
        {"metric": "gained_A->B (n mau co signal moi)", "value": gained_transition["A->B"]},
        {"metric": "gained_B->C (n mau co signal moi)", "value": gained_transition["B->C"]},
        {"metric": "gained_C->D (n mau co signal moi)", "value": gained_transition["C->D"]},
        {"metric": "phase_dong_gop_bien_lon_nhat", "value": marginal_biggest},
    ]
    for cfg in CONFIG_ORDER:
        rec, tp, p = recall_at_40[cfg]
        summary_rows.append({
            "metric": f"recall@40_{cfg} (TP/P, P={p})",
            "value": f"{rec:.4f}",
        })

    with open(OUT_DIR / "summary.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["metric", "value"])
        w.writeheader()
        w.writerows(summary_rows)

    # ---- bieu do cot (tuy chon, neu co matplotlib) ----
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        counts = [sum(1 for r in per_sample_rows if r[f"signals_{cfg}"]) for cfg in CONFIG_ORDER]
        fig, ax = plt.subplots(figsize=(5, 4))
        ax.bar(CONFIG_ORDER, counts, color=["#888", "#5b8", "#e94", "#39c"])
        ax.set_ylabel("So mau co >=1 dynamic signal")
        ax.set_title("Detections theo cau hinh stimulus tich luy (A->D)")
        for i, c in enumerate(counts):
            ax.text(i, c, str(c), ha="center", va="bottom")
        plt.tight_layout()
        out_png = OUT_DIR / "detections_by_config.png"
        plt.savefig(out_png, dpi=130)
        print(f"Da luu bieu do: {out_png}")
    except ImportError:
        print("(Chua co matplotlib -- bo qua ve bieu do)")

    # ---- tom tat in ra chat ----
    recD = recall_at_40["D"][0]
    recA = recall_at_40["A"][0]
    print(f"\n[ablation_stimulus] {n_scored} mau (loai {n_not_complete} not-complete, "
          f"{n_missing_events} missing events)")
    print(f"  target_matched active (co content_scripts host cu the): {n_target_active}/{n_scored}")
    print(f"  dom_activity phase-tagged: {n_dom_phase_tagged}/{n_dom_present} mau co dom_activity "
          f"({'FULL - script_injection VAO ablation' if n_dom_phase_tagged == n_dom_present and n_dom_present else 'LOWER BOUND - can chay lai pool bang image da va dom.py'})")
    print(f"\ntarget_matched danh thuc them {n_woken_signal} mau (woken_signal) / "
          f"{n_woken_level} mau (woken_level, B->C); "
          f"recall@40 A->D: {recA:.3f} -> {recall_at_40['B'][0]:.3f} -> "
          f"{recall_at_40['C'][0]:.3f} -> {recD:.3f}; "
          f"dong gop bien lon nhat o phase {marginal_biggest} "
          f"(A->B={gained_transition['A->B']}, B->C={gained_transition['B->C']}, "
          f"C->D={gained_transition['C->D']})")
    if n_dom_phase_tagged == n_dom_present and n_dom_present:
        print(f"\nGHI CHU: dom_activity CO phase-tag -> script_injection DA VAO ablation. "
              f"Chi con local_harvest (1 mau toan pool) + undeclared_from_cs bi loai. "
              f"Con so tren la FULL (khong con la lower bound cho script_injection).")
    else:
        print(f"\nGHI CHU LOWER BOUND: dom_activity CHUA phase-tag (pool tien-va) -> "
              f"script_injection/local_harvest/undeclared_from_cs bi loai khoi ca 4 cau hinh "
              f"-- con so tren la CAN DUOI. Chay lai pool bang image da va dom.py de co so FULL.")
    print(f"\nOutput: {OUT_DIR / 'per_sample.csv'}  |  {OUT_DIR / 'summary.csv'}")


if __name__ == "__main__":
    main()
