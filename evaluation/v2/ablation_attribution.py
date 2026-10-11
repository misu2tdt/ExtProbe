"""
ablation_attribution.py — Ablation: NAIVE (moi traffic la cua extension, tat provenance
filter) vs PROVENANCE-AWARE (chi tinh extension-initiated: SW + CS ext=True, hien hanh
trong worker/risk.py) cho tin hieu undeclared_domain_contact.

CHAN DOAN (xem bao cao Phan A kem theo): `network_requests` trong events.json ghi LAI
TAT CA request (ca origin="page" LAN origin="service_worker"), khong chi loc san
extension-initiated -> NAIVE mode tai tao duoc HOAN TOAN offline tu du lieu da co, KHONG
can pool run rieng. DOM channel (dom_activity) cung co du page_url de phan biet own-page/
external nhung KHONG duoc ablate trong script nay (Phan B chi yeu cau undeclared_domain/
network channel; Phan C chi minh hoa DOM/SW bang so lieu co san tu cac dot truoc).

CHI DOC eval/results/*/output/events.json (san co, khong pool run lai) +
eval/results/summary.csv (lay label/verified_label/run_status). KHONG sua worker/risk.py -
chi IMPORT cac ham helper cua no (read-only) de tai su dung dung logic loc host (harness/
infra/declared) va cong thuc cham diem (DYNAMIC_WEIGHTS, CORROBORATION_COEF...), dam bao
ablation CHI khac o buoc thu thap evidence undeclared_domain, moi thu khac (script_injection,
unsolicited_tab, static...) giu nguyen y het production.

Thiet ke NAIVE (da sua sau 1 lan chay thu - xem docstring detect_undeclared_domains_naive
de biet chi tiet loi ban dau va cach sua): kenh SW giu nguyen y het PROVENANCE (khong nhap
nhang, khong thuoc pham vi GD3). Kenh page: NAIVE dem MOI host origin=page (BAT KY
request_provenance[host] True/False) vao CUNG bucket trong-so 15 ma PROVENANCE dang dung
cho CS ext_initiated=True - CHI khac o TIEU CHI loc (tat dieu kien ext_initiated==True),
KHONG doi trong so bucket. Day la cach ly dung 1 bien duy nhat (co ap dung provenance filter
hay khong), tranh nham lan voi truc "bucket nao trong so bao nhieu" (dieu ma lan thu dau bi
sai, xem chi tiet trong code).

Chay: python eval/ablation_attribution.py
"""
import csv
import json
import sys
from copy import deepcopy
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RESULTS_DIR = Path(__import__("os").environ.get("EXTPROBE_V2_RESULTS") or REPO / "data" / "v2_results")   # recorded traces (release asset) go here
sys.path.insert(0, str(REPO / "scoring"))
import risk  # noqa: E402  (chi doc/goi ham, KHONG sua file)

RESULTS = RESULTS_DIR
SUMMARY_CSV = RESULTS / "summary.csv"
OUT_CSV = RESULTS / "ablation_attribution.csv"


def detect_undeclared_domains_naive(events: dict) -> dict:
    """Ban NAIVE cua risk.detect_undeclared_domains: TAT GD3 (provenance filter isolated-
    world/ext_initiated) — dem MOI host origin=page (BAT KY request_provenance[host] la
    True hay False, hay khong co trong request_provenance) coi nhu deu la "extension
    initiated". Kenh SW (from_sw) GIU NGUYEN y het PROVENANCE: origin=service_worker da la
    tin hieu khong con nhap nhang (1 session CDP rieng cho dung 1 extension, xem Fix #1
    SW-attribution) — GD3/provenance chua bao gio ap dung cho kenh SW, nen KHONG thuoc
    pham vi ablation nay.

    QUAN TRONG (sua sau lan chay dau, xem bao cao): ban dau du dinh don TAT CA host (ca
    SW lan page) vao 1 bucket "from_sw" trong-so cao (base=30 trong _dynamic_score) voi ly
    do "NAIVE = coi extension goi tat". Do luong tren du lieu that (vd
    kjidkkncdchjnnfpclneimlcmghcfoon) cho thay dieu nay SAI: no lam risk NAIVE tang len
    KHONG PHAI vi co evidence MOI, ma chi vi CUNG MOT host bi chuyen tu bucket
    trong-so-thap (from_cs, 15) sang trong-so-cao (from_sw, 30) - conflate 2 truc khac
    nhau (co tinh vao undeclared hay khong, vs trong so cua bucket nao). Da sua: host tu
    origin=page (bat ke provenance) vao from_cs (GIU NGUYEN trong so 15, dung nhu PROVENANCE
    dang dung cho CS-initiated) — CHI khac o TIEU CHI loc (tat ext_initiated==True), khong
    doi trong so. Day moi la ablation dung y "tat provenance filter", cach ly dung 1 bien so."""
    manifest = events.get("manifest", {})
    declared = risk._manifest_declared_hosts(manifest)

    def _keep(host):
        return (risk._is_real_domain(host) and not risk._is_harness_host(host)
                and not risk._is_declared_host(host, declared)
                and not risk._is_known_infra_host(host))

    from_sw = set()
    from_page = set()
    for r in events.get("network_requests", []):
        url = r.get("url", "")
        if url.startswith(risk._INTERNAL_SCHEMES):
            continue
        host = risk._host_of(url)
        if not _keep(host):
            continue
        if r.get("origin") == "service_worker":
            from_sw.add(host)
        elif r.get("origin") == "page":
            from_page.add(host)

    total = from_sw | from_page
    return {
        "undeclared_from_sw": sorted(from_sw),
        "undeclared_from_cs": sorted(from_page),   # ten field giu nguyen de tuong thich voi
                                                     # _dynamic_score (trong so 15) - noi dung
                                                     # thuc te la "from_page (GD3 da tat)"
        "undeclared_total": sorted(total),
        "has_undeclared": bool(total),
    }


def score_both_modes(events: dict) -> dict:
    """Tra ve (risk_naive, level_naive, risk_prov, level_prov, ud_naive, ud_prov)."""
    report_prov = risk.build_behavioral_report(events)
    risk_prov, level_prov, bd_prov = risk.compute_risk_score(report_prov)

    report_naive = deepcopy(report_prov)
    ud_naive = detect_undeclared_domains_naive(events)
    report_naive["dynamic"]["undeclared_domains"] = ud_naive
    report_naive["indicators"]["undeclared_domain_contact"] = ud_naive["has_undeclared"]
    risk_naive, level_naive, bd_naive = risk.compute_risk_score(report_naive)

    ud_prov = report_prov["dynamic"]["undeclared_domains"]
    return {
        "risk_naive": risk_naive, "level_naive": level_naive,
        "static_naive": bd_naive["static_score"], "dynamic_naive": bd_naive["dynamic_score"],
        "risk_provenance": risk_prov, "level_provenance": level_prov,
        "static_provenance": bd_prov["static_score"], "dynamic_provenance": bd_prov["dynamic_score"],
        "undeclared_naive": ud_naive["undeclared_total"],
        "undeclared_provenance": ud_prov["undeclared_total"],
    }


def main():
    if not SUMMARY_CSV.exists():
        print(f"Khong thay {SUMMARY_CSV}. Chay eval/rescore.py + eval/apply_verified_labels.py truoc.")
        return

    meta_rows = {r["ext_id"]: r for r in csv.DictReader(open(SUMMARY_CSV, encoding="utf-8"))}

    out_rows = []
    n_missing_events = 0
    n_not_complete = 0
    page_reqs_total = 0
    sw_reqs_total = 0

    for ext_id, meta in sorted(meta_rows.items()):
        if meta.get("run_status") != "complete":
            n_not_complete += 1
            continue
        ev_path = RESULTS / ext_id / "output" / "events.json"
        if not ev_path.exists():
            n_missing_events += 1
            continue
        try:
            events = json.loads(ev_path.read_text(encoding="utf-8"))
        except Exception as e:
            print(f"[FATAL] khong doc/parse duoc events.json cua {ext_id} ({ev_path}): {e}",
                  file=sys.stderr)
            raise

        for r in events.get("network_requests", []):
            o = r.get("origin")
            if o == "page":
                page_reqs_total += 1
            elif o == "service_worker":
                sw_reqs_total += 1

        scores = score_both_modes(events)
        dropped = sorted(set(scores["undeclared_naive"]) - set(scores["undeclared_provenance"]))
        out_rows.append({
            "ext_id": ext_id,
            "label": meta.get("label", ""),
            "verified_label": meta.get("verified_label", meta.get("label", "")),
            "verified": meta.get("verified", "no"),
            "run_status": meta.get("run_status", ""),
            "risk_naive": scores["risk_naive"],
            "level_naive": scores["level_naive"],
            "risk_provenance": scores["risk_provenance"],
            "level_provenance": scores["level_provenance"],
            "undeclared_count_naive": len(scores["undeclared_naive"]),
            "undeclared_count_provenance": len(scores["undeclared_provenance"]),
            "hosts_dropped_by_provenance": "|".join(dropped),
            "n_hosts_dropped": len(dropped),
        })

    fieldnames = ["ext_id", "label", "verified_label", "verified", "run_status",
                  "risk_naive", "level_naive", "risk_provenance", "level_provenance",
                  "undeclared_count_naive", "undeclared_count_provenance",
                  "hosts_dropped_by_provenance", "n_hosts_dropped"]
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(out_rows)

    print(f"[ablation] {len(out_rows)} mau (run_status=complete, co events.json) -> {OUT_CSV}")
    print(f"  bo qua: {n_not_complete} run_status!=complete, {n_missing_events} thieu events.json")
    tot = page_reqs_total + sw_reqs_total
    if tot:
        print(f"  Network channel toan dataset: page-initiated={page_reqs_total} "
              f"({page_reqs_total/tot*100:.1f}%)  sw-initiated={sw_reqs_total} "
              f"({sw_reqs_total/tot*100:.1f}%)  tong={tot}")

    # ---- Phan tich: FP / precision / recall / AUC theo 2 mode, threshold=40 ----
    # Nhan verified: malicious = positive; benign_mislabel + benign = negative;
    # grey / unknown_verify = LOAI khoi phep tinh chinh (giong pr_roc.py --mode verified).
    def classify(vlabel):
        if vlabel == "grey" or vlabel == "unknown_verify":
            return None
        if vlabel == "benign_mislabel":
            return False
        if vlabel == "malicious":
            return True
        if vlabel == "benign":
            return False
        return None  # nhan la, khong xac dinh -> loai (giong raw filter cua pr_roc)

    data = []  # (ext_id, is_mal, risk_naive, risk_prov)
    n_grey = 0
    for r in out_rows:
        cls = classify(r["verified_label"])
        if cls is None:
            n_grey += 1
            continue
        data.append((r["ext_id"], cls, r["risk_naive"], r["risk_provenance"]))

    P = sum(1 for _, m, _, _ in data if m)
    N = sum(1 for _, m, _, _ in data if not m)
    print(f"\n[verified mode] dataset ablation: malicious(P)={P} benign(N)={N} "
          f"(loai grey/unknown_verify: {n_grey})")

    def metrics_at(threshold, risk_key_idx):
        TP = sum(1 for _, m, rn, rp in data if m and (rn if risk_key_idx == 0 else rp) >= threshold)
        FP = sum(1 for _, m, rn, rp in data if (not m) and (rn if risk_key_idx == 0 else rp) >= threshold)
        FN = P - TP
        recall = TP / P if P else 0
        precision = TP / (TP + FP) if (TP + FP) else 1.0
        return TP, FP, FN, recall, precision

    def auc_of(risk_key_idx):
        pts = []
        for t in range(0, 101):
            TP = sum(1 for _, m, rn, rp in data if m and (rn if risk_key_idx == 0 else rp) >= t)
            FP = sum(1 for _, m, rn, rp in data if (not m) and (rn if risk_key_idx == 0 else rp) >= t)
            pts.append((FP / N if N else 0, TP / P if P else 0))
        pts.sort()
        a = 0.0
        for i in range(1, len(pts)):
            x0, y0 = pts[i - 1]; x1, y1 = pts[i]
            a += (x1 - x0) * (y0 + y1) / 2
        return a, pts

    TPn, FPn, FNn, recn, precn = metrics_at(40, 0)
    TPp, FPp, FNp, recp, precp = metrics_at(40, 1)
    aucn, ptsn = auc_of(0)
    aucp, ptsp = auc_of(1)

    print("\n=== BANG SO SANH (nguong=40, verified mode) ===")
    print(f"{'Metric':<20} {'NAIVE':>10} {'PROVENANCE':>12} {'Delta':>10}")
    print(f"{'FP@40':<20} {FPn:>10} {FPp:>12} {FPp-FPn:>10}")
    print(f"{'TP@40':<20} {TPn:>10} {TPp:>12} {TPp-TPn:>10}")
    print(f"{'Precision@40':<20} {precn:>10.3f} {precp:>12.3f} {precp-precn:>10.3f}")
    print(f"{'Recall@40':<20} {recn:>10.3f} {recp:>12.3f} {recp-recn:>10.3f}")
    print(f"{'AUC':<20} {aucn:>10.3f} {aucp:>12.3f} {aucp-aucn:>10.3f}")

    # ---- Recall LOI (hard_malicious+injector), bucket theo PROVENANCE (khong bi ablate) ----
    def bucket_of(ext_id):
        m = meta_rows[ext_id]
        if int(m.get("credential_exfil", 0) or 0) or int(m.get("local_harvest", 0) or 0) or int(m.get("beaconing", 0) or 0):
            return "hard_malicious"
        if int(m.get("script_injection", 0) or 0):
            return "injector"
        return "other"

    core_ids = [r["ext_id"] for r in out_rows if r["label"] == "malicious"
                and r["verified_label"] not in ("benign", "benign_mislabel", "grey", "unknown_verify")
                and bucket_of(r["ext_id"]) in ("hard_malicious", "injector")]
    core_rows = {r["ext_id"]: r for r in out_rows if r["ext_id"] in core_ids}
    core_flagged_naive = sum(1 for eid in core_ids if core_rows[eid]["risk_naive"] >= 40)
    core_flagged_prov = sum(1 for eid in core_ids if core_rows[eid]["risk_provenance"] >= 40)
    n_core = len(core_ids)
    print(f"\n[Recall loi hard_malicious+injector] n={n_core}  "
          f"NAIVE={core_flagged_naive} ({core_flagged_naive/n_core:.4f})  "
          f"PROVENANCE={core_flagged_prov} ({core_flagged_prov/n_core:.4f})")
    lost_by_prov = [eid for eid in core_ids
                    if core_rows[eid]["risk_naive"] >= 40 and core_rows[eid]["risk_provenance"] < 40]
    print(f"  Mau trong cohort loi bi PROVENANCE loai mat (naive>=40 -> prov<40): {len(lost_by_prov)}")
    if lost_by_prov:
        print("  DANH SACH (can xem xet - co the provenance dang loai nham evidence that):")
        for eid in lost_by_prov:
            print(f"    {eid}: naive={core_rows[eid]['risk_naive']} prov={core_rows[eid]['risk_provenance']} "
                  f"hosts_dropped={core_rows[eid]['hosts_dropped_by_provenance']}")

    # ---- "So what": benign FP(naive) -> clean(provenance) ----
    benign_rows = [r for r in out_rows if r["verified_label"] == "benign"]
    flipped = [r for r in benign_rows if r["risk_naive"] >= 40 and r["risk_provenance"] < 40]
    print(f"\n[Benign FP(naive) -> clean(provenance)]: {len(flipped)}/{len(benign_rows)} mau benign")
    for r in sorted(flipped, key=lambda x: -x["n_hosts_dropped"])[:15]:
        print(f"    {r['ext_id']}: risk {r['risk_naive']}->{r['risk_provenance']}  "
              f"({r['n_hosts_dropped']} host bi loai: {r['hosts_dropped_by_provenance']})")

    still_fp_both = [r for r in benign_rows if r["risk_naive"] >= 40 and r["risk_provenance"] >= 40]
    print(f"\n[Benign van FP o CA HAI mode] (provenance khong giup): {len(still_fp_both)}")
    for r in still_fp_both:
        print(f"    {r['ext_id']}: naive={r['risk_naive']} prov={r['risk_provenance']}")

    # ---- Tong evidence items bi provenance loai tren toan dataset ----
    total_dropped = sum(r["n_hosts_dropped"] for r in out_rows)
    n_samples_with_drop = sum(1 for r in out_rows if r["n_hosts_dropped"] > 0)
    print(f"\n[Evidence items bi provenance loai] tong {total_dropped} host-instance, "
          f"tren {n_samples_with_drop}/{len(out_rows)} mau co it nhat 1 host bi loai")

    # ---- Ve ROC 2 duong chong len nhau (neu co matplotlib) ----
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(6, 6))
        xs_n = [p[0] for p in ptsn]; ys_n = [p[1] for p in ptsn]
        xs_p = [p[0] for p in ptsp]; ys_p = [p[1] for p in ptsp]
        ax.plot(xs_n, ys_n, "-o", ms=2, label=f"NAIVE (AUC={aucn:.3f})", color="tab:red")
        ax.plot(xs_p, ys_p, "-o", ms=2, label=f"PROVENANCE (AUC={aucp:.3f})", color="tab:blue")
        ax.plot([0, 1], [0, 1], "--", color="gray", lw=0.8)
        ax.set_xlabel("False Positive Rate"); ax.set_ylabel("Recall (TPR)")
        ax.set_title("Ablation: NAIVE vs PROVENANCE-AWARE attribution")
        ax.legend(); ax.grid(alpha=0.3)
        out_png = RESULTS / "ablation_roc.png"
        plt.tight_layout(); plt.savefig(out_png, dpi=130)
        print(f"\nDa luu bieu do: {out_png}")
    except ImportError:
        print("\n(Chua co matplotlib — bo qua ve bieu do)")


if __name__ == "__main__":
    main()
