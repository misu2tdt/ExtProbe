"""B-triage: doc moi events.json da luu, phan loai MOI mau theo HANH VI QUAN SAT
duoc (dung chinh risk.py de nhat quan voi scoring), va cheo voi CAPABILITY khai bao
trong manifest.

Muc dich: tra loi cau hoi "tin hieu manh cam la vi extension THAT SU khong co hanh vi
do, hay vi stimulus/mau chet?" -- bang cach tach:
  - silent_minimal : cam + quyen toi thieu   => nhieu kha nang LANH THAT (nghi mislabel)
  - silent_capable : cam + quyen NGUY HIEM    => dang ngo (cho trigger / evasive / C2 chet)
Va sinh bang phan tang dataset cho thesis. Thuan Python, KHONG Docker.
"""
import csv, json, sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RESULTS_DIR = Path(__import__("os").environ.get("EXTPROBE_V2_RESULTS") or REPO / "data" / "v2_results")   # recorded traces (release asset) go here
sys.path.insert(0, str(REPO / "scoring"))
from risk import build_behavioral_report  # noqa: E402

DANGEROUS_PERMS = {"webRequest", "webRequestBlocking", "declarativeNetRequest",
                   "declarativeNetRequestWithHostAccess", "scripting", "cookies",
                   "tabs", "proxy", "debugger", "management", "browsingData",
                   "downloads", "history", "clipboardRead"}
BROAD_HOSTS = ("<all_urls>", "*://*/*", "http://*/*", "https://*/*")

SIGNALS = ["credential_exfil", "local_harvest", "beaconing",
           "script_injection", "undeclared_domain_contact", "unsolicited_tab"]


def has_broad_capability(manifest: dict) -> bool:
    perms = set(manifest.get("permissions", []) or [])
    if perms & DANGEROUS_PERMS:
        return True
    hosts = (manifest.get("host_permissions", []) or [])
    for cs in manifest.get("content_scripts", []) or []:
        hosts += cs.get("matches", []) or []
    return any(any(b in (h or "") for b in BROAD_HOSTS) for h in hosts)


def classify(events: dict) -> dict:
    man = events.get("manifest", {}) or {}
    rs = (events.get("run_status", {}) or {}).get("status", "unknown")
    report = build_behavioral_report(events)
    ind = report.get("indicators", {})
    sig = {s: bool(ind.get(s)) for s in SIGNALS}
    summ = events.get("summary", {}) or {}
    broad = has_broad_capability(man)
    n_perms = len(man.get("permissions", []) or []) + len(man.get("host_permissions", []) or [])
    total_req = summ.get("total_requests", 0)
    activity = total_req + summ.get("new_tabs_opened", 0) + summ.get("scripts_injected", 0)

    if rs not in ("complete",):
        bucket = "run_incomplete"
    elif sig["credential_exfil"] or sig["local_harvest"] or sig["beaconing"]:
        bucket = "hard_malicious"
    elif sig["script_injection"]:
        bucket = "injector"
    elif sig["unsolicited_tab"] or sig["undeclared_domain_contact"]:
        bucket = "adware_or_pup"
    else:
        bucket = "silent_capable" if broad else "silent_minimal"

    return {
        "run_status": rs, "bucket": bucket, "broad_capability": int(broad),
        "n_perms": n_perms, "total_requests": total_req, "activity": activity,
        "new_tabs": summ.get("new_tabs_opened", 0),
        "honeypot_exfil": int(bool(summ.get("honeypot_exfil"))),
        "honeypot_stored": int(bool(summ.get("honeypot_stored"))),
        **{s: int(v) for s, v in sig.items()},
    }


def main():
    results = Path(sys.argv[1]) if len(sys.argv) > 1 else RESULTS_DIR
    rows = []
    for d in sorted(p for p in results.iterdir() if p.is_dir()):
        ev = d / "output" / "events.json"
        meta = {}
        mp = d / "meta.json"
        if mp.exists():
            meta = json.loads(mp.read_text(encoding="utf-8"))
        if not ev.exists():
            rows.append({"ext_id": meta.get("ext_id", d.name), "name": "",
                         "manifest_version": "", "bucket": "no_events", "run_status": "no_events"})
            continue
        try:
            events = json.loads(ev.read_text(encoding="utf-8"))
            r = classify(events)
            r["ext_id"] = meta.get("ext_id", d.name)
            r["name"] = (events.get("manifest", {}) or {}).get("name", "")
            r["manifest_version"] = (events.get("manifest", {}) or {}).get("manifest_version", "")
            rows.append(r)
        except Exception as e:
            rows.append({"ext_id": meta.get("ext_id", d.name), "bucket": "triage_error",
                         "run_status": "error", "name": str(e)[:80]})

    if not rows:
        print("khong co ket qua trong", results); return

    cols = ["ext_id", "name", "manifest_version", "run_status", "bucket",
            "broad_capability", "n_perms", "total_requests", "new_tabs", "activity",
            "honeypot_exfil", "honeypot_stored", *SIGNALS]
    out = results / "triage.csv"
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)

    n = len(rows)
    buckets = Counter(r["bucket"] for r in rows)
    print(f"[triage] {n} mau -> {out}\n")
    print("=== PHAN TANG DATASET (theo hanh vi quan sat) ===")
    order = ["hard_malicious", "injector", "adware_or_pup", "silent_capable",
             "silent_minimal", "run_incomplete", "no_events", "triage_error"]
    label = {
        "hard_malicious": "co bang chung manh (exfil/harvest/beacon)",
        "injector": "chen remote script",
        "adware_or_pup": "chi tin hieu yeu (tab/domain la) = PUP/adware",
        "silent_capable": "CAM du co quyen nguy hiem  <-- cho trigger / evasive / C2 chet",
        "silent_minimal": "CAM + quyen toi thieu       <-- NGHI mislabel / lanh that",
        "run_incomplete": "phien chay hut (khong ket luan)",
        "no_events": "khong co events.json",
        "triage_error": "loi doc",
    }
    for b in order:
        if buckets.get(b):
            print(f"  {buckets[b]:4d}  ({buckets[b]/n*100:4.1f}%)  {b:16s} {label.get(b,'')}")

    suspect = buckets.get("adware_or_pup", 0) + buckets.get("silent_minimal", 0)
    scored = n - buckets.get("no_events", 0) - buckets.get("triage_error", 0) - buckets.get("run_incomplete", 0)
    print(f"\n=== DO SACH GROUND TRUTH ===")
    if scored:
        print(f"  nghi KHONG hanh vi doc hai manh (adware/pup + silent_minimal): "
              f"{suspect}/{scored} = {suspect/scored*100:.0f}% cua mau ket luan duoc")
        print(f"  co bang chung doc hai (hard_malicious + injector): "
              f"{buckets.get('hard_malicious',0)+buckets.get('injector',0)}/{scored}")

    sc = buckets.get("silent_capable", 0)
    sm = buckets.get("silent_minimal", 0)
    print(f"\n=== VI SAO TIN HIEU MANH CAM (cheo capability) ===")
    print(f"  cam + quyen toi thieu (lanh that):     {sm}")
    print(f"  cam + quyen nguy hiem (dang stimulus): {sc}  <-- day moi la cho stimulus co the cuu")


if __name__ == "__main__":
    main()
