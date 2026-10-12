import csv, json, sys
from collections import Counter
from pathlib import Path
import argparse
NEW = Path(__file__).resolve().parents[2]
_ap = argparse.ArgumentParser(description="Compare old and new scores (run_scores.py output) and recompute the headline numbers.")
_ap.add_argument("--old-repo", required=True, help="checkout of the development repository (read-only)")
_ap.add_argument("--scores", required=True, help="folder with the JSON written by run_scores.py")
_ap.add_argument("--out", required=True, help="output JSON file (rescore_summary.json)")
_a = _ap.parse_args()
OLD = Path(_a.old_repo).resolve()
SC = Path(_a.scores).resolve()
TR = {"test_v3": OLD / "eval/v3/test/traces_v3", "dev_v3": OLD / "eval/v3/dev/traces", "itw_A": OLD / "eval/v3/in_the_wild/traces_A",
      "itw_B": OLD / "eval/v3/in_the_wild/traces_B", "probe_a": OLD / "eval/v3_1_probe/traces_a", "probe_b": OLD / "eval/v3_1_probe/traces_b"}
LABEL = {"test_v3": "held-out benign test set", "dev_v3": "dev set", "itw_A": "in-the-wild set A", "itw_B": "in-the-wild set B",
         "probe_a": "v3.1-probe trial (a)", "probe_b": "v3.1-probe trial (b)"}
L = lambda p: json.loads(Path(p).read_text(encoding="utf-8"))
out = {}
md = []

def status(setname, d):
    try:
        return (json.loads((TR[setname] / d / "output" / "events.json").read_text(encoding="utf-8")).get("run_status") or {}).get("status")
    except Exception:
        return "unreadable"

def score_flag(r, probe):
    return (r["v31_score"], r["flag_v31"], r["v31_fired"]) if probe else (r["score"], r["flag"], r["fired"])

for s in TR:
    probe = s.startswith("probe")
    o, n = L(SC / f"{s}_old.json"), L(SC / f"{s}_new.json")
    keys = sorted(set(o) | set(n))
    same_key = set(o) == set(n)
    both = [k for k in keys if k in o and k in n]
    ident_score = ident_flag = ident_full = 0
    mism = []
    for k in both:
        so, fo, do = score_flag(o[k], probe)
        sn, fn, dn = score_flag(n[k], probe)
        ident_score += so == sn
        ident_flag += fo == fn
        ident_full += o[k] == n[k]
        if so != sn or fo != fn or set(do) != set(dn):
            mism.append((k, so, sn, sorted(set(do) ^ set(dn))))
    out[s] = dict(n_old=len(o), n_new=len(n), same_keys=same_key, compared=len(both), ident_score=ident_score, ident_flag=ident_flag, ident_full_result=ident_full, mismatches=len(mism))
    md.append(f"| {LABEL[s]} | {len(both)} | {ident_score} | {ident_flag} | {ident_full} | {len(mism)} |")
    if mism:
        out[s]["mismatch_detail"] = [(f"{s}#{i}", a, b, c) for i, (_, a, b, c) in enumerate(mism)]
print("\n".join(md))

# ---- dev set vs the RECORDED per-sample file (summary_v3.csv)
rows = list(csv.DictReader(open(OLD / "eval/v3/dev/summary_v3.csv", encoding="utf-8", newline="")))
DET = ["credential_exfil", "history_exfil", "affiliate_hijack", "local_harvest", "undeclared_domain_contact", "unsolicited_tab", "script_injection",
       "page_api_hooking", "beaconing", "causes_page_hang"]
n = L(SC / "dev_v3_new.json")
cmp = dict(rows=len(rows), found=0, ident_risk=0, ident_flag=0, ident_det=0, bad=[])
for i, r in enumerate(rows):
    k = r["ext_id"]
    if k not in n:
        continue
    if r["run_status"] != "complete" or r["risk"] == "":
        continue
    cmp["found"] += 1
    sn = n[k]["score"]
    ok_r = int(float(r["risk"])) == sn
    rec_det = {d for d in DET if r.get(d) not in ("", "0", None)}
    ok_d = rec_det == set(n[k]["fired"])
    cmp["ident_risk"] += ok_r
    cmp["ident_flag"] += (int(float(r["risk"])) >= 40) == (sn >= 40)
    cmp["ident_det"] += ok_d
    if not (ok_r and ok_d):
        cmp["bad"].append((f"dev#{i}", r["risk"], sn, sorted(rec_det ^ set(n[k]["fired"]))))
out["dev_vs_recorded_summary_v3_csv"] = cmp
print("dev vs recorded:", {k: v for k, v in cmp.items() if k != "bad"}, "bad", len(cmp["bad"]))

# ---- headline numbers from the NEW scores
man = {r["ext_id"]: r for r in csv.DictReader(open(NEW / "evaluation/manifests/samples_manifest_benign_test.csv", encoding="utf-8", newline=""))}
nt = L(SC / "test_v3_new.json")
c = Counter()
for k, r in nt.items():
    if status("test_v3", k) != "complete":
        c["incomplete"] += 1
        continue
    lab = man[k]["label"]
    c[lab + "_n"] += 1
    c[lab + "_flag"] += r["score"] >= 40
out["headline_test"] = dict(c)
print("test:", dict(c))
for s in ("itw_A", "itw_B"):
    nn = L(SC / f"{s}_new.json")
    comp = [k for k in nn if status(s, k) == "complete"]
    out["headline_" + s] = dict(total=len(nn), complete=len(comp), flagged=sum(nn[k]["score"] >= 40 for k in comp))
    print(s, out["headline_" + s])
lab = {r["ext_id"]: r for r in csv.DictReader(open(NEW / "evaluation/v3/labels/labels_tiers.csv", encoding="utf-8", newline=""))}
nd = L(SC / "dev_v3_new.json")
tot = fl = 0
for k, r in lab.items():
    if r["label_verified"] == "malicious" and k in nd and status("dev_v3", k) == "complete":
        tot += 1
        fl += nd[k]["score"] >= 40
out["headline_dev_malware_verified_label"] = dict(n=tot, flagged=fl)
print("dev malware (label_verified=malicious, complete):", tot, fl)
for s in ("probe_a", "probe_b"):
    nn = L(SC / f"{s}_new.json")
    up = sum(1 for r in nn.values() if r["flag_v31"] and not r["flag_v3"])
    dn = sum(1 for r in nn.values() if r["flag_v3"] and not r["flag_v31"])
    y = sum(1 for r in nn.values() if r["probe"]["yield"])
    out["headline_" + s] = dict(n=len(nn), newly_flagged=up, unflagged=dn, yield_=y, v3_flagged=sum(r["flag_v3"] for r in nn.values()), v31_flagged=sum(r["flag_v31"] for r in nn.values()))
    print(s, out["headline_" + s])
Path(_a.out).write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")

