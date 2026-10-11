"""operating_points.py -- operating points and performance figures for the paper.

Recomputed only from traces / scores that already exist: no sandbox run, no change to any frozen file.

  py eval/v3/operating_points/operating_points.py     # -> eval/v3/operating_points/results.md

1. Operating points of v2 and v3 at thresholds 15/25/35/40/50/60
   - recall on the development malware (label verified malicious, run complete in the profile): all,
     T1 / T2 / T3 (eval/v3/labels/labels_tiers.csv), all without family F000, T1 without F000
   - FPR on the development new benign set (benign_ext, manifest label benign) and on the held-out test set
     (192 benign)
   - Wilson 95 % interval on every rate
   - v2 recall at the threshold whose test FPR first falls to v3@40's (17 / 192), with bootstrap intervals
   The threshold 40 is the pre-registered one; the others are for reference only.
2. The false positives of v3 on the test set, anonymised, with detector and cause.
3. Run time per extension (median, p90), trace size, and counts of complete / partial / failed per set.

Scores: v2 = worker/risk.py via the existing summaries / test_analysis.collect; v3 = score_v3.py (summary_v3.csv for
the dev set, test_analysis.collect for the test set).
"""
import csv
import json
import random
import re
import statistics as st
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO / "eval" / "v3"))
sys.path.insert(0, str(REPO / "eval"))
import score_v3 as S  # noqa: E402
import test_analysis as TA  # noqa: E402
from expanded_analysis import wilson, pct  # noqa: E402

THRESHOLDS = [15, 25, 35, 40, 50, 60]
SEED = 20261010
BOOT = 10000
DEV_V2 = REPO / "eval" / "expanded" / "V2"
DEV_V3 = REPO / "eval" / "v3" / "dev"
TEST = REPO / "eval" / "v3" / "test"
MALWARE_TEST = REPO / "eval" / "v3" / "malware_test"
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def cell(k, n):
    if n == 0:
        return "n/a"
    lo, hi = wilson(k, n)
    return f"{k}/{n} = {pct(k / n)} ({pct(lo)}–{pct(hi)})"


# ---------------------------------------------------------------- data
def read_csv(p):
    return list(csv.DictReader(open(p, encoding="utf-8")))


def load():
    tiers = {r["ext_id"]: r for r in read_csv(REPO / "eval/v3/labels/labels_tiers.csv")}
    v2 = {r["ext_id"]: r for r in read_csv(DEV_V2 / "summary.csv")}
    v3 = {r["ext_id"]: r for r in read_csv(DEV_V3 / "summary_v3.csv")}
    mismatch = 0
    mal = {"v2": [], "v3": []}
    for i, t in tiers.items():
        if t["label_verified"] != "malicious":
            continue
        for p, src in (("v2", v2), ("v3", v3)):
            r = src.get(i)
            if r and r["run_status"] == "complete":
                score = int(float(r["risk"]))
                if t.get(f"{p}_score", "") != "" and int(float(t[f"{p}_score"])) != score:
                    mismatch += 1
                mal[p].append({"ext_id": i, "score": score, "tier": t["tier"], "family": t["family"]})
    man_dev = {r["ext_id"]: r for r in read_csv(REPO / "docs/samples_manifest_benign_ext.csv")}
    dev_ben = {"v2": [], "v3": []}
    for p, src in (("v2", v2), ("v3", v3)):
        for i, m in man_dev.items():
            r = src.get(i)
            if m["label"] == "benign" and r and r["run_status"] == "complete":
                dev_ben[p].append({"ext_id": i, "score": int(float(r["risk"]))})
    man_test = read_csv(REPO / "docs/samples_manifest_benign_test.csv")
    test = {"v2": TA.collect(man_test, TEST / "traces_v2", "v2", REPO / "samples/benign_test"),
            "v3": TA.collect(man_test, TEST / "traces_v3", "v3", REPO / "samples/benign_test")}
    test_ben = {p: [r for r in test[p] if r["label"] == "benign" and r["run_status"] == "complete" and r["score"] is not None]
                for p in test}
    return mal, dev_ben, test_ben, test, mismatch


def rate(scores, t):
    k = sum(1 for s in scores if s >= t)
    return k, len(scores)


# ---------------------------------------------------------------- bootstrap
def pct_ci(vals):
    vals = sorted(vals)
    return vals[int(0.025 * (len(vals) - 1))], vals[int(round(0.975 * (len(vals) - 1)))]


def boot_recall_fixed(mal, t, cluster=False, seed=SEED):
    rng = random.Random(seed)
    if cluster:
        fam = defaultdict(list)
        for m in mal:
            fam[m["family"]].append(m["score"] >= t)
        groups = list(fam.values())
        out = []
        for _ in range(BOOT):
            pick = [groups[rng.randrange(len(groups))] for _ in groups]
            flat = [x for g in pick for x in g]
            out.append(sum(flat) / len(flat))
        return pct_ci(out)
    flags = [m["score"] >= t for m in mal]
    out = [sum(flags[rng.randrange(len(flags))] for _ in flags) / len(flags) for _ in range(BOOT)]
    return pct_ci(out)


def threshold_for(fp_scores, max_fp_fraction):
    """Smallest integer threshold whose FPR <= max_fp_fraction (flag = score >= t)."""
    for t in range(0, 102):
        if sum(1 for s in fp_scores if s >= t) / len(fp_scores) <= max_fp_fraction + 1e-12:
            return t
    return 101


def boot_joint(mal, test_scores, target_fraction, seed=SEED):
    """Resample malware and test benign; re-choose the threshold in every replicate."""
    rng = random.Random(seed)
    ms = [m["score"] for m in mal]
    recs, ts = [], []
    for _ in range(BOOT):
        b = [test_scores[rng.randrange(len(test_scores))] for _ in test_scores]
        t = threshold_for(b, target_fraction)
        m = [ms[rng.randrange(len(ms))] for _ in ms]
        recs.append(sum(1 for s in m if s >= t) / len(m))
        ts.append(t)
    return pct_ci(recs), pct_ci(ts)


# ---------------------------------------------------------------- false-positive anatomy
ANALYTICS = ("amplitude", "sentry", "rollbar", "inboxsdk", "segment", "mixpanel", "datadog", "bugsnag", "posthog",
             "clarity.ms", "hotjar", "google-analytics", "newrelic", "fullstory", "heap", "launchdarkly", "growthbook")
CDN = ("b-cdn.net", "cloudfront.net", "githubusercontent.com", "jsdelivr", "unpkg", "amazonaws.com", "cloudflare")
WELCOME_RE = re.compile(r"welcome|thank|install|success|congrat|get started|onboard|tutorial|setup|getting started", re.I)
STOP = {"chrome", "extension", "free", "with", "from", "your", "that", "this", "tool", "tools", "online", "browser", "for", "the"}


def reg(h):
    return S.registrable(h)


def host_class(host, own_domains, name_tokens):
    h = host.lower()
    for k in ANALYTICS:
        if k in h:
            return "third-party analytics / error SDK"
    for k in CDN:
        if k in h:
            return "CDN / static hosting"
    d = reg(h)
    body = d.split(".")[0].replace("-", "")
    if d in own_domains or any(t in body or (len(body) >= 4 and body in t) for t in name_tokens):
        return "first-party domain"
    return "other third party"


def explain(ev, name, res):
    """(detectors, one-sentence cause) for one false positive, from the signals alone."""
    sg = res["signals"]
    fired = [n for n, s in sg.items() if s["fired"]]
    tabs = sg["unsolicited_tab"]["details"] if sg["unsolicited_tab"]["fired"] else []
    own = {d for t in tabs for d in t["registrable_domains"]}
    toks = [t for t in re.split(r"[^a-z0-9]+", (name or "").lower()) if len(t) >= 4 and t not in STOP]
    parts, cause = [], None
    if sg["history_exfil"]["fired"]:
        det = sg["history_exfil"]["details"]
        kinds = sorted({d["kind"].replace("visited_url", "URL") for d in det})
        via = sorted({d["via"].replace("service_worker", "service worker").replace("page_extension", "content script") for d in det})
        cls = sorted({host_class(d["host"], own, toks) for d in det})
        cause = f"visited {' + '.join(kinds)} of the harness pages sent by the {'/'.join(via)} to host class: {'/'.join(cls)}"
        parts.append(cause)
    if sg["undeclared_domain_contact"]["fired"] and sg["undeclared_domain_contact"].get("class") == "heavy" and not sg["history_exfil"]["fired"]:
        det = [u for u in sg["undeclared_domain_contact"]["details"] if u["user_data"]]
        cls = sorted({host_class(u["host"], own, toks) for u in det})
        what = sorted({x.replace("persistent_id", "persistent identifier (UUID in 2 phases)") for u in det for x in u["user_data"]})
        parts.append(f"{', '.join(what)} sent to host class: {'/'.join(cls)}")
    if not parts:
        # light signals only: say which ones
        if sg["undeclared_domain_contact"]["fired"]:
            det = sg["undeclared_domain_contact"]["details"]
            cc = Counter(host_class(u["host"], own, toks) for u in det)
            parts.append("undeclared hosts: " + ", ".join(f"{n} {c}" for c, n in cc.most_common()))
    if sg["unsolicited_tab"]["fired"]:
        t = tabs[0]
        welcome = bool(WELCOME_RE.search(" ".join(str(x) for x in t.get("titles", []) + [t.get("first_url", ""), t.get("final_url", "")])))
        parts.append(f"{'welcome-like' if welcome else 'non-welcome'} extension-opened tab {t['t_since_install']} s after install ({t['n_registrable_domains']} domain)")
    if sg["script_injection"]["fired"]:
        own_ui = all(n["host"].count(".") == 0 or n["src"].startswith("chrome-extension://") or len(n["host"]) in (32, 36)
                     for n in sg["script_injection"]["details"])
        parts.append("own UI script / iframe inserted into the page" if own_ui else "cross-origin script inserted")
    if sg["page_api_hooking"]["fired"]:
        rep = sorted({a for h in sg["page_api_hooking"]["details"] for a in h["replaced"]})
        parts.append("page " + "/".join(rep) + " wrapped")
    if sg["beaconing"]["fired"]:
        parts.append("periodic requests")
    if sg["causes_page_hang"]["fired"]:
        parts.append("page hang during the visit")
    return fired, "; ".join(parts)


# ---------------------------------------------------------------- performance
def perf_rows():
    sets = [("dev, v3 image", sorted((DEV_V3 / "traces").glob("*/meta.json")), "folder", True),
            ("dev, v2 image (expanded run)", sorted(DEV_V2.glob("*/meta.json")), "source_folder", False),
            ("test benign, v3", sorted((TEST / "traces_v3").glob("*/meta.json")), None, False),
            ("test benign, v2", sorted((TEST / "traces_v2").glob("*/meta.json")), None, False),
            ("MADWeb V3 malware test, v3", sorted((MALWARE_TEST / "traces_v3").glob("*/meta.json")), None, False),
            ("MADWeb V3 malware test, v2", sorted((MALWARE_TEST / "traces_v2").glob("*/meta.json")), None, False)]
    out = []
    for name, metas, key, drop_canary in sets:
        groups = defaultdict(list)
        for mp in metas:
            if drop_canary and mp.parent.name == "canary":
                continue
            m = json.loads(mp.read_text(encoding="utf-8"))
            ev = mp.parent / "output" / "events.json"
            total = sum(f.stat().st_size for f in (mp.parent / "output").rglob("*") if f.is_file()) if (mp.parent / "output").exists() else 0
            groups[(m.get(key) if key else "") or ""].append(
                {"dur": m.get("duration_s"), "status": m.get("run_status") or "unknown",
                 "events": ev.stat().st_size if ev.exists() else None, "total": total})
        if not groups:
            continue
        if key:
            for g in sorted(groups):
                out.append((f"{name}: {g}", groups[g]))
        else:
            out.append((name, groups[""]))
    return out


def q(vals, p):
    vals = sorted(vals)
    return vals[int(round(p * (len(vals) - 1)))] if vals else None


def fmt_kb(b):
    return "—" if b is None else (f"{b / 1024:.0f} kB" if b < 1024 * 1024 else f"{b / 1024 / 1024:.1f} MB")


def main():
    mal, dev_ben, test_ben, test_all, mismatch = load()
    P = ("v2", "v3")
    groups = [("all", lambda m: True), ("T1", lambda m: m["tier"] == "T1"), ("T2", lambda m: m["tier"] == "T2"),
              ("T3", lambda m: m["tier"] == "T3"), ("all without F000", lambda m: m["family"] != "F000"),
              ("T1 without F000", lambda m: m["tier"] == "T1" and m["family"] != "F000")]
    L = ["# Operating points and performance (v2 and v3)", "",
         "Recomputed from existing traces and scores only (`operating_points.py`): no sandbox run, no frozen file changed. "
         "Rates are `k/n = p% (Wilson 95 %)`; Wilson treats samples as independent, which the malware set is not "
         "(family F000 alone is 101 samples; see the cluster bootstrap below).", "",
         "**The threshold 40 is the pre-registered one** (`FREEZE_v3.md`). The other thresholds are shown for reference only; "
         "nothing here changes the scoring or the threshold.", ""]
    if mismatch:
        L.append(f"Note: {mismatch} scores in `labels_tiers.csv` differ from the summaries used here.")

    # ---- key figures
    f = lambda sc, tt: cell(*rate(sc, tt))
    m2 = [m["score"] for m in mal["v2"]]
    m3 = [m["score"] for m in mal["v3"]]
    L += ["## Key figures at the pre-registered threshold 40", "", "| | v2 | v3 |", "|---|---|---|",
          f"| recall, dev malware (verified) | {f(m2, 40)} | {f(m3, 40)} |",
          f"| FPR, dev new benign | {f([r['score'] for r in dev_ben['v2']], 40)} | {f([r['score'] for r in dev_ben['v3']], 40)} |",
          f"| FPR, held-out test benign | {f([r['score'] for r in test_ben['v2']], 40)} | {f([r['score'] for r in test_ben['v3']], 40)} |", ""]

    # ---- recall
    L += ["## 1a. Recall on the development malware", "",
          "Positives: label verified `malicious` (the 313 malware minus the benign_mislabel / grey / unknown_verify "
          "of the label review) with a complete run in the profile; tiers from `eval/v3/labels/labels_tiers.csv`. "
          "n differs between v2 and v3 because the runs that failed differ.", "",
          "| group | profile | " + " | ".join(f"≥ {t}" for t in THRESHOLDS) + " |", "|---|---|" + "---|" * len(THRESHOLDS)]
    for gname, f in groups:
        for p in P:
            sel = [m["score"] for m in mal[p] if f(m)]
            L.append(f"| {gname} (n = {len(sel)}) | {p} | " + " | ".join(cell(*rate(sel, t)) for t in THRESHOLDS) + " |")

    # ---- FPR
    L += ["", "## 1b. False-positive rate", "",
          "Development new benign: the 256 `benign_ext` extensions with the manifest label benign (grey excluded), complete runs. "
          "Test: the 192 benign extensions of the held-out set (8 grey excluded), run once on the frozen configuration.", "",
          "| set | profile | " + " | ".join(f"≥ {t}" for t in THRESHOLDS) + " |", "|---|---|" + "---|" * len(THRESHOLDS)]
    for sname, data in (("dev new benign", {p: [r["score"] for r in dev_ben[p]] for p in P}),
                        ("test benign", {p: [r["score"] for r in test_ben[p]] for p in P})):
        for p in P:
            sc = data[p]
            L.append(f"| {sname} (n = {len(sc)}) | {p} | " + " | ".join(cell(*rate(sc, t)) for t in THRESHOLDS) + " |")

    # ---- matched operating point
    ts3 = [r["score"] for r in test_ben["v3"]]
    ts2 = [r["score"] for r in test_ben["v2"]]
    k3 = sum(1 for s in ts3 if s >= 40)
    target = k3 / len(ts3)
    t2 = threshold_for(ts2, target)
    L += ["", "## 1c. v2 at the same test FPR as v3@40", "",
          f"v3 at 40 flags {k3} of {len(ts3)} test benign ({pct(target)}). The smallest v2 threshold with a test FPR no higher "
          f"than that is **{t2}**. This is a threshold chosen on the test set to match v3, so it shows what v2 would need to give up "
          "to reach v3's false-positive rate; it is not a v2 operating point anyone fixed in advance.", "",
          "| v2 threshold | test FPR | dev new benign FPR | recall all | recall T1 | recall T2 | recall T3 | recall without F000 |",
          "|---|---|---|---|---|---|---|---|"]
    for t in sorted({t2 - 2, t2 - 1, t2, t2 + 1}):
        if t < 0:
            continue
        sel = lambda f: [m["score"] for m in mal["v2"] if f(m)]
        L.append(f"| {t}{' **(matched)**' if t == t2 else ''} | {cell(*rate(ts2, t))} | {cell(*rate([r['score'] for r in dev_ben['v2']], t))} | "
                 + " | ".join(cell(*rate(sel(f), t)) for _, f in groups[:4] + [groups[4]]) + " |")
    dev2 = [r["score"] for r in dev_ben["v2"]]
    L += ["", f"At v2 threshold {t2} the dev new benign FPR is {cell(*rate(dev2, t2))}: the match holds on the test set only."]
    all2 = [m for m in mal["v2"]]
    lo_s, hi_s = boot_recall_fixed(all2, t2)
    lo_c, hi_c = boot_recall_fixed(all2, t2, cluster=True)
    (lo_j, hi_j), (tlo, thi) = boot_joint(all2, ts2, target)
    rec2 = sum(1 for m in all2 if m["score"] >= t2) / len(all2)
    all3 = mal["v3"]
    rec3 = sum(1 for m in all3 if m["score"] >= 40) / len(all3)
    l3s, h3s = boot_recall_fixed(all3, 40)
    l3c, h3c = boot_recall_fixed(all3, 40, cluster=True)
    L += ["", f"Bootstrap intervals (percentile, {BOOT} replicates, seed {SEED}), recall on all verified malware:", "",
          "| | recall | resampling samples | resampling families (cluster) | samples + test benign, threshold re-chosen |", "|---|---|---|---|---|",
          f"| v2 at {t2} (matched to v3@40) | {pct(rec2)} | {pct(lo_s)}–{pct(hi_s)} | {pct(lo_c)}–{pct(hi_c)} | "
          f"{pct(lo_j)}–{pct(hi_j)} (threshold {tlo}–{thi}) |",
          f"| v3 at 40 (pre-registered) | {pct(rec3)} | {pct(l3s)}–{pct(h3s)} | {pct(l3c)}–{pct(h3c)} | — |", "",
          "The family-cluster interval is the honest one for the malware: the replicates draw whole families, so F000 (101 of "
          f"{len(all2)} samples for v2) is either in or out. The last column adds the uncertainty of the 192 test benign extensions "
          "to the choice of the matched threshold."]

    # ---- false positives
    L += ["", "## 2. The v3 false positives on the test set (17 of 192)", "",
          "Extension names are replaced by FP-01…FP-17 (score order). Detectors are those of `score_v3.py` that fired; the cause is "
          "derived from the signals (host classes: first-party = a registrable domain of the extension's own tab or a token of its "
          "name; analytics SDK = well-known telemetry vendors).", "",
          "| id | category | score (v2 / v3) | detectors | cause |", "|---|---|---|---|---|"]
    fps = sorted((r for r in test_ben["v3"] if r["score"] >= 40), key=lambda r: (-r["score"], r["ext_id"]))
    v2s = {r["ext_id"]: r["score"] for r in test_ben["v2"]}
    causes = Counter()
    for k, r in enumerate(fps, 1):
        ev = json.loads((TEST / "traces_v3" / r["ext_id"] / "output" / "events.json").read_text(encoding="utf-8"))
        crx = REPO / "samples" / "benign_test" / f"{r['ext_id']}.crx"
        res = S.score_trace(ev, S.package_text(crx) if crx.exists() else None)
        fired, why = explain(ev, r["name"], res)
        heavy = "history" if res["signals"]["history_exfil"]["fired"] else (
            "persistent id" if res["signals"]["undeclared_domain_contact"].get("class") == "heavy" else "light signals")
        causes[heavy] += 1
        L.append(f"| FP-{k:02d} | {r['category']} | {v2s.get(r['ext_id'], '—')} / {r['score']} | {', '.join(fired)} | "
                 f"{IP_RE.sub('<ip>', why)} |")
    L += ["", "Summary of the 17:", "",
          f"- visited URL / title sent to a backend (`history_exfil`, heavy): {causes['history']} (whether this is the extension's function or analytics is not decided here)",
          f"- persistent identifier (UUID seen in two phases) sent to an undeclared host (`undeclared_domain_contact`, heavy): {causes['persistent id']}",
          f"- only light signals adding up to ≥ 40 (extension-opened tab + undeclared hosts + own UI / page wrapper / periodic requests): {causes['light signals']}"]

    # ---- performance
    L += ["", "## 3. Performance", "",
          "Run time = `duration_s` of `meta.json` (container wall time per extension, 2 workers in parallel, includes start-up and the "
          "180 s timeout when hit). Trace size = `events.json`; the output folder adds `capture.pcap` and the screenshots. "
          "Counts are run statuses of the traces on disk.", "",
          "| set | n | complete | partial | failed | time median / p90 / max (s) | events.json median / p90 / max | output folder median |",
          "|---|---|---|---|---|---|---|---|"]
    for name, rows in perf_rows():
        c = Counter(r["status"] for r in rows)
        d = [r["dur"] for r in rows if r["dur"] is not None]
        e = [r["events"] for r in rows if r["events"] is not None]
        tot = [r["total"] for r in rows if r["total"]]
        L.append(f"| {name} | {len(rows)} | {c['complete']} | {c['partial']} | {c['failed']} | "
                 f"{q(d, .5):g} / {q(d, .9):g} / {max(d):g} | {fmt_kb(q(e, .5))} / {fmt_kb(q(e, .9))} / {fmt_kb(max(e) if e else None)} | "
                 f"{fmt_kb(q(tot, .5))} |")
    (HERE / "results.md").write_text("\n".join(L) + "\n", encoding="utf-8", newline="\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
