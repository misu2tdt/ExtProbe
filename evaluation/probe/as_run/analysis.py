"""analysis.py -- results of the v3.1-probe trial, exactly the measures of eval/v3_1_probe/CRITERIA.md.

  py eval/v3_1_probe/analysis.py [--traces-root eval/v3_1_probe] [--out eval/v3_1_probe/results.md]

Aggregates only: no extension id is printed or written. Traces: <root>/traces_{a,b,c}/<id>/; selected ids:
..\\itw\\probe\\selected_{a,b,c}.txt; earlier v3 traces of the same packages: eval/v3/in_the_wild/traces_A (a, c) and
eval/v3/test/traces_v3 (b).
"""
import argparse
import json
import statistics as st
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
ITW = REPO.parent / "itw"
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(REPO / "eval"))
import score_v31 as V  # noqa: E402  (puts eval/v3 on the path)
import score_v3 as S  # noqa: E402
from expanded_analysis import wilson, pct  # noqa: E402

SETS = {"a": {"pkg": ITW / "A", "v3": REPO / "eval/v3/in_the_wild/traces_A", "label": "(a) set A, silent under v3"},
        "b": {"pkg": REPO / "samples/benign_test", "v3": REPO / "eval/v3/test/traces_v3", "label": "(b) test benign"},
        "c": {"pkg": ITW / "A", "v3": REPO / "eval/v3/in_the_wild/traces_A", "label": "(c) T2 listed by Socket (case study)"}}


def rate(k, n):
    if not n:
        return "n/a"
    lo, hi = wilson(k, n)
    return f"{k}/{n} = {pct(k / n)} ({pct(lo)}–{pct(hi)})"


def q(vals, p):
    vals = sorted(v for v in vals if v is not None)
    return vals[int(round(p * (len(vals) - 1)))] if vals else None


def load_set(key, root, ids):
    rows = []
    for i in ids:
        d = root / f"traces_{key}" / i
        evp, prp = d / "output" / "events.json", d / "output" / "events_probe.json"
        meta = json.loads((d / "meta.json").read_text(encoding="utf-8")) if (d / "meta.json").exists() else {}
        if not evp.exists():
            rows.append({"status": "missing", "docker_exit": meta.get("docker_exit")})
            continue
        pre = json.loads(evp.read_text(encoding="utf-8"))
        post = json.loads(prp.read_text(encoding="utf-8")) if prp.exists() else {}
        crx = SETS[key]["pkg"] / f"{i}.crx"
        r = V.score_run(pre, post, S.package_text(crx) if crx.exists() else None)
        r["status"] = (pre.get("run_status") or {}).get("status")
        r["probe_present"] = bool(post)
        r["duration_s"] = meta.get("duration_s")
        old = SETS[key]["v3"] / i / "output" / "events.json"
        if old.exists():
            r["old_v3_score"] = S.score_trace(json.loads(old.read_text(encoding="utf-8")), S.package_text(crx) if crx.exists() else None)["score"]
        rows.append(r)
    return rows


def section(key, rows):
    L = [f"## {SETS[key]['label']}", ""]
    comp = [r for r in rows if r.get("status") == "complete" and r.get("probe_present")]
    n = len(comp)
    L.append(f"Runs: {len(rows)} selected, {n} complete with a probe file; "
             f"other: {dict((s, sum(1 for r in rows if r.get('status') == s)) for s in {r.get('status') for r in rows} if s != 'complete')}.")
    if not n:
        return L + [""]
    P = lambda r: r["probe"]  # noqa: E731
    L += ["", "| measure | value |", "|---|---|",
          f"| **elicitation yield** (proxy, DNR or new extension host) | {rate(sum(P(r)['yield'] for r in comp), n)} |",
          f"| — proxy configured | {rate(sum(P(r)['proxy_configured'] for r in comp), n)} |",
          f"| — DNR rules changed | {rate(sum(bool(P(r)['dnr_changed']) for r in comp), n)} |",
          f"| — new extension host | {rate(sum(P(r)['new_extension_hosts'] > 0 for r in comp), n)} |",
          f"| storage changed (reported apart) | {rate(sum(P(r)['storage_changed'] for r in comp), n)} |",
          f"| pages declared / opened (samples with ≥ 1 opened) | {sum(len(P(r)['pages_declared']) for r in comp)} / {rate(sum(P(r)['pages_opened'] > 0 for r in comp), n)} |",
          f"| clicks per sample (median / max) | {q([P(r)['clicks'] for r in comp], .5)} / {max(P(r)['clicks'] for r in comp)} |",
          f"| login_gate | {rate(sum(P(r)['login_gate'] for r in comp), n)} |",
          f"| flag @40: v3 (events.json) → v3.1 view, up / down — with beaconing | {sum((not r['flag_v3']) and r['flag_v31'] for r in comp)} / {sum(r['flag_v3'] and not r['flag_v31'] for r in comp)} |",
          f"| flag @40, up / down — without beaconing (its weight left out of both scores) | "
          f"{sum((not r['flag_v3_nobeacon']) and r['flag_v31_nobeacon'] for r in comp)} / {sum(r['flag_v3_nobeacon'] and not r['flag_v31_nobeacon'] for r in comp)} |",
          f"| flag changes due ONLY to beaconing (reported apart, NOT a probe effect; amendment 3) | "
          f"{sum(r['flag_change_beacon_only'] for r in comp)} |",
          f"| flag changes attributable to the probe (with beaconing, minus beaconing-only), up / down | "
          f"{sum((not r['flag_v3']) and r['flag_v31'] and not r['flag_change_beacon_only'] for r in comp)} / "
          f"{sum(r['flag_v3'] and not r['flag_v31'] and not r['flag_change_beacon_only'] for r in comp)} |",
          f"| score changed (v3.1 view ≠ v3) | {sum(r['v31_score'] != r['v3_score'] for r in comp)} |",
          f"| extra time per sample, s (median / p90) | {q([P(r)['extra_s'] for r in comp], .5)} / {q([P(r)['extra_s'] for r in comp], .9)} |",
          f"| run time per sample, s (median / p90) | {q([r['duration_s'] for r in comp], .5)} / {q([r['duration_s'] for r in comp], .9)} |",
          f"| proxy guard: set() calls intercepted after the probe start (samples / calls) | "
          f"{sum(P(r)['proxy_set_calls'] > 0 for r in comp)} / {sum(P(r)['proxy_set_calls'] for r in comp)} |",
          f"| proxy guard: managed policy confirmed in the run (chrome://policy at the probe start, or real get; must be all) | {sum(bool(P(r)['policy_in_force']) for r in comp)} / {n} |",
          f"| proxy guard: proxy_unwrapped_set (effective config not direct; must be 0) | {sum(P(r)['proxy_unwrapped_set'] for r in comp)} |",
          f"| controls never clicked: unlabeled / non-English (total) | {sum(P(r)['skipped_unlabeled'] for r in comp)} / "
          f"{sum(P(r)['skipped_non_english'] for r in comp)} |"]
    old = [r for r in comp if r.get("old_v3_score") is not None]
    L.append(f"| consistency: score_v3(events.json) vs the earlier v3 trace, equal / higher / lower | "
             f"{sum(r['v3_score'] == r['old_v3_score'] for r in old)} / {sum(r['v3_score'] > r['old_v3_score'] for r in old)} / "
             f"{sum(r['v3_score'] < r['old_v3_score'] for r in old)} (of {len(old)}) |")
    if key == "b":
        L.append(f"| benign newly flagged by the v3.1 view (with beaconing) | {rate(sum((not r['flag_v3']) and r['flag_v31'] for r in comp), n)} |")
        L.append(f"| benign newly flagged, beaconing-only changes excluded | "
                 f"{rate(sum((not r['flag_v3']) and r['flag_v31'] and not r['flag_change_beacon_only'] for r in comp), n)} |")
    if key == "c":
        r = comp[0]
        L += ["", f"Case study: pages opened {P(r)['pages_opened']} of {len(P(r)['pages_declared'])}, clicks {P(r)['clicks']}, "
                  f"login_gate {P(r)['login_gate']}, proxy configured {P(r)['proxy_configured']}, new hosts "
                  f"{P(r)['new_extension_hosts']}, score v3 {r['v3_score']} → v3.1 {r['v31_score']}."]
    return L + [""]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces-root", default=str(HERE))
    ap.add_argument("--selected", default=str(ITW / "probe"))
    ap.add_argument("--out", default=str(HERE / "results.md"))
    a = ap.parse_args()
    root = Path(a.traces_root)
    L = ["# v3.1-probe trial: results (exploratory)", "",
         "Generated by `analysis.py` with the measures of `CRITERIA.md`. **Exploratory: no primary result is replaced.** "
         "Yield and flag changes compare two views of the same run (`events.json` = the v3 part, scored by the unchanged "
         "`score_v3`; the `score_v31` view adds probe behaviour that a click did not directly cause). Rates are Wilson 95 %. "
         "The main metric (yield) does not depend on `beaconing`; a flag change due only to `beaconing` (unstable near its "
         "threshold, DESIGN §11) is reported apart and not counted as a probe effect (CRITERIA amendment 3).", ""]
    for key in ("a", "b", "c"):
        f = Path(a.selected) / f"selected_{key}.txt"
        ids = [l.strip() for l in f.read_text(encoding="utf-8").splitlines() if l.strip()] if f.exists() else []
        L += section(key, load_set(key, root, ids))
    Path(a.out).write_text("\n".join(L) + "\n", encoding="utf-8", newline="\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
