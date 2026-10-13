"""provenance_counts.py -- per-pattern request counts for the attribution check on the canary / demo fixture (examples/canary, examples/demo).

  python evaluation/probe/provenance_counts.py --traces <run dir> [<run dir> ...] [--out provenance_counts.md]

Each <run dir> holds output/events.json of one v3 run of the fixture (a run of `extprobe analyze examples/canary` or `examples/demo`: `<out>/traces/run`).
Ground truth is known by construction: the fixture's own code decides which host each request goes to (examples/canary/content.js, sw.js, target_probe.js;
the page's own request is in sandbox/base/honey_pages/universal.html). PATTERNS maps each host to the pattern, the true context and the record type
that carries the attribution. A request is *correct* when the recorded attribution equals the true context:
  service worker  -> a request recorded by the CDP service-worker session (`network_requests`, origin service_worker, source cdp_sw)
  content script  -> `page_request_initiators` record attributed `extension` whose outermost extension frame is a content script file of the manifest
  page            -> `page_request_initiators` record attributed `page`
Requests the harness itself starts (navigations of its pages) have no script initiator, are labelled `unknown` by design and are listed apart.
Output: counts only, no extension ids.
"""
import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlparse

# host -> (pattern, true context, record kind)
PATTERNS = {
    "canary-c2.invalid": ("P1 service-worker fetch", "service worker", "sw"),
    "canary-beacon.invalid": ("P2 service-worker call deferred with setTimeout", "service worker", "sw"),
    "canary-cs.invalid": ("P3 content-script fetch (top level, isolated world)", "content script", "page"),
    "canary-target-hit.invalid": ("P4 content-script fetch on a target-matched page", "content script", "page"),
    "canary-inject.invalid": ("P5 <script src> created by a content script", "content script", "page"),
    "canary-frame.invalid": ("P6 <iframe src> created by a content script", "content script", "page"),
    "canary-page.invalid": ("P7 page inline-script fetch", "page", "page"),
    "example.com": ("P8 page parser-initiated <script src>", "page", "page"),
    "canary-target.invalid": ("P9 page parser-initiated media load", "page", "page"),
}
# P8 / P9 are single record types on shared hosts; only these (host, resource_type) pairs belong to the pattern
ONLY_TYPES = {"example.com": {"Script"}, "canary-target.invalid": {"Media"}}


def context_of(ev, rec):
    """'service worker' / 'content script' / 'extension (other)' / 'page' / 'unknown' from the recorded attribution."""
    who = rec.get("attributed")
    if who != "extension":
        return who
    cs = {f for c in (ev.get("manifest") or {}).get("content_scripts") or [] for f in c.get("js") or []}
    frames = [re.sub(r"^chrome-extension://[a-p]{32}/", "", f) for f in rec.get("ext_frames") or []]
    return "content script" if frames and frames[-1] in cs else "extension (other)"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--traces", nargs="+", required=True)
    ap.add_argument("--out", default=str(Path(__file__).with_name("provenance_counts.md")))
    a = ap.parse_args(argv)
    total = defaultdict(lambda: [0, 0])      # pattern -> [requests, correct]
    per_run = []
    wrong, unmapped, unknown = [], Counter(), Counter()
    for d in a.traces:
        ev = json.loads((Path(d) / "output" / "events.json").read_text(encoding="utf-8"))
        run = defaultdict(lambda: [0, 0])
        for r in ev.get("network_requests", []):
            if r.get("origin") != "service_worker":
                continue
            h = urlparse(r["url"]).hostname
            pat = PATTERNS.get(h)
            if not pat or pat[2] != "sw":
                unmapped[("service worker", h)] += 1
                continue
            ok = r.get("source") == "cdp_sw"
            run[pat[0]][0] += 1
            run[pat[0]][1] += ok
            if not ok:
                wrong.append((pat[0], h, "service worker request not recorded by the CDP session"))
        for r in ev.get("page_request_initiators", []):
            h = urlparse(r["url"]).hostname
            pat = PATTERNS.get(h)
            if r.get("attributed") == "unknown":
                unknown[(h, r.get("resource_type"))] += 1
                continue
            if not pat or pat[2] != "page" or (h in ONLY_TYPES and r.get("resource_type") not in ONLY_TYPES[h]):
                unmapped[("page request", h, r.get("resource_type"))] += 1
                continue
            got = context_of(ev, r)
            run[pat[0]][0] += 1
            run[pat[0]][1] += got == pat[1]
            if got != pat[1]:
                wrong.append((pat[0], h, f"attributed {got}, expected {pat[1]}"))
        per_run.append((Path(d), run))
        for k, (n, c) in run.items():
            total[k][0] += n
            total[k][1] += c
    order = [v[0] for v in PATTERNS.values()]
    L = ["# Attribution check on the canary / demo fixture: requests per pattern", "",
         f"Generated by `evaluation/probe/provenance_counts.py` on {len(a.traces)} v3 runs of the fixture. Counts only, no extension ids.", "",
         "**Ground truth.** The fixture's code decides, by construction, which host each request goes to, so the true context of every counted request is known before "
         "the run (hosts and their sources: `examples/canary/content.js`, `sw.js`, `target_probe.js`; the page's own request: `sandbox/base/honey_pages/universal.html`). "
         "A request is counted as correct when the recorded attribution equals the true context (service worker, content script or page; the content-script vs other-extension-code "
         "distinction is read from the outermost extension frame against the manifest's `content_scripts` files). One request per page visit is recorded, so a pattern has "
         "several requests per run.", "",
         "| pattern | true context | requests | correct |", "|---|---|---|---|"]
    allr = allc = 0
    for name in order:
        n, c = total.get(name, [0, 0])
        ctx = next(v[1] for v in PATTERNS.values() if v[0] == name)
        L.append(f"| {name} | {ctx} | {n} | {c} |")
        allr += n
        allc += c
    L += [f"| **all nine patterns** | | **{allr}** | **{allc}** |", "", "Per run:", "", "| run | requests | correct |", "|---|---|---|"]
    for i, (d, run) in enumerate(per_run, 1):
        L.append(f"| run {i} | {sum(v[0] for v in run.values())} | {sum(v[1] for v in run.values())} |")
    L += ["", "## Requests not assigned, or assigned wrongly", ""]
    L.append(f"- Wrongly attributed (among the {allr} counted): " + (str(len(wrong)) + " " + "; ".join(f"{p} @ {h}: {m}" for p, h, m in wrong) if wrong else "none."))
    L.append("- Not assignable by design (browser-initiated: the harness navigating its own pages; no script initiator, label `unknown`): "
             + (", ".join(f"{h} {t} x{n}" for (h, t), n in sorted(unknown.items())) or "none") + ".")
    L.append("- Recorded requests outside the nine patterns (not counted): " + (", ".join(f"{'/'.join(str(x) for x in k)} x{n}" for k, n in sorted(unmapped.items(), key=str)) or "none") + ".")
    Path(a.out).write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L[6:]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
