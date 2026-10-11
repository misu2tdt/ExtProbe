"""make_dossiers.py -- blind labelling dossiers for the in-the-wild audit (CRITERIA.md section 7, amendment 1).

  py -I eval/v3/in_the_wild/make_dossiers.py --samples <dir with A/ and B/> --private <dir outside the repo>

Audit list (CRITERIA A1.2): flagged samples of A (all if <= 60, else 60 drawn with Random(2026) over the sorted IDs) +
20 unflagged complete samples of A (Random(2026) over the sorted IDs) + every flagged sample of B. The list is shuffled with
Random(2026) and coded L-001... Reads the flags from <private>/flags_{A,B}.csv (written by analysis.py).
Writes, ALL OUTSIDE the repository, into <private>/labeling/:
  dossiers/L-xxx.md   raw evidence only: no score, no detector name, no flag, no set (A/B)
  mapping.csv         code -> ID, set, flag, score        (do not open until the labels are reconciled)
  rater_1.csv, rater_2.csv   empty sheets
Evidence comes from the trace (events.json) and the package (read in memory); IP addresses are masked.
"""
import argparse
import csv
import json
import random
import re
import sys
import time
import zipfile
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO / "eval" / "v3"))
sys.path.insert(0, str(REPO / "eval"))
import score_v3 as S  # noqa: E402  (only its raw helpers: extension-initiated requests, visited pages, UUIDs)
sys.path.insert(0, str(HERE))
from fetch_itw import http  # noqa: E402

SEED = 2026
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+(?:@|%40)[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
COOKIE_RE = re.compile(r"(?i)\b(cookie|sessionid|session_id|sid|auth|token|bearer|csrf|password|passwd)\b")


def mask(s):
    return IP_RE.sub("<ip>", s or "")


def clip(s, n=300):
    s = mask(str(s))
    return s if len(s) <= n else s[:n] + " ..."


def listing(i):
    code, final, b = http(f"https://chromewebstore.google.com/detail/{i}", 3_000_000, 60)
    t = b.decode("utf-8", "replace") if isinstance(b, bytes) else ""
    live = code == 200 and "/detail/empty-title/" not in final and "Add to Chrome" in t
    pp = sorted({u for u in re.findall(r"https?://[^\"'\\\s<>]+", t)
                 if re.search(r"privacy|policy", u, re.I) and not re.search(r"google\.com|gstatic|googleapis|schema\.org", u)})
    return live, final if live else "", pp[:3]


def pkg_files(crx):
    with zipfile.ZipFile(crx) as z:
        return {n: z.read(n).decode("utf-8", "replace") for n in z.namelist() if not n.endswith("/") and n.lower().endswith((".js", ".html"))}


def excerpt(files, needle, radius=12, max_lines=80):
    for name in sorted(files):
        txt = files[name]
        pos = txt.find(needle)
        if pos < 0:
            continue
        lines = txt.splitlines()
        if len(lines) <= 3:                              # minified: character window
            lo = max(0, pos - 150)
            return name, 1, mask(txt[lo:pos + 150])
        ln = txt[:pos].count("\n")
        a, b = max(0, ln - radius), min(len(lines), ln + radius + 1)
        b = min(b, a + max_lines)
        return name, a + 1, "\n".join(mask(l[:300]) for l in lines[a:b])
    return None


def dossier(code, i, ev, crx, flag_unused=None):
    mf = ev.get("manifest") or {}
    live, url, pp = listing(i)
    time.sleep(1.0)
    L = [f"# Dossier {code}", "",
         "Raw evidence from one 45-second sandbox run and from the package. No score, no detector name, no flag. "
         "Judge each item yourself against `LABELING_GUIDE.md`.", "",
         "## Listing", "",
         f"- Chrome Web Store listing: https://chromewebstore.google.com/detail/{i}  ({'page alive' if live else 'page not alive (removed or unavailable)'})",
         "- Privacy policy link(s) found in the listing: " + (", ".join(pp) if pp else "none found automatically (open the listing, section Privacy practices)"),
         "", "## Manifest", "",
         f"- name: {clip(mf.get('name'), 100)}   version: {mf.get('version')}   manifest_version: {mf.get('manifest_version')}",
         f"- description: {clip(mf.get('description'), 200)}",
         f"- permissions: {mf.get('permissions')}   optional: {mf.get('optional_permissions')}",
         f"- host_permissions: {mf.get('host_permissions')}",
         f"- background: {mf.get('background')}",
         f"- content_scripts: {[{'matches': c.get('matches'), 'js': c.get('js'), 'run_at': c.get('run_at')} for c in mf.get('content_scripts') or []][:4]}",
         f"- chrome_settings_overrides: {mf.get('chrome_settings_overrides')}   chrome_url_overrides: {mf.get('chrome_url_overrides')}",
         f"- externally_connectable: {mf.get('externally_connectable')}   update_url: {clip(mf.get('update_url'), 120)}"]

    # requests
    reqs = S.ext_requests(ev)
    needles = S.visited_needles(ev)
    L += ["", "## Requests initiated by the extension (service worker, or page requests whose caller is the extension)", ""]
    if not reqs:
        L.append("none recorded")
    seen = {}
    for r in reqs:
        text = r["url"] + " " + r["body"]
        variants = S.surface_variants(text)
        matched = sorted({meta["kind"] + ": " + meta["value"][:60] for n, meta in needles.items() for _, t in variants if n in t})
        key = (r["host"], r["method"], urlparse(r["url"]).path)
        e = seen.setdefault(key, {"n": 0, "r": r, "matched": set(), "uuid": False, "email": False, "cookie": False})
        e["n"] += 1
        e["matched"].update(matched)
        e["uuid"] |= bool(S.UUID4_RE.search(text))
        e["email"] |= bool(EMAIL_RE.search(text))
        e["cookie"] |= bool(COOKIE_RE.search(text))
    L += ["| host | method | caller | count | path | URL / title of a visited page in URL or body | UUID | e-mail-like | cookie / token-like word |",
          "|---|---|---|---|---|---|---|---|---|"]
    for (h, m, p), e in list(seen.items())[:40]:
        L.append(f"| {mask(h)} | {m} | {e['r']['via']} | {e['n']} | {clip(p, 60)} | {clip('; '.join(sorted(e['matched'])) or 'no', 120)} | "
                 f"{'yes' if e['uuid'] else 'no'} | {'yes' if e['email'] else 'no'} | {'yes' if e['cookie'] else 'no'} |")
    L += ["", "Excerpts (URL query and POST body, at most 300 characters each; first request per host/path):", ""]
    shown = 0
    for (h, m, p), e in seen.items():
        r = e["r"]
        q = urlparse(r["url"]).query
        if (q or r["body"]) and shown < 8:
            L.append(f"- {mask(h)} {m}: query `{clip(q)}`  body `{clip(r['body'])}`")
            shown += 1
    if shown == 0:
        L.append("- (no query string and no body in the recorded requests)")
    L.append(f"- honeypot values (fake login / mail pages of the harness) seen leaving the browser: {bool(ev.get('honeypot_exfil'))}")

    # tabs
    tabs = [t for t in ev.get("tabs_v3") or [] if t.get("opened_by") != "harness"]
    L += ["", "## Tabs opened by the extension", ""]
    if not tabs and not ev.get("sw_tab_calls"):
        L.append("none")
    for t in tabs[:10]:
        L.append(f"- opened in phase `{t.get('opened_phase')}` {round(t.get('t_since_install') or 0, 1)} s after install: "
                 f"{clip(t.get('first_url'), 150)} -> {clip(t.get('final_url'), 150)}; redirects: {len(t.get('redirects') or [])}")
    for c in (ev.get("sw_tab_calls") or [])[:10]:
        L.append(f"- service worker called `{c.get('api')}` with {clip(c.get('url'), 150)}")

    # DOM
    dom = [d for d in ev.get("dom_node_initiators") or [] if d.get("attributed") == "extension"]
    L += ["", "## DOM nodes inserted into pages by the extension", ""]
    L += [f"- <{d.get('tag')}> src: {clip(d.get('src'), 150)}" for d in dom[:15]] or ["none"]

    # hooks
    hooks = {tuple(h.get("replaced") or []) for h in ev.get("page_api_hooks") or [] if h.get("replaced")}
    L += ["", "## Page APIs replaced (fetch / XMLHttpRequest / WebSocket)", ""]
    L += [f"- {list(h)}" for h in sorted(hooks)] or ["none"]

    # api calls
    L += ["", "## Extension API calls recorded", ""]
    api = ev.get("api_calls") or []
    for a in api[:15]:
        L.append(f"- {a.get('api')}: {clip(json.dumps(a.get('args'), ensure_ascii=False), 200)}")
    if not api:
        L.append("none")

    # code
    L += ["", "## Code excerpts (from the package; at most 80 lines each, long lines cut)", ""]
    files = pkg_files(crx)
    needles_code = []
    for (h, m, p) in list(seen)[:4]:
        needles_code.append(("request host " + mask(h), h))
    needles_code += [("setUninstallURL", "setUninstallURL"), ("tabs.create", "tabs.create"), ("cookies API", "chrome.cookies"),
                     ("script injection", "executeScript"), ("dynamic code", "new Function("), ("dynamic code", "eval(")]
    n = 0
    for lab, nd in needles_code:
        ex = excerpt(files, nd)
        if ex and n < 8:
            fn, ln, body = ex
            L += [f"### {lab} -- `{fn}` from line {ln}", "", "```", body, "```", ""]
            n += 1
    if n == 0:
        L.append("no matching code found for the evidence above")
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", required=True)
    ap.add_argument("--private", required=True)
    a = ap.parse_args()
    priv = Path(a.private)
    flags = {}
    for s in ("A", "B"):
        for r in csv.DictReader(open(priv / f"flags_{s}.csv", encoding="utf-8")):
            flags[(s, r["ext_id"])] = r
    fa = sorted(i for (s, i), r in flags.items() if s == "A" and r["flag"] == "1")
    ua = sorted(i for (s, i), r in flags.items() if s == "A" and r["flag"] == "0" and r["run_status"] == "complete")
    fb = sorted(i for (s, i), r in flags.items() if s == "B" and r["flag"] == "1")
    if len(fa) > 60:
        fa = sorted(random.Random(SEED).sample(fa, 60))
    ua = sorted(random.Random(SEED).sample(ua, 20))
    items = [("A", i) for i in fa] + [("A", i) for i in ua] + [("B", i) for i in fb]
    random.Random(SEED).shuffle(items)
    out = priv / "labeling"
    (out / "dossiers").mkdir(parents=True, exist_ok=True)
    mp = []
    for n, (s, i) in enumerate(items, 1):
        code = f"L-{n:03d}"
        tdir = HERE / ("traces_A" if s == "A" else "traces_B")
        ev = json.loads((tdir / i / "output" / "events.json").read_text(encoding="utf-8"))
        text = dossier(code, i, ev, Path(a.samples) / s / f"{i}.crx")
        (out / "dossiers" / f"{code}.md").write_text(text, encoding="utf-8")
        r = flags[(s, i)]
        mp.append([code, i, s, r["flag"], r["score"]])
    with open(out / "mapping.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["code", "ext_id", "set", "flag", "score"])
        w.writerows(mp)
    for k in (1, 2):
        with open(out / f"rater_{k}.csv", "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["code", "label", "evidence", "notes"])
            for n in range(1, len(items) + 1):
                w.writerow([f"L-{n:03d}", "", "", ""])
    print(len(items), "dossiers:", len(fa), "flagged A,", len(ua), "unflagged A,", len(fb), "flagged B")


if __name__ == "__main__":
    main()
