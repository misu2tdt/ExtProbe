"""evidence.py -- per-sample evidence sheet for the audit (AUDIT_CRITERIA.md). Not scores.

  py eval/v3/audit/evidence.py <out_dir> [ext_id ...]     # default: every row of sample.csv

For each sample: unpacks the .crx into <out_dir>/pkg/<ext_id>/ (outside the repo), greps the code
for behaviour patterns (file:line + a short snippet), and summarises the v3 trace (requests with
status / errors, tabs and redirects, setUninstallURL, eval / Function calls, injected nodes,
API hooks). Writes <out_dir>/ev/<ext_id>.txt. Nothing here is committed except this script.
"""
import csv
import json
import re
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
TRACES = HERE.parent / "dev" / "traces"
SAMPLE_DIRS = ["samples/malware", "samples/benign", "../sample/cws_benign_crx", "samples/benign_ext"]
PATTERNS = {
    "remote_code": r"\beval\s*\(|new Function\s*\(|importScripts\s*\(|setTimeout\(\s*['\"]|executeScript|userScripts|"
                   r"createElement\(\s*['\"]script|\.src\s*=\s*['\"`]https?:|insertAdjacentHTML|document\.write\(",
    "network": r"\bfetch\s*\(|XMLHttpRequest|sendBeacon|new WebSocket|\$\.(ajax|get|post)\(|axios",
    "tabs": r"tabs\.(create|update|query|onUpdated|onActivated|onCreated)|windows\.create|setUninstallURL|onInstalled|webNavigation",
    "user_data": r"chrome\.history|chrome\.cookies|document\.cookie|\bpassword\b|chrome\.bookmarks|getAllInWindow|"
                 r"chrome\.management|clipboard|chrome\.downloads|tab\.url|tabs\[0\]\.url|location\.href",
    "search_newtab": r"chrome_settings_overrides|search_provider|chrome_url_overrides|newtab|search_url|omnibox|keyword",
    "web_request": r"webRequest|declarativeNetRequest|updateDynamicRules|onBeforeRequest|redirectUrl|regexSubstitution",
    "ads_affiliate": r"[?&](tag|aff|affid|aff_id|ref|clickid|subid|utm_source)=|affiliate|s\.click\.|amzn|admitad|"
                     r"\bads?\b|banner|popunder|monetiz",
    "obfuscation": r"_0x[0-9a-f]{4}|atob\s*\(|String\.fromCharCode|\\x[0-9a-f]{2}\\x[0-9a-f]{2}|unescape\(",
}
CODE_EXT = (".js", ".mjs", ".html", ".json")
URL_RE = re.compile(r"https?://[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?::\d+)?[^\s'\"`<>)]*")
IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
SKIP_HOSTS = ("w3.org", "mozilla.org", "jquery", "googleapis.com/css", "schema.org", "fb.me", "reactjs.org",
              "github.com", "npmjs", "momentjs", "polyfill", "babeljs", "feross", "lodash", "opensource.org")


def short(s, n=140):
    s = IP_RE.sub("<ip>", s.replace("\n", " "))
    return s if len(s) <= n else s[:n] + "…"


def redact_url(u):
    p = urlparse(u)
    q = "?" + "&".join(kv.split("=")[0] + "=…" for kv in p.query.split("&") if kv) if p.query else ""
    return IP_RE.sub("<ip>", f"{p.scheme}://{p.netloc}{p.path[:80]}{q}")


def unpack(crx, dst):
    if dst.exists() and any(dst.iterdir()):
        return
    dst.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(crx) as z:
        for n in z.namelist():
            if n.endswith("/") or ".." in n or n.startswith("/"):
                continue
            p = dst / n
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(z.read(n))


def grep(pkg, out):
    hits = defaultdict(list)
    hosts = Counter()
    files = [p for p in pkg.rglob("*") if p.is_file() and p.suffix.lower() in CODE_EXT]
    sizes = sorted(((p.stat().st_size, p) for p in files if p.suffix.lower() in (".js", ".mjs")), reverse=True)
    out.append("files: " + ", ".join(f"{p.relative_to(pkg).as_posix()} ({s // 1024} kB)" for s, p in sizes[:12]))
    for p in files:
        rel = p.relative_to(pkg).as_posix()
        if "_locales/" in rel:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for u in URL_RE.findall(text):
            h = urlparse(u).netloc.lower()
            if h and not any(s in u for s in SKIP_HOSTS):
                hosts[h] += 1
        lines = text.split("\n")
        for ln, line in enumerate(lines, 1):
            for name, pat in PATTERNS.items():
                for m in re.finditer(pat, line, re.I):
                    if len(hits[name]) >= 14:
                        break
                    a = max(0, m.start() - 60)
                    hits[name].append(f"{rel}:{ln} …{short(line[a:m.end() + 70], 160)}")
    out.append("hosts in code: " + ", ".join(f"{h}({c})" for h, c in hosts.most_common(25)))
    for name in PATTERNS:
        if hits[name]:
            out.append(f"[{name}] {len(hits[name])}{'+' if len(hits[name]) >= 14 else ''}")
            out += ["   " + h for h in hits[name]]


def trace(ev, out):
    rs = ev.get("run_status") or {}
    out.append(f"run: {rs.get('status')} {rs.get('reason') or ''} phases={[(p['name'], p.get('status')) for p in ev.get('phases', [])]}")
    out.append(f"load: {ev.get('v3_load')}  sw: {[s.get('url') for s in ev.get('service_workers', [])][:2]}  "
               f"sw_hooked: {len(ev.get('v3_sw_hooked') or [])}")
    errs = [e for e in ev.get("errors", []) if "v3_post" not in e][:6]
    if errs:
        out.append("errors: " + " | ".join(short(e, 110) for e in errs))
    apis = Counter(a.get("api") for a in ev.get("api_calls", []))
    out.append(f"api_calls: {dict(apis)}")
    for a in ev.get("api_calls", []):
        if a.get("api") in ("runtime.setUninstallURL",):
            out.append(f"   uninstall: {redact_url(str((a.get('args') or [''])[0]))}")
            break
    for a in [a for a in ev.get("api_calls", []) if a.get("api") in ("eval", "Function")][:6]:
        out.append(f"   {a['api']}: {short(str(a.get('preview')), 120)}")
    for c in ev.get("sw_tab_calls", [])[:5]:
        out.append(f"   sw_tab_call {c.get('api')} {redact_url(c.get('url') or '')} t={c.get('t_since_install')}")
    sw = [r for r in ev.get("network_requests", []) if r.get("origin") == "service_worker"
          and (r.get("source") == "cdp_sw" or (r.get("resource_type") or "")[:1].isupper())]
    out.append(f"SW requests: {len(sw)}")
    for r in sw[:25]:
        body = (r.get("response_body") or "")
        st = r.get("response_status") or r.get("response_error") or "-"
        out.append(f"   {r.get('method')} {redact_url(r['url'])} -> {st} len={r.get('response_body_len')} "
                   f"post={r.get('post_data_len') or 0} | {short(body, 100)}")
    pe = [r for r in ev.get("page_request_initiators", []) if r.get("attributed") == "extension"]
    out.append(f"extension-initiated page requests: {len(pe)}")
    for r in pe[:15]:
        st = r.get("response_status") or r.get("response_error") or "-"
        out.append(f"   {r.get('method')} {r.get('resource_type')} {redact_url(r['url'])} -> {st} "
                   f"from {(r.get('ext_frames') or ['?'])[0].split('/', 3)[-1][:40]}")
    fails = Counter()
    for r in ev.get("page_request_initiators", []):
        if r.get("response_error"):
            fails[(urlparse(r["url"]).netloc, r["response_error"][:30])] += 1
    for r in ev.get("network_requests", []):
        if r.get("response_error"):
            fails[(urlparse(r["url"]).netloc, r["response_error"][:30])] += 1
    if fails:
        out.append("network errors: " + ", ".join(f"{h} {e} x{n}" for (h, e), n in fails.most_common(8)))
    for t in ev.get("tabs_v3", []):
        if t.get("opened_by") == "harness":
            continue
        chain = [t.get("first_url") or t.get("initial_url")] + [u for r in t.get("redirects") or []
                                                                for u in r.get("redirect_chain") or []] + [t.get("final_url")]
        chain = list(dict.fromkeys(u for u in chain if u))
        out.append(f"tab (ext_opened={t.get('extension_opened')}, t={t.get('t_since_install')}): "
                   + " => ".join(redact_url(u) for u in chain) + f" | titles {[x.get('title') for x in t.get('titles') or []][:2]}")
    nodes = [n for n in ev.get("dom_node_initiators", []) if n.get("attributed") == "extension"]
    if nodes:
        out.append("extension-created nodes: " + "; ".join(f"{n.get('tag')} {redact_url(n.get('src') or '') if (n.get('src') or '').startswith('http') else (n.get('src') or '')[:60]} "
                                                          f"on {redact_url(n.get('frame_target_url') or '')}" for n in nodes[:8]))
    hooks = sorted({k for h in ev.get("page_api_hooks", []) for k in h.get("replaced") or []})
    if hooks:
        out.append(f"page API replaced: {hooks}")
    if ev.get("honeypot_exfil_details"):
        out.append(f"honeypot details: {[(d.get('via'), urlparse(d.get('url', '')).netloc, d.get('markers')) for d in ev['honeypot_exfil_details'][:4]]}")


def main():
    out_dir = Path(sys.argv[1])
    ids = sys.argv[2:] or [r["ext_id"] for r in csv.DictReader(open(HERE / "sample.csv", encoding="utf-8"))]
    pkgs = {}
    for d in SAMPLE_DIRS:
        p = (REPO / d).resolve()
        if p.exists():
            for f in p.glob("*.crx"):
                pkgs.setdefault(f.stem, f)
    (out_dir / "ev").mkdir(parents=True, exist_ok=True)
    for i in ids:
        ev = json.loads((TRACES / i / "output" / "events.json").read_text(encoding="utf-8"))
        m = ev.get("manifest") or {}
        out = [f"=== {i}  name={m.get('name')}  v{m.get('version')}  mv{m.get('manifest_version')}",
               f"desc: {short(m.get('description') or '', 200)}",
               f"permissions: {m.get('permissions')}  host_permissions: {m.get('host_permissions')}",
               f"content_scripts: {[(c.get('matches'), c.get('js')) for c in m.get('content_scripts') or []][:4]}",
               f"other manifest keys: {sorted(k for k in m if k not in ('name', 'version', 'description', 'permissions', 'host_permissions', 'content_scripts', 'icons', 'manifest_version', 'default_locale', 'action', 'browser_action'))}"]
        for k in ("chrome_settings_overrides", "chrome_url_overrides", "externally_connectable", "declarative_net_request",
                  "content_security_policy", "background", "web_accessible_resources"):
            if k in m:
                out.append(f"{k}: {short(json.dumps(m[k]), 300)}")
        out.append("--- trace")
        trace(ev, out)
        out.append("--- code")
        if i in pkgs:
            pkg = out_dir / "pkg" / i
            unpack(pkgs[i], pkg)
            grep(pkg, out)
        else:
            out.append("package not found")
        (out_dir / "ev" / f"{i}.txt").write_text("\n".join(out) + "\n", encoding="utf-8")
        print(i, len(out))


if __name__ == "__main__":
    main()
