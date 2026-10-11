"""guard_check.py -- end-to-end check of the v3.1-probe proxy guard and causal tagging on a synthetic extension.

  py eval/v3_1_probe/feasibility/guard_check.py <work dir outside the repo>

Builds a test extension (proxy + offscreen permissions, popup with a "Connect" button), packs it as CRX3, runs it
once through extprobe-sandbox:v3.1-probe (same docker limits as eval/v3_1_probe/run_probe.py, plus
PROBE_SELFTEST_STOP_SW=1: the extension's service worker is stopped at the probe start (ServiceWorker.stopWorker), so the
popup's message restarts it) and checks the trace. The extension:
  service worker  first statement: proxy.settings.set(fixed_servers), then get() and a request whose URL carries
                  the mode get() returned; creates an offscreen document; on a message from the popup:
                  after an await, fetch .../from-msg (linked to the click), and 0.6 s later from a timer, fetch
                  .../sw-spont (not linked); every 0.5 s, after the first message, fetch .../sw-tick
  popup           "Connect": proxy.settings.set(pac_script), runtime.sendMessage, and 3 s later fetch
                  .../popup-late from the popup itself (1 s: the popup is closed when the explorer is done)
  offscreen       tries proxy.settings (offscreen documents only have chrome.runtime: expected absent)
Checks (PASS / FAIL lines): policy in force; effective proxy never other than direct; SW set() recorded at the
first statement in both worker starts (before and after the forced stop) and answered with the faked value; popup set() recorded by the page guard;
causal classes of the requests above.
"""
import io
import json
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]

MANIFEST = {"manifest_version": 3, "name": "Guard check", "version": "1.0",
            "permissions": ["proxy", "offscreen"], "host_permissions": ["<all_urls>"],
            "background": {"service_worker": "sw.js"}, "action": {"default_popup": "popup.html"}}
SW = r"""
chrome.proxy.settings.set({value: {mode: 'fixed_servers', rules: {singleProxy: {host: 'proxy.invalid', port: 3128}}}, scope: 'regular'}, () => {
  chrome.proxy.settings.get({}, (v) => { fetch('https://example.org/get?mode=' + v.value.mode + '&level=' + v.levelOfControl).catch(() => {}); });
});
chrome.offscreen && chrome.offscreen.createDocument({url: 'off.html', reasons: ['DOM_PARSER'], justification: 'test'}).catch(() => {});
let ticking = false;
chrome.runtime.onMessage.addListener(async (msg, sender) => {
  if (msg !== 'go') return;
  await new Promise(r => setTimeout(r, 50));
  await Promise.resolve();
  fetch('https://example.org/from-msg').catch(() => {});
  setTimeout(() => fetch('https://example.org/sw-spont').catch(() => {}), 600);
  if (!ticking) { ticking = true; setInterval(() => fetch('https://example.org/sw-tick').catch(() => {}), 500); }
});
"""
POPUP_HTML = '<!doctype html><html><body><button id="c">Connect</button><script src="popup.js"></script></body></html>'
POPUP_JS = r"""
document.getElementById('c').addEventListener('click', () => {
  chrome.proxy.settings.set({value: {mode: 'pac_script', pacScript: {data: 'function FindProxyForURL(u,h){return "PROXY p.invalid:8080";}'}}, scope: 'regular'});
  chrome.runtime.sendMessage('go');
  setTimeout(() => fetch('https://example.net/popup-late').catch(() => {}), 1000);
});
"""
OFF_HTML = '<!doctype html><html><body><script src="off.js"></script></body></html>'
OFF_JS = "try { chrome.proxy.settings.set({value: {mode: 'direct'}}); } catch (e) {}"


def build(path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in {"manifest.json": json.dumps(MANIFEST), "sw.js": SW, "popup.html": POPUP_HTML,
                           "popup.js": POPUP_JS, "off.html": OFF_HTML, "off.js": OFF_JS}.items():
            z.writestr(name, data)
    path.write_bytes(b"Cr24" + struct.pack("<II", 3, 0) + buf.getvalue())


def main():
    work = Path(sys.argv[1]).resolve()
    work.mkdir(parents=True, exist_ok=True)
    crx = work / "guardcheck.crx"
    build(crx)
    traces = work / "traces"
    run = traces / "guardcheck"
    out = run / "output"
    if not (out / "events.json").exists():
        out.mkdir(parents=True, exist_ok=True)
        (run / "extension.crx").write_bytes(crx.read_bytes())
        host = str(run).replace("\\", "/")
        cmd = ["docker", "run", "--rm", "-e", "PROBE_SELFTEST_STOP_SW=1", "-v", f"{host}:/work",
               "--tmpfs", "/work/output/extension_unpacked:size=1g", "--memory", "3g", "--pids-limit", "512",
               "--cap-drop", "ALL", "--cap-add", "NET_RAW", "--cap-add", "CHOWN", "--cap-add", "SETUID",
               "--cap-add", "SETGID", "--cap-add", "KILL", "--security-opt", "no-new-privileges",
               "extprobe-sandbox:v3.1-probe", "/work/extension.crx", "/work/output", "240"]
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=330)
        (run / "container.log").write_text(p.stdout + p.stderr, encoding="utf-8")
    pre = json.loads((out / "events.json").read_text(encoding="utf-8"))
    post = json.loads((out / "events_probe.json").read_text(encoding="utf-8"))
    g = post.get("proxy_guard") or {}
    mon = g.get("monitor") or {}
    res = []

    def check(name, ok, detail=""):
        res.append(ok)
        print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}")

    check("run complete", (pre.get("run_status") or {}).get("status") == "complete", str(pre.get("run_status")))
    check("policy file in the image", g.get("policy_file") == {"ProxyMode": "direct"}, str(g.get("policy_file")))
    check("policy in force at the run start (real get: direct, not_controllable)", g.get("policy_in_force") is True,
          str((mon.get("marks") or {})))
    check("effective proxy always direct (monitor)", set(mon.get("modes") or {}) == {"direct"} and not g.get("proxy_unwrapped_set"),
          f"snapshots={mon.get('snapshots')} modes={mon.get('modes')} unavailable={mon.get('unavailable')}")
    allapi = (pre.get("api_calls") or []) + (post.get("api_calls_harness_pre") or []) + (post.get("api_calls") or [])
    sw_sets = list({(a.get("ts"), a.get("args")): a for a in allapi
                    if a.get("api") == "proxy.settings.set" and a.get("ctx") == "sw"}.values())   # Runtime.enable replays
    stop_ts = next((x["ts"] for x in (g.get("page_guard") or {}).get("selftest") or [] if x["method"] == "ServiceWorker.stopWorker"), None) or 9e15
    check("SW set() at the first statement recorded and faked, before AND after the forced worker stop",
          any(a["ts"] < stop_ts for a in sw_sets) and any(a["ts"] > stop_ts for a in sw_sets) and all(a.get("faked") for a in sw_sets),
          f"{len(sw_sets)} distinct records, {sum(a['ts'] > stop_ts for a in sw_sets)} after the stop, stop_ts={stop_ts}")
    reqs = (pre.get("network_requests") or []) + (post.get("network_requests") or [])
    gets = [r["url"] for r in reqs if "/get?mode=" in (r.get("url") or "")]
    check("SW get() answered with the faked configuration", bool(gets) and all("mode=fixed_servers" in u and "controlled_by_this_extension" in u for u in gets),
          f"{len(gets)} get requests")
    page_sets = [a for a in g.get("page_calls") or [] if a.get("api") == "proxy.settings.set"]
    check("popup set() recorded by the page guard", any(a.get("ctx", "").endswith("popup.html") and a.get("mode") == "pac_script" for a in page_sets),
          f"{[(a.get('ctx'), a.get('mode')) for a in page_sets]}")
    check("page guard attached to page targets", ((g.get("page_guard") or {}).get("by_type") or {}).get("page", 0) > 0, str(g.get("page_guard")))
    gets_after = [r for r in (post.get("network_requests") or []) if "/get?mode=" in (r.get("url") or "")]
    check("restarted worker: get() answered with the faked configuration too", bool(gets_after) and
          all("mode=fixed_servers" in r["url"] for r in gets_after), f"{len(gets_after)} get requests after the probe start")
    print("--- causal tags (events_probe.json)")
    tags = {}
    for k in ("network_requests", "page_request_initiators"):
        for r in post.get(k) or []:
            u = r.get("url") or ""
            for key in ("from-msg", "sw-spont", "sw-tick", "popup-late"):
                if u.endswith("/" + key):
                    tags.setdefault(key, set()).add((k, r.get("cause_class"), r.get("cause_reason")))
    for key, v in sorted(tags.items()):
        print(f"      {key}: {sorted(v, key=str)}")
    want = {"from-msg": "user_initiated", "sw-spont": "post_probe", "sw-tick": "post_probe", "popup-late": "user_initiated"}
    for key, cls in want.items():
        got = {c for _, c, _ in tags.get(key, set())}
        check(f"cause of .../{key} = {cls}", got == {cls}, str(sorted(got, key=str)))
    print(f"{sum(res)}/{len(res)} checks passed")
    sys.exit(0 if all(res) else 1)


if __name__ == "__main__":
    main()
