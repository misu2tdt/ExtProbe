"""v3.1-probe proxy guard (eval/v3_1_probe/DESIGN.md §5): an extension's proxy configuration never takes effect.

Three layers, all active from the load phase to the end of the run:
  1. Managed Chrome policy ProxyMode=direct, baked into the image at the path Chrome for Testing 153 reads
     (/etc/opt/chrome_for_testing/policies/managed/, root-owned; evidence in DESIGN.md §5). With it,
     chrome.proxy.settings.get reports levelOfControl=not_controllable and set() has no effect.
  2. chrome.proxy.settings.set / clear / get are replaced by a recorder (GUARD_JS) in every extension context:
       service worker  appended to the v3 SW hook string (v3_cdp._HOOKS, read at run time: first start), and
                       PageGuard's own SW session keeps an instrumentation breakpoint (beforeScriptExecution) and
                       injects GUARD_JS at every pause before a script runs: on a restart the DevTools session
                       survives and its breakpoints are restored, but v3 hooks a session only once. v3 resumes
                       those pauses itself, so its Debugger.resume is held (ResumeGate, at most 0.3 s, through a
                       wrapper of v3_cdp's websocket module set at run time) until the guard is in. The pauses are per
                       session (Chrome 153): PageGuard resumes its own pause 50 ms after the injection if nobody
                       else did, and any pause still open after 1.5 s (v3_cdp's file is not modified);
       pages           PageGuard, a separate CDP client with auto-attach (waitForDebuggerOnStart), adds GUARD_JS
                       with Page.addScriptToEvaluateOnNewDocument to every page / iframe / other target before it
                       runs (popup, options, pages they open, offscreen documents, extension iframes in web pages);
                       the script does nothing outside chrome-extension:// documents that have chrome.proxy.
     set() records the configuration and reports success without calling Chrome; get() returns the configuration
     the extension "set" (else the default of an unmanaged browser: system, controllable_by_this_extension);
     clear() resets it. The real get / clear stay reachable for the harness only (non-enumerable __xpRealProxy).
  3. ProxyMonitor reads the EFFECTIVE configuration with the real get (harness side, through the extension's
     service worker or one of its pages) at the run start, at the probe start and every 2 s; anything other than
     mode=direct is cleared at once and recorded as proxy_unwrapped_set=true.
The service worker part also links SW activity to the extension's own pages: a fetch / XHR / WebSocket /
tabs.create / tabs.update / windows.create call whose JS stack (async frames included) goes through a
runtime.onMessage listener invoked for a message from an extension page is recorded as caused_by_ui
(used by v31_split; no other SW request is treated as caused by a click).
Records go to the SW console as __APICALL__ (v3 sensor -> events["api_calls"]) and, for pages, to the CDP
binding __xpReport (PageGuard -> events["_guard_pages"]).
"""
import asyncio
import json
import logging
import time
import urllib.request

import websockets

from config import REMOTE_DEBUG_PORT
from v3_common import now_ms
from v31_split import HARNESS_EVAL_PREFIXES

logger = logging.getLogger(__name__)
POLICY_PATH = "/etc/opt/chrome_for_testing/policies/managed/extprobe_proxy.json"
MONITOR_EVERY_S = 2.0

GUARD_JS = r"""
(function () {
  try {
    if (self.__xpGuard) return;
    const isSW = typeof ServiceWorkerGlobalScope !== 'undefined' && self instanceof ServiceWorkerGlobalScope;
    if (!isSW && !(self.location && self.location.protocol === 'chrome-extension:')) return;
    const C = self.chrome;
    const ps = C && C.proxy && C.proxy.settings;
    Object.defineProperty(self, '__xpGuard', {value: true, enumerable: false});
    const sink = function (r) {
      r.ts = Date.now(); r.ctx = isSW ? 'sw' : String(self.location.pathname).slice(0, 80);
      try { const s = JSON.stringify(r);
            if (!isSW && typeof self.__xpReport === 'function') self.__xpReport(s); else console.log('__APICALL__' + s); }
      catch (e) {}
    };
    const put = function (obj, name, fn) {
      try { obj[name] = fn; } catch (e) {}
      if (obj[name] !== fn) { try { Object.defineProperty(obj, name, {value: fn, configurable: true, writable: true}); } catch (e) {} }
    };
    if (ps) {
      const realGet = ps.get.bind(ps), realClear = ps.clear.bind(ps);
      let fake = null;
      Object.defineProperty(self, '__xpRealProxy', {enumerable: false, value: {
        get: () => new Promise(r => realGet({incognito: false}, r)),
        clear: () => new Promise(r => realClear({scope: 'regular'}, r))}});
      const answer = function (cb, value) {
        if (typeof cb === 'function') { setTimeout(() => cb(value), 0); return undefined; }
        return Promise.resolve(value);
      };
      put(ps, 'set', function (details, cb) {
        let a = ''; try { a = JSON.stringify(details).slice(0, 4000); } catch (e) {}
        fake = details && details.value ? JSON.parse(JSON.stringify(details.value)) : null;
        sink({api: 'proxy.settings.set', faked: true, mode: fake && fake.mode, args: a});
        return answer(cb, undefined);
      });
      put(ps, 'clear', function (details, cb) {
        fake = null; sink({api: 'proxy.settings.clear', faked: true});
        return answer(cb, undefined);
      });
      put(ps, 'get', function (details, cb) {
        if (typeof details === 'function') { cb = details; }
        const v = fake ? {value: JSON.parse(JSON.stringify(fake)), levelOfControl: 'controlled_by_this_extension'}
                       : {value: {mode: 'system'}, levelOfControl: 'controllable_by_this_extension'};
        return answer(cb, v);
      });
    }
    try {
      const dnr = C && C.declarativeNetRequest;
      if (dnr) for (const f of ['updateDynamicRules', 'updateSessionRules', 'updateEnabledRulesets']) {
        if (!dnr[f]) continue; const o = dnr[f].bind(dnr);
        put(dnr, f, function (opts, cb) {
          let a = ''; try { a = JSON.stringify(opts).slice(0, 2000); } catch (e) {}
          sink({api: 'declarativeNetRequest.' + f, args: a}); return o(opts, cb); });
      }
    } catch (e) {}
    if (!isSW) return;
    // ---- service worker: which calls come from a message sent by one of the extension's own pages
    const own = self.location.origin + '/';
    const fromUI = function () {
      const L = Error.stackTraceLimit; Error.stackTraceLimit = 80;
      const s = String(new Error().stack || ''); Error.stackTraceLimit = L;
      return s.indexOf('__xpFromExtPage') >= 0;
    };
    const mark = function (kind, url) { if (fromUI()) sink({api: 'xp.caused_by_ui', kind: kind, url: String(url || '').slice(0, 2000)}); };
    const absolute = function (u) { try { return new URL(String(u), self.location.href).href; } catch (e) { return String(u); } };
    try {
      const om = C.runtime && C.runtime.onMessage;
      if (om) {
        const add = om.addListener.bind(om), rem = om.removeListener.bind(om), has = om.hasListener.bind(om);
        const wrapped = new WeakMap();
        put(om, 'addListener', function (fn) {
          if (typeof fn !== 'function') return add(fn);
          let w = wrapped.get(fn);
          if (!w) {
            // sync frames: the listener runs inside __xpFromExtPage; async frames: when the listener returns a
            // promise, __xpFromExtPageAwait is its ONLY consumer (V8 follows an async stack only through a promise
            // with a single reaction) and Chrome gets __xpFromExtPageAwait's promise instead (same value or
            // rejection), so every continuation inside the listener (and in async functions it awaits) has
            // "at async __xpFromExtPageAwait" in its stack. Non-promise return values are unchanged.
            const __xpFromExtPage = function () { return fn.apply(this, arguments); };
            w = function (msg, sender) {
              const ui = sender && sender.id === C.runtime.id && typeof sender.url === 'string' && sender.url.indexOf(own) === 0;
              if (!ui) return fn.apply(this, arguments);
              const r = __xpFromExtPage.apply(this, arguments);
              if (r instanceof Promise) return (async function __xpFromExtPageAwait() { return await r; })();
              return r;
            };
            wrapped.set(fn, w);
          }
          return add(w);
        });
        put(om, 'removeListener', function (fn) { return rem(wrapped.get(fn) || fn); });
        put(om, 'hasListener', function (fn) { return has(wrapped.get(fn) || fn); });
      }
    } catch (e) {}
    try {
      const of = self.fetch;
      if (of) self.fetch = function (input) {
        try { mark('fetch', absolute(input && input.url ? input.url : input)); } catch (e) {}
        return of.apply(this, arguments);
      };
      const xo = XMLHttpRequest.prototype.open, xs = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.open = function (m, u) { this.__xpU = absolute(u); return xo.apply(this, arguments); };
      XMLHttpRequest.prototype.send = function () { try { mark('xhr', this.__xpU); } catch (e) {} return xs.apply(this, arguments); };
    } catch (e) {}
    try {
      const WS = self.WebSocket;
      if (WS) { self.WebSocket = function (u, p) { try { mark('websocket', u); } catch (e) {}
                                                   return p === undefined ? new WS(u) : new WS(u, p); };
                self.WebSocket.prototype = WS.prototype; }
    } catch (e) {}
    for (const [ns, fn] of [['tabs', 'create'], ['tabs', 'update'], ['windows', 'create']]) {
      try { if (C[ns] && C[ns][fn]) { const o = C[ns][fn].bind(C[ns]);
        put(C[ns], fn, function () {
          try { const a = Array.prototype.slice.call(arguments).find(x => x && typeof x === 'object' && x.url);
                mark(ns + '.' + fn, a ? (Array.isArray(a.url) ? a.url[0] : a.url) : ''); } catch (e) {}
          return o.apply(this, arguments); }); } } catch (e) {}
    }
  } catch (e) {}
})();
"""


class ResumeGate:
    """Holds v3's Debugger.resume until PageGuard has handled every SW pause it saw (at most HOLD_S)."""
    HOLD_S = 0.3

    def __init__(self):
        self.seen = self.handled = self.consumed = 0
        self.held = self.timeouts = 0

    async def before_resume(self):
        loop = asyncio.get_event_loop()
        end = loop.time() + self.HOLD_S
        self.held += 1
        while not (self.seen > self.consumed and self.handled >= self.seen):
            if loop.time() > end:
                self.timeouts += 1
                break
            await asyncio.sleep(0.003)
        self.consumed = self.seen


GATE = ResumeGate()


class _WS:
    def __init__(self, ws):
        self._ws = ws

    async def send(self, data):
        if isinstance(data, str) and '"Debugger.resume"' in data:
            try:
                await GATE.before_resume()
            except Exception:
                pass
        return await self._ws.send(data)

    def __getattr__(self, k):
        return getattr(self._ws, k)


class _Connect:
    def __init__(self, cm):
        self._cm = cm

    async def __aenter__(self):
        return _WS(await self._cm.__aenter__())

    async def __aexit__(self, *exc):
        return await self._cm.__aexit__(*exc)


class _WebsocketsShim:
    def __init__(self, real):
        self._real = real

    def connect(self, *a, **kw):
        return _Connect(self._real.connect(*a, **kw))

    def __getattr__(self, k):
        return getattr(self._real, k)


def install_sw_hook():
    """Append GUARD_JS to the v3 SW hook string (read by cdp_sensor_v3 at every SW attach) and route v3's
    websocket through the ResumeGate. Call before the sensor starts. The v3 module file is not modified; only
    this process's module attributes."""
    import v3_cdp
    if GUARD_JS not in v3_cdp._HOOKS:
        v3_cdp._HOOKS = v3_cdp._HOOKS + "\n" + GUARD_JS
    if not isinstance(v3_cdp.websockets, _WebsocketsShim):
        v3_cdp.websockets = _WebsocketsShim(v3_cdp.websockets)


def policy_file():
    """The managed policy as installed in the image (None when absent)."""
    try:
        with open(POLICY_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


class PageGuard:
    """Separate CDP client: every page / iframe / other target gets GUARD_JS before its first script."""
    TYPES = ("page", "iframe", "other", "background_page", "webview")

    def __init__(self, events, port=REMOTE_DEBUG_PORT):
        self.events, self.port = events, port
        self.log = events.setdefault("_guard_pages", [])
        self.stats = events.setdefault("_guard_stats", {"attached": 0, "by_type": {}, "errors": 0})
        self.ready = asyncio.Event()
        self.stop_evt = asyncio.Event()
        self.task = None
        self.page_sids = []
        self.outbox = []                                  # (method, params) to send on a page session
        self.stop_pending = False
        self.sw_sids = set()
        self.sw_targets = set()
        self.open_pause = {}                              # SW session -> time after which an open pause is resumed here
        self.inject = {}                                  # command id -> SW session (guard injections)

    def stop_all_workers(self):
        """Self-test only (PROBE_SELFTEST_STOP_SW=1): stop the extension's running service worker
        (ServiceWorker.stopWorker, same DevTools target, as an idle stop), so that the next event restarts it
        and the first-statement hook has to apply again."""
        self.stop_pending = True
        self.outbox.append(("ServiceWorker.enable", {}))

    async def _main(self):
        burl = None
        for _ in range(40):
            try:
                burl = json.loads(urllib.request.urlopen(f"http://localhost:{self.port}/json/version", timeout=1).read())["webSocketDebuggerUrl"]
                break
            except Exception:
                await asyncio.sleep(0.25)
        if not burl:
            self.stats["error"] = "cdp_endpoint_unavailable"
            self.ready.set()
            return
        async with websockets.connect(burl, max_size=None) as ws:
            n = [5000000]

            async def send(method, params=None, sid=None):
                n[0] += 1
                m = {"id": n[0], "method": method, "params": params or {}}
                if sid:
                    m["sessionId"] = sid
                await ws.send(json.dumps(m))
                return n[0]

            auto = {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": True}
            ack = await send("Target.setAutoAttach", auto)
            while not self.stop_evt.is_set():
                while self.outbox and self.page_sids:
                    method, params = self.outbox.pop(0)
                    self.stats.setdefault("selftest", []).append({"method": method, "ts": now_ms()})
                    await send(method, params, sid=self.page_sids[-1])
                for psid, since in list(self.open_pause.items()):
                    if time.monotonic() > since:                # nobody resumed: do not leave the worker paused
                        self.open_pause.pop(psid, None)
                        self.stats["self_resumed"] = self.stats.get("self_resumed", 0) + 1
                        await send("Debugger.resume", {}, sid=psid)
                try:
                    msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=0.2))
                except asyncio.TimeoutError:
                    continue
                if msg.get("id") == ack:
                    self.ready.set()
                if "id" in msg:
                    if msg["id"] in self.inject:
                        psid = self.inject.pop(msg["id"])
                        GATE.handled += 1
                        if psid in self.open_pause:             # a pause of this session only: resume it soon
                            self.open_pause[psid] = time.monotonic() + 0.05
                        ok = "error" not in msg and "exceptionDetails" not in (msg.get("result") or {})
                        self.stats["sw_injections" if ok else "sw_injection_errors"] = \
                            self.stats.get("sw_injections" if ok else "sw_injection_errors", 0) + 1
                    elif "error" in msg:
                        self.stats["errors"] += 1
                    continue
                method, pr, sid = msg.get("method"), msg.get("params", {}), msg.get("sessionId")
                if method == "Target.attachedToTarget":
                    s = pr.get("sessionId")
                    t = (pr.get("targetInfo") or {}).get("type")
                    turl = (pr.get("targetInfo") or {}).get("url") or ""
                    tid = (pr.get("targetInfo") or {}).get("targetId")
                    if t == "service_worker" and turl.startswith("chrome-extension://") and tid not in self.sw_targets:
                        self.sw_targets.add(tid)                  # one instrumentation session per worker target
                        self.sw_sids.add(s)
                        self.stats["sw_sessions"] = self.stats.get("sw_sessions", 0) + 1
                        await send("Debugger.enable", {}, sid=s)
                        await send("Debugger.setInstrumentationBreakpoint", {"instrumentation": "beforeScriptExecution"}, sid=s)
                    if t in self.TYPES:
                        self.stats["attached"] += 1
                        self.stats["by_type"][t] = self.stats["by_type"].get(t, 0) + 1
                        await send("Runtime.addBinding", {"name": "__xpReport"}, sid=s)
                        await send("Runtime.enable", {}, sid=s)
                        await send("Page.enable", {}, sid=s)
                        await send("Page.addScriptToEvaluateOnNewDocument", {"source": GUARD_JS, "runImmediately": True}, sid=s)
                        if t in ("page", "iframe", "webview"):
                            await send("Target.setAutoAttach", auto, sid=s)
                        if t == "page":
                            self.page_sids.append(s)
                    await send("Runtime.runIfWaitingForDebugger", {}, sid=s)
                elif method == "Debugger.paused" and sid in self.sw_sids:
                    GATE.seen += 1
                    self.open_pause[sid] = time.monotonic() + 1.5
                    cf = (pr.get("callFrames") or [{}])[0].get("callFrameId")
                    if pr.get("reason") == "instrumentation" and cf:
                        self.inject[await send("Debugger.evaluateOnCallFrame", {"callFrameId": cf, "expression": GUARD_JS}, sid=sid)] = sid
                    else:
                        GATE.handled += 1
                elif method == "Debugger.resumed" and sid in self.sw_sids:
                    self.open_pause.pop(sid, None)
                elif method == "ServiceWorker.workerVersionUpdated" and self.stop_pending:
                    for v in pr.get("versions") or []:
                        if (v.get("scriptURL") or "").startswith("chrome-extension://") and v.get("runningStatus") == "running":
                            self.stop_pending = False
                            self.stats.setdefault("selftest", []).append({"method": "ServiceWorker.stopWorker", "ts": now_ms()})
                            await send("ServiceWorker.stopWorker", {"versionId": v["versionId"]}, sid=sid)
                elif method == "Target.detachedFromTarget" and pr.get("sessionId") in self.page_sids:
                    self.page_sids.remove(pr.get("sessionId"))
                elif method == "Runtime.bindingCalled" and pr.get("name") == "__xpReport":
                    try:
                        rec = json.loads(pr.get("payload") or "{}")
                        self.log.append(rec)
                    except Exception:
                        pass

    async def start(self):
        async def run():
            try:
                await self._main()
            except Exception as e:
                self.stats["error"] = str(e)[:120]
            finally:
                self.ready.set()
        self.task = asyncio.create_task(run())
        try:
            await asyncio.wait_for(self.ready.wait(), timeout=12)
        except asyncio.TimeoutError:
            self.stats["error"] = "auto_attach_not_acknowledged"

    async def stop(self):
        self.stop_evt.set()
        self.stats["resume_gate"] = {"held": GATE.held, "timeouts": GATE.timeouts, "pauses": GATE.seen}
        if self.task:
            try:
                await asyncio.wait_for(self.task, timeout=3)
            except Exception:
                self.task.cancel()


REAL_GET_JS = ("async () => { if (!(self.chrome && chrome.proxy)) return {no_api: true};"
               " if (!self.__xpRealProxy) return {missing: true}; return await self.__xpRealProxy.get(); }")
POLICY_TEXT_JS = """() => { const walk = n => { let s = ''; for (const c of n.childNodes) { if (c.nodeType === 3) s += c.textContent + ' ';
  else if (c.nodeType === 1) { s += walk(c); if (c.shadowRoot) s += walk(c.shadowRoot); } } return s; }; return walk(document.body); }"""


async def policy_page(context):
    """Harness-side check, independent of the extension: the ProxyMode row of chrome://policy (e.g.
    'ProxyMode direct Platform Machine Mandatory ...'), or None."""
    tab = None
    try:
        tab = await context.new_page()
        await tab.goto("chrome://policy/", timeout=5000)
        for _ in range(10):
            await tab.wait_for_timeout(300)
            txt = await tab.evaluate(POLICY_TEXT_JS)
            i = txt.find("ProxyMode")
            if i >= 0 and ("direct" in txt[i:i + 60] or "Not set" in txt[i:i + 60]):
                return " ".join(txt[i:i + 120].split())[:120]
        return None
    except Exception as e:
        return f"error: {str(e)[:80]}"
    finally:
        if tab:
            try:
                await tab.close()
            except Exception:
                pass
REAL_CLEAR_JS = "async () => { if (!self.__xpRealProxy) return false; await self.__xpRealProxy.clear(); return true; }"
assert REAL_GET_JS.startswith(HARNESS_EVAL_PREFIXES) and REAL_CLEAR_JS.startswith(HARNESS_EVAL_PREFIXES)   # split filters them


class ProxyMonitor:
    """Effective proxy configuration, harness side (real get through the extension's own contexts)."""

    def __init__(self, context, events):
        self.context, self.events = context, events
        self.rec = events.setdefault("_proxy_monitor", {"snapshots": 0, "unavailable": 0, "modes": {}, "levels": {},
                                                        "non_direct": [], "proxy_unwrapped_set": False,
                                                        "marks": {}})
        self.stop_evt = asyncio.Event()
        self.task = None

    def _targets(self):
        ext = (self.events.get("v3_load") or {}).get("id")
        out = list(self.context.service_workers)
        if ext:
            out = [w for w in out if w.url.startswith(f"chrome-extension://{ext}/")]
            out += [p for p in self.context.pages if p.url.startswith(f"chrome-extension://{ext}/") and not p.is_closed()]
        return out

    async def snapshot(self, mark=None):
        for t in self._targets():
            try:
                v = await asyncio.wait_for(t.evaluate(REAL_GET_JS), timeout=2)
            except Exception:
                continue
            if isinstance(v, dict) and v.get("no_api"):       # no `proxy` permission: cannot set a proxy at all
                self.rec["no_proxy_api"] = self.rec.get("no_proxy_api", 0) + 1
                if mark:
                    self.rec["marks"][mark] = {"ts": now_ms(), "mode": None, "level": "no_proxy_api"}
                return
            if not isinstance(v, dict) or v.get("missing"):
                continue
            mode = (v.get("value") or {}).get("mode")
            level = v.get("levelOfControl")
            self.rec["snapshots"] += 1
            self.rec["modes"][str(mode)] = self.rec["modes"].get(str(mode), 0) + 1
            self.rec["levels"][str(level)] = self.rec["levels"].get(str(level), 0) + 1
            if mark:
                self.rec["marks"][mark] = {"ts": now_ms(), "mode": mode, "level": level}
            if mode != "direct":
                cleared = False
                try:
                    cleared = await asyncio.wait_for(t.evaluate(REAL_CLEAR_JS), timeout=2)
                except Exception:
                    pass
                self.rec["proxy_unwrapped_set"] = True
                if len(self.rec["non_direct"]) < 20:
                    self.rec["non_direct"].append({"ts": now_ms(), "mode": mode, "level": level, "cleared": bool(cleared),
                                                   "phase": self.events.get("_current_phase")})
            return
        self.rec["unavailable"] += 1
        if mark:
            self.rec["marks"][mark] = {"ts": now_ms(), "mode": None, "level": None}

    async def _loop(self):
        while not self.stop_evt.is_set():
            t = time.monotonic()
            try:
                await self.snapshot()
            except Exception as e:
                self.rec["error"] = str(e)[:120]
            try:
                await asyncio.wait_for(self.stop_evt.wait(), timeout=max(0.1, MONITOR_EVERY_S - (time.monotonic() - t)))
            except asyncio.TimeoutError:
                pass

    def start(self):
        self.task = asyncio.create_task(self._loop())

    async def stop(self):
        self.stop_evt.set()
        if self.task:
            try:
                await asyncio.wait_for(self.task, timeout=5)
            except Exception:
                self.task.cancel()
