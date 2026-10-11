"""v3 CDP sensor: the v2 service-worker sensor (sandbox/sensors/cdp_sw.py) plus

  A1b   loads the extension itself (Extensions.loadUnpacked) once auto-attach is in place, and
        injects the SW API hooks at the worker's first statement (instrumentation breakpoint
        beforeScriptExecution), so start-up calls are not missed (v3_startup.py)
  T1-1  page / iframe targets: Debugger with setSkipAllPauses(true) and async call stacks; each
        http(s) request gets a record in events["page_request_initiators"]
  A2    T1-2: DOM node creation stacks (DOM.setNodeStackTracesEnabled + getNodeStackTraces) for
        every SCRIPT / IFRAME / FORM node, in events["dom_node_initiators"]
  T1-3  the SW hook wraps chrome.tabs.create / tabs.update / windows.create (events["sw_tab_calls"])
  A3    T1-8: response bodies (<= 64 kB + sha256 + content type + length) of requests the extension
        initiated (all SW requests; page requests attributed to the extension)
  T1-6  `ts` (epoch ms) on every record; T1-7 request bodies up to 64 kB
Only used by the v3 profile; the v2 module is unchanged.
"""
import asyncio
import hashlib
import json
import logging
import time
import urllib.request

import websockets

from config import INTERESTING_HEADERS, REMOTE_DEBUG_PORT
from honeypot import find_honeypot_any, record_exfil_encoding
from utils import _host_of
from sensors.cdp_sw import _API_HOOK_JS, _initiator_is_extension
from v3_common import attribute, body_fields, now_ms, response_fields
import v3_startup

logger = logging.getLogger(__name__)

_TAB_HOOK_JS = """
(function(){
  if (self.__v3tabhook) return; self.__v3tabhook = true;
  function L(r){ try{ console.log('__APICALL__'+JSON.stringify(r)); }catch(e){} }
  for (const [ns, fn] of [['tabs','create'],['tabs','update'],['windows','create']]) {
    try { if (self.chrome && chrome[ns] && chrome[ns][fn]) {
      const o = chrome[ns][fn].bind(chrome[ns]);
      chrome[ns][fn] = function(){
        const a = Array.prototype.slice.call(arguments).filter(x => typeof x !== 'function');
        L({api: ns + '.' + fn, ts: Date.now(), args: a});
        return o.apply(this, arguments);
      };
    }} catch(e) {}
  }
})();
"""
_HOOKS = _API_HOOK_JS + "\n" + _TAB_HOOK_JS
NODE_TAGS = ("SCRIPT", "IFRAME", "FORM")
OUTER_HTML_MAX = 4096
NET_BUFFERS = {"maxTotalBufferSize": 100_000_000, "maxResourceBufferSize": 20_000_000}


def _tab_call_url(call):
    for a in call.get("args") or []:
        if isinstance(a, dict) and isinstance(a.get("url"), (str, list)):
            u = a["url"]
            return u if isinstance(u, str) else (u[0] if u else None)
    return None


def _check_honeypot(entry, events, url, body, picked, via):
    surface = url + " " + (body or "") + " " + json.dumps(picked)
    hits, encoding = find_honeypot_any(surface)
    if hits and not entry.get("honeypot_markers"):
        entry["honeypot_markers"] = hits
        entry["honeypot_encoding"] = encoding
        events["honeypot_exfil"] = True
        record_exfil_encoding(events, encoding)
        events["honeypot_exfil_details"].append({
            "url": url, "method": entry.get("method"), "markers": hits, "encoding": encoding,
            "where": "post_data" if (body and find_honeypot_any(body)[0]) else "url_or_header",
            "via": via, "ts": entry.get("ts")})


def _record_sw_request(pr, events):
    rq = pr.get("request", {})
    url = rq.get("url", "")
    body = rq.get("postData")
    entry = {"url": url, "method": rq.get("method"), "resource_type": pr.get("type", "cdp"),
             "origin": "service_worker", "source": "cdp_sw", "host": _host_of(url), "phase": events.get("_current_phase"),
             "ts": round(pr["wallTime"] * 1000, 1) if pr.get("wallTime") else now_ms()}
    if events.get("_t0") is not None:
        entry["t"] = round(time.monotonic() - events["_t0"], 3)
    entry.update(body_fields(body))
    if rq.get("hasPostData") and not body:
        entry["post_data_pending"] = True
    hdrs = rq.get("headers", {}) or {}
    picked = {k: str(v)[:200] for k, v in hdrs.items() if k.lower() in INTERESTING_HEADERS}
    if picked:
        entry["headers_of_interest"] = picked
    _check_honeypot(entry, events, url, body, picked, "cdp_service_worker")
    events["network_requests"].append(entry)
    return entry


def _attr(node, name):
    a = node.get("attributes") or []
    for i in range(0, len(a) - 1, 2):
        if a[i] == name:
            return a[i + 1]
    return None


def _walk_nodes(node):
    yield node
    for c in node.get("children") or []:
        yield from _walk_nodes(c)
    if node.get("contentDocument"):
        yield from _walk_nodes(node["contentDocument"])


async def cdp_sensor_v3(events, stop_evt, port=REMOTE_DEBUG_PORT):
    burl = None
    for _ in range(20):
        try:
            ver = json.loads(urllib.request.urlopen(f"http://localhost:{port}/json/version", timeout=1).read())
            burl = ver["webSocketDebuggerUrl"]
            break
        except Exception:
            await asyncio.sleep(0.3)
    if not burl:
        events["errors"].append("cdp_endpoint_unavailable")
        if v3_startup.LOADED["event"]:
            v3_startup.LOADED["event"].set()
        return
    for k in ("api_calls", "sw_tab_calls", "page_request_initiators", "dom_node_initiators"):
        events.setdefault(k, [])
    try:
        async with websockets.connect(burl, max_size=None) as ws:
            _id = [1000]
            pending = {}                          # id -> (method, ctx)

            async def send(method, params=None, sid=None, ctx=None):
                _id[0] += 1
                m = {"id": _id[0], "method": method, "params": params or {}}
                if sid:
                    m["sessionId"] = sid
                pending[_id[0]] = (method, ctx)
                await ws.send(json.dumps(m))

            sw_sessions, sw_hooked, page_sessions = set(), set(), {}
            req_ctx = {}                          # (sid, requestId) -> record wanting a response body
            node_seen = set()

            async def scan_nodes(s, roots):
                """A2: ask the creation stack of every SCRIPT / IFRAME / FORM node not seen yet, whether
                it arrives as an insertion event or inside a getDocument tree (nodes already present
                when the document was fetched are only in the reply, not in events)."""
                for root in roots:
                    for n in _walk_nodes(root or {}):
                        key = (s, n.get("backendNodeId"))
                        if n.get("nodeName") in NODE_TAGS and key not in node_seen:
                            node_seen.add(key)
                            src = _attr(n, "src") or _attr(n, "action") or "(inline)"
                            await send("DOM.getNodeStackTraces", {"nodeId": n["nodeId"]}, sid=s,
                                       ctx={"kind": "nodestack", "sid": s, "backend_id": n.get("backendNodeId"),
                                            "node": {
                                           "tag": n.get("nodeName"), "src": src[:300], "ts": now_ms(),
                                           "frame_target_url": (page_sessions.get(s) or "")[:200]}})
            await send("Target.setAutoAttach", {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": True},
                       ctx={"kind": "autoattach"})
            while not stop_evt.is_set():
                try:
                    msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=1))
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    if not events.get("_browser_closing"):
                        logger.warning("v3 CDP sensor: websocket read failed, stopping: %s", e)
                    break
                if "id" in msg:                   # ---- command responses
                    meth, ctx = pending.pop(msg["id"], (None, None))
                    kind = (ctx or {}).get("kind") if isinstance(ctx, dict) else None
                    if "error" in msg:
                        if kind == "nodestack" and not ctx.get("retried") and ctx.get("backend_id"):
                            # stale nodeId (the document was fetched again): re-resolve by backend id once
                            await send("DOM.pushNodesByBackendIdsToFrontend", {"backendNodeIds": [ctx["backend_id"]]},
                                       sid=ctx["sid"], ctx=dict(ctx, kind="repush"))
                            continue
                        samples = events.setdefault("v3_cdp_error_samples", {}).setdefault(meth or "?", [])
                        if len(samples) < 3:
                            samples.append(msg["error"].get("message", "")[:120])
                        if meth == "Extensions.loadUnpacked":
                            events["v3_load"]["error"] = msg["error"].get("message", "")[:200]
                            v3_startup.LOADED["event"].set()
                        cnt = events.setdefault("v3_cdp_command_errors", {})
                        cnt[meth] = cnt.get(meth, 0) + 1
                        continue
                    res = msg.get("result", {})
                    if kind == "autoattach" and events.get("v3_load", {}).get("mode") == "cdp" and events.get("_ext_dir"):
                        await send("Extensions.loadUnpacked", {"path": events["_ext_dir"]}, ctx={"kind": "load"})
                    elif kind == "load":
                        events["v3_load"].update(id=res.get("id"), ts=now_ms())
                        events["install_ts"] = events["v3_load"]["ts"]
                        v3_startup.LOADED["event"].set()
                    elif meth == "Network.getRequestPostData" and kind == "postdata":
                        entry = ctx["entry"]
                        body = res.get("postData")
                        entry.pop("post_data_pending", None)
                        entry.update(body_fields(body))
                        _check_honeypot(entry, events, entry.get("url", ""), body, entry.get("headers_of_interest", {}),
                                        "cdp_service_worker_postdata")
                    elif kind == "respbody":
                        ctx["rec"].update(response_fields(res.get("body", ""), res.get("base64Encoded", False),
                                                          ctx["rec"].get("response_content_type")))
                    elif kind == "document":
                        await scan_nodes(ctx["sid"], [res.get("root") or {}])
                    elif kind == "repush":
                        ids = res.get("nodeIds") or []
                        if ids and ids[0]:
                            await send("DOM.getNodeStackTraces", {"nodeId": ids[0]}, sid=ctx["sid"],
                                       ctx=dict(ctx, kind="nodestack", retried=True))
                    elif kind == "nodestack":
                        creation = res.get("creation") or {}
                        who, frames = attribute({"stack": creation} if creation else {})
                        nrec = dict(ctx["node"], attributed=who if creation else "no_stack", ext_frames=frames)
                        events["dom_node_initiators"].append(nrec)
                        if who == "extension" and creation and ctx.get("backend_id"):
                            # content of what the extension inserted (inline code, iframe / form markup)
                            await send("DOM.getOuterHTML", {"backendNodeId": ctx["backend_id"]}, sid=ctx["sid"],
                                       ctx={"kind": "outer", "rec": nrec})
                    elif kind == "outer":
                        h = res.get("outerHTML") or ""
                        ctx["rec"].update({"outer_html": h[:OUTER_HTML_MAX], "outer_html_len": len(h),
                                           "outer_html_sha256": hashlib.sha256(h.encode("utf-8", "replace")).hexdigest()})
                    continue
                method = msg.get("method")
                pr = msg.get("params", {})
                sid = msg.get("sessionId")
                if method == "Target.attachedToTarget":
                    info = pr.get("targetInfo", {})
                    s = pr.get("sessionId")
                    ttype, url = info.get("type"), info.get("url", "")
                    is_ext_sw = ttype == "service_worker" and url.startswith("chrome-extension://")
                    if ttype in ("service_worker", "worker", "page", "iframe"):
                        await send("Network.enable", NET_BUFFERS if ttype in ("service_worker", "page", "iframe") else {}, sid=s)
                    if is_ext_sw:
                        sw_sessions.add(s)
                        events.setdefault("v3_sw_attach", []).append(
                            {"url": url[:200], "ts": now_ms(), "waiting": pr.get("waitingForDebugger")})
                        await send("Runtime.enable", {}, sid=s)
                        if pr.get("waitingForDebugger"):
                            # A1b: pause before the first statement, inject the hooks there
                            await send("Debugger.enable", {}, sid=s)
                            await send("Debugger.setInstrumentationBreakpoint",
                                       {"instrumentation": "beforeScriptExecution"}, sid=s)
                        else:
                            await send("Runtime.evaluate", {"expression": _HOOKS}, sid=s)
                            sw_hooked.add(s)
                    if ttype == "page":
                        events.setdefault("cdp_page_targets", []).append(
                            {"target_id": info.get("targetId"), "url": url[:2000], "ts": now_ms(),
                             "opener_id": info.get("openerId"), "parent_session": bool(sid)})
                    if ttype in ("page", "iframe"):
                        page_sessions[s] = url
                        await send("Debugger.enable", {"maxScriptsCacheSize": 0}, sid=s)
                        await send("Debugger.setSkipAllPauses", {"skip": True}, sid=s)
                        await send("Debugger.setAsyncCallStackDepth", {"maxDepth": 32}, sid=s)
                        await send("DOM.enable", {}, sid=s)
                        await send("DOM.setNodeStackTracesEnabled", {"enable": True}, sid=s)
                        await send("DOM.getDocument", {"depth": -1}, sid=s, ctx={"kind": "document", "sid": s})
                        await send("Target.setAutoAttach",
                                   {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": True}, sid=s)
                    await send("Runtime.runIfWaitingForDebugger", {}, sid=s)
                elif method == "Debugger.paused" and sid in sw_sessions:
                    if pr.get("reason") == "instrumentation" and sid not in sw_hooked:
                        sw_hooked.add(sid)
                        cf = (pr.get("callFrames") or [{}])[0].get("callFrameId")
                        if cf:
                            await send("Debugger.evaluateOnCallFrame", {"callFrameId": cf, "expression": _HOOKS}, sid=sid)
                        else:
                            await send("Runtime.evaluate", {"expression": _HOOKS}, sid=sid)
                        events.setdefault("v3_sw_hooked", []).append({"ts": now_ms(), "how": "first_statement"})
                    await send("Debugger.resume", {}, sid=sid)
                elif method == "Runtime.consoleAPICalled" and sid in sw_sessions:
                    try:
                        args = pr.get("args", [])
                        v = args[0].get("value") if args else None
                        if isinstance(v, str) and v.startswith("__APICALL__"):
                            call = json.loads(v[len("__APICALL__"):])
                            call.setdefault("ts", round(pr.get("timestamp", time.time() * 1000), 1))
                            events["api_calls"].append(call)
                            if call.get("api") in ("tabs.create", "tabs.update", "windows.create"):
                                events["sw_tab_calls"].append({"api": call["api"], "url": _tab_call_url(call),
                                                               "ts": call.get("ts")})
                    except Exception as e:
                        logger.warning("v3 API-call sensor: record dropped: %s", e)
                elif method == "DOM.documentUpdated" and sid in page_sessions:
                    await send("DOM.getDocument", {"depth": -1}, sid=sid, ctx={"kind": "document", "sid": sid})
                elif method in ("DOM.childNodeInserted", "DOM.setChildNodes") and sid in page_sessions:
                    roots = [pr.get("node")] if method == "DOM.childNodeInserted" else (pr.get("nodes") or [])
                    await scan_nodes(sid, roots)
                elif method == "Network.requestWillBeSent":
                    if sid in sw_sessions:
                        entry = _record_sw_request(pr, events)
                        req_ctx[(sid, pr.get("requestId"))] = entry
                        if entry.get("post_data_pending"):
                            await send("Network.getRequestPostData", {"requestId": pr.get("requestId")},
                                       sid=sid, ctx={"kind": "postdata", "entry": entry})
                    else:
                        req = pr.get("request", {})
                        url = req.get("url", "")
                        if url.startswith("http"):
                            ini = pr.get("initiator", {}) or {}
                            host = _host_of(url)
                            if host and "." in host:      # v2 per-host provenance, unchanged meaning
                                prov = events.setdefault("request_provenance", {})
                                prov[host] = bool(prov.get(host, False) or _initiator_is_extension(ini))
                            who, frames = attribute(ini)
                            redir = pr.get("redirectResponse") or {}
                            rec = {
                                "url": url, "method": req.get("method"), "resource_type": pr.get("type"),
                                "ts": round(pr["wallTime"] * 1000, 1) if pr.get("wallTime") else now_ms(),
                                "request_id": pr.get("requestId"), "frame_id": pr.get("frameId"),
                                "loader_id": pr.get("loaderId"),
                                "redirect_from": (redir.get("url") or "")[:2000] or None,
                                "redirect_status": redir.get("status"),
                                "initiator_type": ini.get("type"), "attributed": who, "ext_frames": frames,
                                "ext_ids": sorted({f.split("/")[2] for f in frames}),
                                "frame_target_url": (page_sessions.get(sid) or "")[:200],
                            }
                            if who == "extension":
                                rec.update({k: v for k, v in body_fields(req.get("postData")).items()})
                                req_ctx[(sid, pr.get("requestId"))] = rec
                            events["page_request_initiators"].append(rec)
                elif method == "Network.responseReceived" and (sid, pr.get("requestId")) in req_ctx:
                    resp = pr.get("response", {})
                    rec = req_ctx[(sid, pr.get("requestId"))]
                    rec["response_status"] = resp.get("status")
                    rec["response_content_type"] = resp.get("mimeType")
                elif method == "Network.loadingFinished" and (sid, pr.get("requestId")) in req_ctx:
                    rec = req_ctx.pop((sid, pr.get("requestId")))
                    await send("Network.getResponseBody", {"requestId": pr.get("requestId")}, sid=sid,
                               ctx={"kind": "respbody", "rec": rec})
                elif method == "Network.loadingFailed" and (sid, pr.get("requestId")) in req_ctx:
                    rec = req_ctx.pop((sid, pr.get("requestId")))
                    rec["response_error"] = (pr.get("errorText") or "")[:120]
    except Exception as e:
        events["errors"].append(f"cdp_v3_sensor_error: {str(e)[:120]}")
    finally:
        if v3_startup.LOADED["event"] and not v3_startup.LOADED["event"].is_set():
            v3_startup.LOADED["event"].set()
