import asyncio
import json
import logging
import time
import urllib.request
import websockets

from config import MAX_BODY_LEN, INTERESTING_HEADERS, REMOTE_DEBUG_PORT
from honeypot import find_honeypot_any, record_exfil_encoding
from utils import _host_of

logger = logging.getLogger(__name__)


# ============ CAM BIEN 7 (GD1): API-CALL CAPTURE TRONG SERVICE WORKER ============
# Wrap mot tap Chrome API nguy hiem TRUOC khi SW chay (luc con waitForDebuggerOnStart),
# moi lan goi phat console.log('__APICALL__'+json) - dung console vi SW MV3 co the bi
# terminate/restart giua chung, console duoc CDP bat "live" nen khong mat du lieu (khac
# global array se mat khi SW restart). CHI capture, KHONG cham diem (worker/risk.py
# khong doc field nay o GD1).
# Gioi han da biet: self.eval chi bat duoc INDIRECT eval (eval dung nhu 1 gia tri, vd
# `const e = self.eval; e(...)`), KHONG bat direct eval (`eval(...)` trong scope rieng
# cua extension co the dung eval goc do V8 optimize truoc khi wrapper kip gan) - chap
# nhan o GD1, se can CDP Debugger.setInstrumentationBreakpoint hoac tuong tu neu can bat.
#
# Gioi han da biet #2 (kiem chung bang malware that, khong phai ly thuyet): cac API goi
# NGAY O TOP-LEVEL cua service worker (vd `chrome.runtime.setUninstallURL(...)` viet
# thang dau file, khong nam trong onMessage/onInstalled/alarm) co the chay xong TRUOC
# khi inject nay kip patch - vi phien CDP rieng cua cdp_sw.py phai tu ket noi
# (urllib polling /json/version) trong khi Playwright co the da attach/tha SW rieng
# cho muc dich theo doi cua no truoc. Da xac nhan qua canary (marker debug rieng) va
# qua 1 mau malware that (adjiljljjoeielcjmafljkicjncjpbha, goi setUninstallURL o dong
# dau background.js) => sensor nay bat CHAC CHAN cac API goi tu event handler (message/
# alarm/webRequest callback...), KHONG dam bao bat cac API goi dong bo o top-level luc
# SW vua khoi dong. Vi vay canary_apihook.js trigger qua onMessage (giong content.js
# cua canary cu), khong goi truc tiep o top-level.
#
# Da thu "Loi 2" (buoc SW restart de no chay lai top-level sau khi hook da gan):
#   - ServiceWorker.enable/stopAllWorkers cap browser-root: loi -32601 (sai scope,
#     domain nay chi kha dung tren session page, khong phai browser-root).
#   - Runtime.evaluate goi self.registration.update()/unregister() TREN CHINH session
#     SW da attach: XAC NHAN SW co chay lai top-level that (dem duoc 2 lan khoi dong
#     thay vi 1), nhung (a) van khong bat duoc API goi o lan chay lai (nghi do do tre
#     asyncio.sleep tu them vao lai tao ra dung race muon giai), va (b) unregister()
#     lam mat trang thai JS giua chung, GAY REGRESSION cho cac phep do hanh vi khac
#     (beaconing qua nhieu lan goi lien tiep bi mat, smoke_test tut tu 13/13 xuong
#     11/13). => BO huong nay, khong dua vao production.
#   Huong giai dung (Future Work, CHUA LAM): nap extension SAU khi da thiet lap CDP
#   hook (Target.setAutoAttach + waitForDebuggerOnStart), thay vi qua --load-extension
#   luc launch browser (hien --load-extension chay SW ngay khi Chromium khoi dong,
#   truoc ca khi Python kip mo websocket CDP rieng cua cdp_sw.py - xem phases/actions.py
#   va analyze.py, thu tu: launch_persistent_context -> tao cdp_task -> _phase_load).
#   Doi hoi sua thu tu launch trong analyze.py, ngoai pham vi file nay.
_API_HOOK_JS = """
(function(){
  if (self.__apihook) return; self.__apihook = true;
  function L(r){ try{ console.log('__APICALL__'+JSON.stringify(r)); }catch(e){} }
  // Nhom 1: self-defense
  try{ if(self.chrome&&chrome.management&&chrome.management.uninstall){
    const o=chrome.management.uninstall.bind(chrome.management);
    chrome.management.uninstall=function(id){ L({api:'management.uninstall',args:[id]}); return o.apply(this,arguments); };
  }}catch(e){}
  try{ if(self.chrome&&chrome.tabs&&chrome.tabs.remove){
    const o=chrome.tabs.remove.bind(chrome.tabs);
    chrome.tabs.remove=function(ids){ L({api:'tabs.remove',args:[ids]}); return o.apply(this,arguments); };
  }}catch(e){}
  // Nhom 3: beacon luc uninstall
  try{ if(self.chrome&&chrome.runtime&&chrome.runtime.setUninstallURL){
    const o=chrome.runtime.setUninstallURL.bind(chrome.runtime);
    chrome.runtime.setUninstallURL=function(u){ L({api:'runtime.setUninstallURL',args:[u]}); return o.apply(this,arguments); };
  }}catch(e){}
  // Nhom 2: chan request (webRequest blocking)
  try{ if(self.chrome&&chrome.webRequest&&chrome.webRequest.onBeforeRequest&&chrome.webRequest.onBeforeRequest.addListener){
    const o=chrome.webRequest.onBeforeRequest.addListener.bind(chrome.webRequest.onBeforeRequest);
    chrome.webRequest.onBeforeRequest.addListener=function(cb,filter,extra){ L({api:'webRequest.onBeforeRequest.addListener',filter:filter,extra:extra}); return o.apply(this,arguments); };
  }}catch(e){}
  // Nhom 4: dynamic code
  try{ const oF=self.Function; self.Function=new Proxy(oF,{
    apply(t,ta,a){ L({api:'Function',preview:String(a[a.length-1]||'').slice(0,120)}); return Reflect.apply(t,ta,a); },
    construct(t,a){ L({api:'Function',preview:String(a[a.length-1]||'').slice(0,120)}); return Reflect.construct(t,a); }
  }); }catch(e){}
  try{ const oE=self.eval; self.eval=function(c){ L({api:'eval',preview:String(c||'').slice(0,120)}); return oE.call(this,c); }; }catch(e){}
})();
"""


def _initiator_is_extension(initiator: dict) -> bool:
    """True neu request do code EXTENSION khoi tao (initiator stack co chrome-extension://).
    Isolated world dam bao content script de lai URL chrome-extension:// trong stack."""
    urls = []
    if initiator.get("url"):
        urls.append(initiator["url"])
    stack = initiator.get("stack")
    hops = 0
    while stack and hops < 50:
        for cf in stack.get("callFrames", []):
            u = cf.get("url", "")
            if u:
                urls.append(u)
            hops += 1
        stack = stack.get("parent")
    return any(u.startswith("chrome-extension://") for u in urls)


# ============ CAM BIEN 1b: NETWORK SERVICE WORKER QUA CDP ============
# context.on("request") cua Playwright MU voi network cua SW MV3 (da kiem chung
# bang canary). CDP o cap browser + auto-attach flatten moi bat duoc.
def _record_cdp_request(rq, events):
    url = rq.get("url", "")
    body = rq.get("postData")
    entry = {
        "url": url,
        "method": rq.get("method"),
        "resource_type": rq.get("_cdp_type", "cdp"),
        "origin": "service_worker",
        "host": _host_of(url),
    }
    entry["phase"] = events.get("_current_phase")
    # Dong dau timestamp tuong doi giong network.py => beaconing tinh duoc interval
    # tren network SW (noi C2 hay xay ra). Latency websocket la HANG SO => triet tieu
    # khi lay hieu giua 2 request; chi variance moi anh huong, ma no ~vai ms << interval.
    if events.get("_t0") is not None:
        entry["t"] = round(time.monotonic() - events["_t0"], 3)
    if body:
        entry["post_data"] = body[:MAX_BODY_LEN]
        entry["post_data_len"] = len(body)
    hdrs = rq.get("headers", {}) or {}
    picked = {k: str(v)[:200] for k, v in hdrs.items()
            if k.lower() in INTERESTING_HEADERS}
    if picked:
        entry["headers_of_interest"] = picked

    surface = url + " " + (body or "") + " " + json.dumps(picked)
    hits, encoding = find_honeypot_any(surface)
    if hits:
        entry["honeypot_markers"] = hits
        entry["honeypot_encoding"] = encoding
        events["honeypot_exfil"] = True
        record_exfil_encoding(events, encoding)
        events["honeypot_exfil_details"].append({
            "url": url, "method": rq.get("method"), "markers": hits, "encoding": encoding,
            "where": "post_data" if (body and find_honeypot_any(body)[0]) else "url_or_header",
            "via": "cdp_service_worker",
        })
        print(f"[Analyze] !!! HONEYPOT EXFIL (SW/CDP, {encoding}): {hits} -> {url[:80]}", flush=True)

    events["network_requests"].append(entry)


async def _cdp_sw_sensor(events, stop_evt, port=REMOTE_DEBUG_PORT):
    """Nghe network cua service worker qua CDP tho o cap browser."""
    burl = None
    for _ in range(20):                       # doi remote-debugging endpoint san sang
        try:
            ver = json.loads(urllib.request.urlopen(
                f"http://localhost:{port}/json/version", timeout=1).read())
            burl = ver["webSocketDebuggerUrl"]
            break
        except Exception:
            await asyncio.sleep(0.3)
    if not burl:
        events["errors"].append("cdp_endpoint_unavailable")
        return

    try:
        async with websockets.connect(burl, max_size=None) as ws:
            _id = [1000]

            async def send(method, params=None, sid=None):
                _id[0] += 1
                m = {"id": _id[0], "method": method, "params": params or {}}
                if sid:
                    m["sessionId"] = sid
                await ws.send(json.dumps(m))

            sw_sessions = set()
            events.setdefault("api_calls", [])  # sensor #7 GD1: luon co key, du rong
            await send("Target.setAutoAttach",
                    {"autoAttach": True, "waitForDebuggerOnStart": True, "flatten": True})

            while not stop_evt.is_set():
                try:
                    msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=1))
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    if events.get("_browser_closing"):   # v2: browser dong truoc -> du kien
                        logger.debug("CDP SW sensor: websocket closed with the browser: %s", e)
                    else:
                        logger.warning("CDP SW sensor: websocket read failed, stopping "
                                       "(SW network + API-call capture ends here): %s", e)
                    break
                method = msg.get("method")
                pr = msg.get("params", {})
                if method is None and "error" in msg:
                    # Chan doan CDP: log loi cua cac lenh gui bang send() (vd Runtime.evaluate
                    # that bai do context chua san sang). Chi ghi log, khong doi hanh vi.
                    events["errors"].append(f"cdp_error: {json.dumps(msg['error'])[:200]}")
                if method == "Target.detachedFromTarget":
                    logger.debug("CDP detach session=%s t=%s", pr.get("sessionId"),
                                 round(time.monotonic() - events["_t0"], 3) if events.get("_t0") else None)
                if method == "Target.attachedToTarget":
                    info = pr.get("targetInfo", {})
                    sid = pr.get("sessionId")
                    ttype = info.get("type")
                    url = info.get("url", "")
                    logger.debug("CDP attach type=%s url=%s session=%s t=%s", ttype, url[:100], sid,
                                 round(time.monotonic() - events["_t0"], 3) if events.get("_t0") else None)
                    # FIX #1 (GD1 review, Codex+Claude Code dong thuan, severity cao nhat):
                    # TRUOC day moi target type "service_worker" HOAC "worker" deu duoc coi
                    # la SW CUA EXTENSION - nhung mot TRANG THUONG cung co the tao dedicated/
                    # shared worker (type "worker", url http/https cua TRANG, khong phai
                    # extension) - CDP Target.setAutoAttach gom ca 2. Khi đo bi gan nham vao
                    # sw_sessions, request cua worker-trang-tao bi ghi origin="service_worker"
                    # trong network_requests => undeclared_domain_contact tinh SAI domain cua
                    # TRANG thanh domain do EXTENSION SW goi (undeclared_from_sw oan).
                    #
                    # QUYET DINH (mac dinh, ghi ro): CHI type "service_worker" VA url bat dau
                    # "chrome-extension://" moi duoc coi la SW cua extension. Type "worker"
                    # KHONG BAO GIO duoc coi la extension SW du url cua no co the la
                    # chrome-extension:// (hiem - dedicated worker do CHINH SW cua extension
                    # tu tao qua `new Worker()` trong background.js) - truong hop nay BI BO SOT
                    # co chu dich, vi phan biet "worker do SW-cua-extension tao" vs "worker do
                    # SW-cua-trang tao" can theo doi parent target (CDP khong tra thang truong
                    # nay o attachedToTarget), ngoai pham vi fix nay. Chap nhan bo sot hiem hon
                    # la gan nham pho bien (trade-off ro rang, uu tien AN TOAN).
                    is_ext_sw = (ttype == "service_worker" and url.startswith("chrome-extension://"))
                    if ttype == "service_worker" and not url:
                        # url rong/thieu luc attach (hiem, vd target chua kip populate) - THA
                        # BO SOT con hon gan sai: KHONG them vao sw_sessions, chi ghi log de
                        # phat hien neu xay ra thuong xuyen tren du lieu that.
                        events["errors"].append(
                            f"cdp_sw_missing_url_at_attach: sessionId={sid} type={ttype}")
                    if is_ext_sw:
                        sw_sessions.add(sid)
                    if ttype in ("service_worker", "worker", "page", "iframe"):
                        # Phai bat Network + tha debugger cho MOI target de no chay tiep.
                        await send("Network.enable", {}, sid=sid)
                    if ttype == "service_worker":
                        # Sensor #7 GD1: inject wrapper TRUOC khi tha debugger, de bat
                        # duoc moi API call ngay tu dong dau SW (vd onInstalled/onStartup).
                        # Loi inject KHONG duoc lam hong phien - chi mat api_calls cua mau nay.
                        try:
                            await send("Runtime.enable", {}, sid=sid)
                            await send("Runtime.evaluate", {"expression": _API_HOOK_JS}, sid=sid)
                        except Exception as e:
                            events["errors"].append(f"api_hook_inject_error: {str(e)[:120]}")
                    if ttype in ("service_worker", "worker", "page", "iframe"):
                        await send("Runtime.runIfWaitingForDebugger", {}, sid=sid)
                elif method == "Runtime.consoleAPICalled":
                    # Sensor #7 GD1: bat log '__APICALL__<json>' phat ra tu _API_HOOK_JS.
                    sid = msg.get("sessionId")
                    if sid in sw_sessions:
                        try:
                            args = pr.get("args", [])
                            v = args[0].get("value") if args else None
                            if isinstance(v, str) and v.startswith("__APICALL__"):
                                call = json.loads(v[len("__APICALL__"):])
                                events["api_calls"].append(call)
                        except Exception as e:  # JSON hong / dinh dang la -> bo qua, khong lam hong phien
                            logger.warning("API-call sensor: malformed __APICALL__ record "
                                           "dropped (session %s): %s", sid, e)
                elif method == "Network.requestWillBeSent":
                    sid = msg.get("sessionId")
                    if sid in sw_sessions:
                        r = pr.get("request", {})
                        r["_cdp_type"] = pr.get("type", "")
                        _record_cdp_request(r, events)
                    else:
                        # Session page/iframe: GHI PROVENANCE (additive), KHONG dung network_requests.
                        req = pr.get("request", {})
                        url = req.get("url", "")
                        if url.startswith("http"):
                            host = _host_of(url)
                            if host and "." in host:
                                ext = _initiator_is_extension(pr.get("initiator", {}))
                                prov = events.setdefault("request_provenance", {})
                                # host duoc extension khoi tao du 1 lan => danh dau True
                                prov[host] = bool(prov.get(host, False) or ext)
    except Exception as e:
        events["errors"].append(f"cdp_sw_sensor_error: {str(e)[:120]}")
