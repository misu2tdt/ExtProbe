import asyncio
import logging
import time

logger = logging.getLogger(__name__)

# ============ CAM BIEN 4: DOM MUTATION ============
async def _setup_dom_sensor(context, events):
    """
    MutationObserver dat o MAIN WORLD.
    Content script chay o isolated world (JS rieng) NHUNG DOM la CHUNG
    => van thay duoc moi thay doi DOM do content script gay ra.

    FUTURE WORK (chan doan, chua lam - xem LIMITATION "INLINE SCRIPT/IFRAME INJECTION #2"
    trong worker/risk.py de biet ly do day du): sensor nay CO ghi node inline (SCRIPT/IFRAME/
    FORM khong co `.src`, xem `src = n.src || n.action || '(inline)'` ben duoi) nhung (a)
    KHONG capture noi dung (`textContent`/`innerHTML`), chi co `tag` + chuoi hang `"(inline)"`,
    va (b) dedup key `tag + '|' + src` bien thanh HANG SO cho moi node inline tren 1 trang =>
    sau node inline DAU TIEN, cac injection inline TIEP THEO (noi dung khac) bi drop het.
    Muon bat inline injection dang ngo (an toan, khong no FP tren inline binh thuong nhu GA/
    config) can: capture noi dung (truncate), doi dedup key, VA co provenance nguon (content-
    script vs chinh trang) - ngoai pham vi cam bien hien tai.
    """
    async def _report(source, payload):
        try:
            payload = dict(payload or {})
            try:
                payload["page_url"] = source["page"].url
            except Exception as e:
                logger.warning("DOM sensor: page_url missing for %s event "
                               "(page closed?): %s", payload.get("type"), e)
            # THEM METADATA (giong network.py:_record_request) — KHONG doi dieu kien bat
            # node / dedup / page_url. phase = phase dang chay luc node duoc bao cao;
            # t = giay tuong doi so voi _t0. Cho phep slice dom_activity theo phase
            # (ablation stimulus C2 - script_injection channel).
            payload["phase"] = events.get("_current_phase")
            if events.get("_t0") is not None:
                payload["t"] = round(time.monotonic() - events["_t0"], 3)
            events["dom_activity"].append(payload)
            if payload.get("type") == "node_injected":
                print(f"[Analyze] * DOM inject: <{payload.get('tag')}> "
                      f"{str(payload.get('src'))[:80]}", flush=True)
        except Exception as e:
            logger.warning("DOM sensor: event dropped: %s", e)

    await context.expose_binding("__extanalyze_report", _report)

    await context.add_init_script("""
    (() => {
      const seen = new Set();
      let injectedCount = 0;
      const send = (d) => { try { window.__extanalyze_report(d); } catch (e) {} };

      const handle = (muts) => {
        for (const m of muts) {
          for (const n of m.addedNodes) {
            if (!n || n.nodeType !== 1) continue;
            injectedCount++;
            const tag = n.tagName;
            if (tag === 'SCRIPT' || tag === 'IFRAME' || tag === 'FORM') {
              const src = n.src || n.action || '(inline)';
              const key = tag + '|' + src;
              if (!seen.has(key)) {
                seen.add(key);
                send({ type: 'node_injected', tag: tag,
                       src: String(src).slice(0, 300) });
              }
            }
          }
        }
      };

      try {
        const obs = new MutationObserver(handle);
        const start = () => {
          try { obs.observe(document.documentElement || document,
                            { childList: true, subtree: true }); } catch (e) {}
        };
        start();
        document.addEventListener('DOMContentLoaded', start);
      } catch (e) {}

      setTimeout(() => send({ type: 'mutation_summary',
                              injected_nodes: injectedCount }), 2500);
    })();
    """)
