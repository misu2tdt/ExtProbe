"""v3 DOM sensor: the v2 MutationObserver sensor (sandbox/sensors/dom.py) with an absolute `ts`
(T1-6) on every record. Same page-side script and dedup as v2, so the nodes seen are the same."""
import logging
import time

from v3_common import now_ms

logger = logging.getLogger(__name__)


async def setup_dom_sensor_v3(context, events):
    import sensors.dom as v2dom

    async def _report(source, payload):
        try:
            payload = dict(payload or {})
            try:
                payload["page_url"] = source["page"].url
            except Exception as e:
                logger.warning("v3 DOM sensor: page_url missing: %s", e)
            payload["phase"] = events.get("_current_phase")
            payload["ts"] = now_ms()
            if events.get("_t0") is not None:
                payload["t"] = round(time.monotonic() - events["_t0"], 3)
            events["dom_activity"].append(payload)
        except Exception as e:
            logger.warning("v3 DOM sensor: event dropped: %s", e)

    # Reuse the exact v2 page-side script: capture it from the v2 setup without running it.
    class _Capture:
        script = None

        async def expose_binding(self, name, fn):
            await context.expose_binding(name, _report)

        async def add_init_script(self, script):
            await context.add_init_script(script)

    await v2dom._setup_dom_sensor(_Capture(), events)
