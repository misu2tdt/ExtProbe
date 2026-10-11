"""Split of a v3.1-probe run into the v3 trace and the probe trace (pure Python; unit-tested in tests/v31).

  events.json        every list item recorded before the probe started (same schema as v3; score_v3 reads it
                     unchanged), the extension storage read before the probe, honeypot_exfil recomputed from
                     the pre-probe details
  events_probe.json  every list item recorded from the probe start on, tagged with cause_class / cause_reason
                     (and stimulus_id when caused by a click), the probe log, the probe phases and the storage
                     read after the browser closed
"Recorded from the probe start on" = timestamp >= probe_t0 for items that carry one (ts / created_ts /
opened_ts); for items without a timestamp (e.g. target_page_probe, errors), position >= the list length noted
at the probe start (events["_offsets"]). api_calls and sw_tab_calls are cut by position (arrival order) even when
they carry a timestamp: a new CDP session's Runtime.enable replays the worker's console with the ORIGINAL
timestamps, and such replays arriving after the probe start must not be added to the v3 part.
Records that are not the extension's (v31 harness) never stay in events.json: the guard's own records
(xp.*, proxy.settings.*, declarativeNetRequest.* -- v3 does not record these) and the v2 eval hook's records of
the harness's own evaluations (proxy monitor). Before the probe start they go to events_probe.json
"api_calls_harness_pre"; after it they are tagged harness_record (also exact replays of an earlier record).

Causal class: by where the item comes from, not by time.
  user_initiated  typed_input          carries a PROBE-tagged value the explorer typed
                  ui_tab               a request / tab / navigation of a UI tab: an extension page the explorer
                                       opened, a tab opened by one (opener chain, Playwright), or a tab whose URL
                                       a UI-linked SW call asked for
                  extension_frame      a request or DOM node of a chrome-extension:// frame
                  sw_message_from_ui   a service-worker request / tab call whose JS stack (async frames included)
                                       goes through a runtime.onMessage listener run for a message from one of the
                                       extension's pages (v31_guard record xp.caused_by_ui)
  post_probe      everything else, in particular service-worker activity with no such chain, however close in
                  time to a click
  harness_record  the guard's own records
"""
import base64
import copy
import json
from urllib.parse import quote

from v31_policy import PROBE_TOKENS

TAGGED = ("network_requests", "page_request_initiators", "tabs_v3", "new_tabs", "navigations", "api_calls",
          "sw_tab_calls", "dom_activity", "dom_node_initiators", "responses", "honeypot_exfil_details")
POSITION_LISTS = ("api_calls", "sw_tab_calls")
GUARD_APIS = ("xp.", "proxy.settings.", "declarativeNetRequest.")
HARNESS_EVAL_PREFIXES = ("async () => { if (!(self.chrome && chrome.proxy))", "async () => { if (!self.__xpRealProxy)")
UI_REQ_SLACK_MS = 3000          # same URL seen by Playwright on a UI tab and by a sensor: timestamps within this
SW_CALL_WINDOW_MS = (-200, 10000)   # SW request vs the UI-linked call that issued it (call first)


def item_ts(it):
    if not isinstance(it, dict):
        return None
    for k in ("ts", "created_ts", "opened_ts"):
        if it.get(k) is not None:
            return it[k]
    return None


def offsets(events):
    """List lengths at the probe start (call right before the probe phases)."""
    return {k: len(v) for k, v in events.items() if isinstance(v, list) and not k.startswith("_")}


def harness_api_record(a):
    """True for an api_calls record that the v3.1 harness, not the extension, caused or wrote."""
    if not isinstance(a, dict):
        return False
    api = str(a.get("api") or "")
    if api.startswith(GUARD_APIS):
        return True
    return api in ("eval", "Function") and str(a.get("preview") or "").startswith(HARNESS_EVAL_PREFIXES)


def _replay_key(a):
    return json.dumps(a, sort_keys=True, default=str) if isinstance(a, dict) else None


def _typed(it):
    try:
        s = json.dumps(it, ensure_ascii=False, default=str)
    except Exception:
        return False
    return any(t in s or quote(t) in s or base64.b64encode(t.encode()).decode().rstrip("=") in s for t in PROBE_TOKENS)


class Causes:
    """Causal evidence of one run (built from the probe record and the post-probe api_calls)."""

    def __init__(self, probe, api_calls, t0):
        ui = probe.get("ui") or {}
        self.sw_req, self.sw_tab = {}, {}
        for a in api_calls or []:
            if isinstance(a, dict) and a.get("api") == "xp.caused_by_ui" and (t0 is None or (a.get("ts") or 0) >= t0):
                d = self.sw_tab if str(a.get("kind", "")).startswith(("tabs.", "windows.")) else self.sw_req
                d.setdefault(a.get("url") or "", []).append(a.get("ts") or 0)
        tabs = ui.get("tabs") or []
        linked = set(self.sw_tab)
        self.ui_tabs = {t["tab"] for t in tabs if t.get("why") in ("explored", "opened_by_ui")
                        or (t.get("why") == "other" and linked & set(t.get("urls") or []))}
        self.ui_urls = set()
        for t in tabs:
            if t["tab"] in self.ui_tabs:
                self.ui_urls |= set(t.get("urls") or [])
        self.ui_req = {}
        for r in ui.get("requests") or []:
            if r.get("tab") in self.ui_tabs:
                self.ui_req.setdefault(r.get("url") or "", []).append(r.get("ts") or 0)

    def _ui_request(self, url, ts):
        hits = self.ui_req.get(url or "")
        if not hits:
            return False
        return ts is None or any(abs(ts - h) <= UI_REQ_SLACK_MS for h in hits)

    def _sw_linked(self, d, url, ts, window=SW_CALL_WINDOW_MS):
        hits = d.get(url or "")
        if not hits:
            return False
        return ts is None or any(window[0] <= ts - h <= window[1] for h in hits)

    def classify(self, kind, it):
        """-> (cause_class, cause_reason)"""
        if not isinstance(it, dict):
            return "post_probe", None
        ts = item_ts(it)
        url = it.get("url") or it.get("initial_url") or it.get("first_url") or ""
        if kind == "api_calls" and harness_api_record(it):
            return "harness_record", "guard" if str(it.get("api", "")).startswith(GUARD_APIS) else "harness_eval"
        if _typed(it):
            return "user_initiated", "typed_input"
        if kind == "network_requests":
            if it.get("origin") == "service_worker" or it.get("source") == "cdp_sw":
                if self._sw_linked(self.sw_req, url, ts):
                    return "user_initiated", "sw_message_from_ui"
                return "post_probe", "sw_unlinked"
            return ("user_initiated", "ui_tab") if self._ui_request(url, ts) else ("post_probe", None)
        if kind in ("page_request_initiators", "honeypot_exfil_details", "responses"):
            if self._ui_request(url, ts):
                return "user_initiated", "ui_tab"
            if (it.get("frame_target_url") or "").startswith("chrome-extension://"):
                return "user_initiated", "extension_frame"
            return "post_probe", None
        if kind in ("tabs_v3", "new_tabs", "navigations"):
            urls = {it.get(k) for k in ("url", "initial_url", "first_url", "final_url") if it.get(k)}
            urls |= {n.get("url") for n in it.get("navigations") or [] if isinstance(n, dict) and n.get("url")}
            if urls & self.ui_urls:
                return "user_initiated", "ui_tab"
            if any(self._sw_linked(self.sw_tab, u, ts, (-10000, 10000)) for u in urls):
                return "user_initiated", "sw_message_from_ui"
            return "post_probe", None
        if kind == "sw_tab_calls":
            if self._sw_linked(self.sw_tab, url, ts, (-1000, 1000)):
                return "user_initiated", "sw_message_from_ui"
            return "post_probe", None
        if kind in ("dom_node_initiators", "dom_activity"):
            if (it.get("frame_target_url") or it.get("page_url") or "").startswith("chrome-extension://"):
                return "user_initiated", "extension_frame"
            return "post_probe", None
        return "post_probe", None


def _stimulus_before(ts, stimuli):
    best = None
    for s in stimuli:
        if ts is not None and s.get("ts") is not None and s["ts"] <= ts:
            best = s.get("stimulus_id")
    return best


def split(events):
    """-> (pre, post). `events` is the full run (probe_t0, _offsets, _probe, _pre_storage set by analyze_v31)."""
    t0 = events.get("probe_t0")
    offs = events.get("_offsets") or {}
    probe = events.get("_probe") or {}
    pre_storage = events.get("_pre_storage") or (None, None)
    pre = {k: v for k, v in events.items() if not k.startswith("_") and k not in ("probe_phases", "probe_t0", "probe_target")}
    post = {"probe": probe, "probe_phases": events.get("probe_phases", []), "probe_t0": t0,
            "probe_target": events.get("probe_target")}
    stimuli = probe.get("stimuli", [])
    per_stim = {}
    if t0 is not None:
        moved_all = {}
        for k, items in list(pre.items()):
            if not isinstance(items, list):
                continue
            off = offs.get(k, 0)
            keep, moved = [], []
            for i, it in enumerate(items):
                ts = item_ts(it)
                late = (i >= off) if (ts is None or k in POSITION_LISTS) else (ts >= t0)
                (moved if late else keep).append(it)
            pre[k] = keep
            if moved:
                moved_all[k] = moved
        harness_pre = [a for a in pre.get("api_calls") or [] if harness_api_record(a)]
        if harness_pre:
            pre["api_calls"] = [a for a in pre["api_calls"] if not harness_api_record(a)]
            post["api_calls_harness_pre"] = harness_pre
        causes = Causes(probe, moved_all.get("api_calls"), t0)
        for k, moved in moved_all.items():
            out = []
            seen = {_replay_key(a) for a in pre.get(k) or []} if k in POSITION_LISTS else set()
            for it in moved:
                if isinstance(it, dict) and k in TAGGED:
                    rk = _replay_key(it) if k in POSITION_LISTS else None
                    it = copy.copy(it)
                    cc, why = causes.classify(k, it)
                    if rk is not None and rk in seen and cc != "harness_record":
                        cc, why = "harness_record", "replay"
                    if rk is not None:
                        seen.add(rk)
                    sid = _stimulus_before(item_ts(it), stimuli) if cc == "user_initiated" else None
                    it["cause_class"], it["cause_reason"], it["stimulus_id"] = cc, why, sid
                    if sid and k in ("network_requests", "page_request_initiators"):
                        per_stim[sid] = per_stim.get(sid, 0) + 1
                out.append(it)
            post[k] = out
    for s in stimuli:
        s["requests_caused"] = per_stim.get(s.get("stimulus_id"), 0)
    post["extension_storage"] = events.get("extension_storage")
    post["extension_storage_v3"] = events.get("extension_storage_v3")
    if pre_storage[0] is not None:
        pre["extension_storage"], pre["extension_storage_v3"] = copy.deepcopy(pre_storage[0]), copy.deepcopy(pre_storage[1])
        pre["honeypot_stored"] = bool((pre_storage[0] or {}).get("honeypot_found"))
    if t0 is not None:
        pre["honeypot_exfil"] = bool(pre.get("honeypot_exfil_details"))
        if not pre["honeypot_exfil"]:
            pre["honeypot_exfil_encoding"] = None
    return pre, post
