"""v3 post-processing at the end of a run (no Playwright imports: unit-testable on the host).

  assign_phase_ts   T1-6: every event with an absolute `ts` gets `phase_ts`, the phase whose
                    [ts_start, ts_end) holds it ("pre_load" before the first phase, "post_run" after
                    the last). The v2 field `phase` (assigned when the event was recorded) is kept.
  join_initiators   T1-1: each Playwright page request in network_requests is matched to the CDP
                    record of the same URL + method with the nearest timestamp (<= 2 s, each CDP
                    record used once) and gets `initiator_ext` (True / False / None) and
                    `initiator_ext_frame`.
  finalize_tabs     T1-4: final URL and per-navigation redirect chains of tabs_v3.
  finalize_sw_tab_calls T1-3: seconds since install (browser launch with --load-extension).
"""
from bisect import bisect_right
from collections import defaultdict

TS_LISTS = ("network_requests", "responses", "navigations", "dom_activity", "api_calls", "console_logs",
            "tabs_v3", "page_request_initiators", "sw_tab_calls", "target_matched_route_log", "new_tabs",
            "dom_node_initiators", "page_api_hooks")


def phase_of(ts, bounds):
    """bounds = sorted [(ts_start, ts_end, name)]."""
    if ts is None or not bounds:
        return None
    starts = [b[0] for b in bounds]
    i = bisect_right(starts, ts) - 1
    if i < 0:
        return "pre_load"
    s, e, name = bounds[i]
    if e is None or ts < e:
        return name
    if i + 1 < len(bounds):
        return "between_phases"
    return "post_run"


def assign_phase_ts(events):
    bounds = sorted((p["ts_start"], p.get("ts_end"), p["name"]) for p in events.get("phases", [])
                    if p.get("ts_start") is not None)
    n = 0
    for key in TS_LISTS:
        for ev in events.get(key, []) or []:
            ts = ev.get("ts") if ev.get("ts") is not None else ev.get("created_ts", ev.get("opened_ts"))
            if ts is not None:
                ev["phase_ts"] = phase_of(ts, bounds)
                n += 1
    return n


def join_initiators(events, window_ms=2000):
    idx = defaultdict(list)
    for i, rec in enumerate(events.get("page_request_initiators", []) or []):
        idx[(rec.get("url"), rec.get("method"))].append((rec.get("ts"), i))
    used = set()
    matched = 0
    for req in events.get("network_requests", []):
        if req.get("origin") != "page":
            continue
        best = None
        for ts, i in idx.get((req.get("url"), req.get("method")), []):
            if i in used or ts is None or req.get("ts") is None:
                continue
            d = abs(ts - req["ts"])
            if d <= window_ms and (best is None or d < best[0]):
                best = (d, i)
        if best is None:
            req["initiator_ext"] = None
            continue
        used.add(best[1])
        rec = events["page_request_initiators"][best[1]]
        req["initiator_ext"] = {"extension": True, "page": False,
                                "page_via_extension_hook": False}.get(rec.get("attributed"))
        if rec.get("attributed") == "page_via_extension_hook":
            req["initiator_via_ext_hook"] = True
        if rec.get("ext_frames"):
            req["initiator_ext_frame"] = rec["ext_frames"][0]
        matched += 1
    return matched


def cdp_document_chains(events):
    """Redirect chains of document requests from the CDP records (same requestId; each hop
    carries redirect_from). Returns [{urls: [first .. last], ts_first, ts_last}]."""
    groups = defaultdict(list)
    for r in events.get("page_request_initiators", []) or []:
        if r.get("resource_type") == "Document" and r.get("request_id"):
            groups[r["request_id"]].append(r)
    out = []
    for recs in groups.values():
        recs.sort(key=lambda r: r.get("ts") or 0)
        urls = []
        for r in recs:
            if r.get("redirect_from") and (not urls or urls[-1] != r["redirect_from"]):
                urls.append(r["redirect_from"])
            urls.append(r["url"])
        out.append({"urls": urls, "ts_first": recs[0].get("ts"), "ts_last": recs[-1].get("ts")})
    return out


def finalize_tabs(events, lookback_ms=30000):
    """T1-4. Playwright reports a tab opened by the extension late (after its first navigation
    and redirects), so the initial URL it sees can already be the redirect target. The CDP
    document chain that ends at that URL, started within lookback_ms before the report, gives
    the real first URL, the redirect hops and the creation time (`created_ts`)."""
    chains = cdp_document_chains(events)
    for t in events.get("tabs_v3", []) or []:
        navs = t.get("navigations", [])
        t["final_url"] = navs[-1]["url"] if navs else t.get("initial_url")
        reqs = t.pop("_nav_requests", [])
        redirects = [{"url": r["url"], "ts": r.get("ts"), "redirect_chain": r["redirect_chain"], "source": "playwright"}
                     for r in reqs if r.get("redirect_chain")]
        t["created_ts"] = t.get("opened_ts")
        best = None
        for c in chains:
            if c["urls"] and c["urls"][-1] == t.get("initial_url") and c["ts_first"] is not None \
                    and t.get("opened_ts") is not None and t["opened_ts"] - lookback_ms <= c["ts_first"] <= t["opened_ts"] + 500:
                if best is None or c["ts_first"] < best["ts_first"]:
                    best = c
        if best is not None:
            t["first_url"] = best["urls"][0]
            t["created_ts"] = min(t["opened_ts"], best["ts_first"])
            if len(best["urls"]) > 1:
                redirects.insert(0, {"url": best["urls"][-1], "ts": best["ts_last"], "redirect_chain": best["urls"][:-1],
                                     "source": "cdp"})
        else:
            t["first_url"] = t.get("initial_url")
        # a recorded SW call that opened this URL is the earliest evidence of creation (T1-3)
        for c in events.get("sw_tab_calls", []) or []:
            u = c.get("url") or ""
            if c.get("ts") is not None and t.get("opened_ts") is not None and u \
                    and (t["first_url"] or "").rstrip("/").startswith(u.rstrip("/")[:200]) \
                    and t["opened_ts"] - lookback_ms <= c["ts"] <= t["opened_ts"]:
                t["created_ts"] = min(t["created_ts"], c["ts"])
                t["opened_by_sw_call"] = c.get("api")
        t["redirects"] = redirects


def finalize_sw_tab_calls(events):
    """The same console record can arrive on two CDP sessions attached to one worker: drop
    exact duplicates (api, url, ts), then add seconds since install."""
    t0 = events.get("t0_wall")
    seen, uniq = set(), []
    for c in events.get("sw_tab_calls", []) or []:
        key = (c.get("api"), c.get("url"), c.get("ts"))
        if key not in seen:
            seen.add(key)
            uniq.append(c)
    events["sw_tab_calls"] = uniq
    install = events.get("install_ts")          # CDP load (A1b); else browser launch with --load-extension
    for c in uniq:
        if c.get("ts") is None:
            continue
        if install is not None:
            c["t_since_install"] = round((c["ts"] - install) / 1000, 3)
        elif t0 is not None:
            c["t_since_install"] = round(c["ts"] / 1000 - t0, 3)


def mark_extension_tabs(events):
    """A1a: a tab is extension-opened when the harness did not create it and no web page opened
    it (window.open from a site). Adds `extension_opened` and, for those, seconds since install."""
    install = events.get("install_ts")
    t0 = events.get("t0_wall")
    for t in events.get("tabs_v3", []) or []:
        t["extension_opened"] = t.get("opened_by") != "harness" and not t.get("opener_is_page")
        base = install if install is not None else (t0 * 1000 if t0 is not None else None)
        if t["extension_opened"] and base is not None and t.get("created_ts") is not None:
            t["t_since_install"] = round((t["created_ts"] - base) / 1000, 3)


def join_node_initiators(events, window_ms=5000):
    """A2: attribution of each v2 DOM record (dom_activity node_injected) from the CDP creation
    stack of the node with the same tag and src, nearest in time."""
    idx = defaultdict(list)
    for i, n in enumerate(events.get("dom_node_initiators", []) or []):
        idx[(n.get("tag"), n.get("src"))].append(i)
    used, matched = set(), 0
    for d in events.get("dom_activity", []) or []:
        if d.get("type") != "node_injected":
            continue
        best = None
        for i in idx.get((d.get("tag"), d.get("src")), []):
            if i in used:
                continue
            n = events["dom_node_initiators"][i]
            dt = abs((n.get("ts") or 0) - (d.get("ts") or 0))
            if dt <= window_ms and (best is None or dt < best[0]):
                best = (dt, i)
        if best is None:
            d["node_attributed"] = None
            continue
        used.add(best[1])
        n = events["dom_node_initiators"][best[1]]
        d["node_attributed"] = n.get("attributed")
        d["node_initiator_index"] = best[1]
        if n.get("ext_frames"):
            d["node_ext_frame"] = n["ext_frames"][0]
        matched += 1
    return matched


def post_process(events):
    finalize_sw_tab_calls(events)
    finalize_tabs(events)
    mark_extension_tabs(events)
    n_join = join_initiators(events)
    n_nodes = join_node_initiators(events)
    n_ts = assign_phase_ts(events)
    events["v3_post"] = {"initiator_joined": n_join, "nodes_joined": n_nodes, "events_with_phase_ts": n_ts}
