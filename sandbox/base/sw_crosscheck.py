"""Cross-check of the extension's service-worker requests: CDP sensor vs Playwright.

Only when Playwright's SW requests were recorded (SANDBOX_RECORD_PW_SW=1, set on the v2
profile). Writes counts to events["sw_request_crosscheck"]; nothing here is scored.

CDP side: network_requests with origin "service_worker" whose resource_type comes from CDP
(capitalized, e.g. "Fetch", or empty); Playwright's own entries use lowercase types.
Playwright side: events["pw_sw_requests"] issued by the extension's own worker
(chrome-extension://<id>/..., ids taken from service_workers). A pair = same method and
URL, at most 1 s apart.
"""
from utils import _host_of

MATCH_WINDOW_S = 1.0


def _is_cdp_entry(r):
    rt = r.get("resource_type") or ""
    return not rt or rt != rt.lower() or rt == "cdp"


def sw_crosscheck(events):
    if "pw_sw_requests" not in events:
        return None
    own = {_host_of(s.get("url", "")) for s in events.get("service_workers", [])} - {""}
    cdp = [r for r in events.get("network_requests", [])
           if r.get("origin") == "service_worker" and _is_cdp_entry(r)]
    pw = [r for r in events["pw_sw_requests"]
          if r.get("sw_url", "").startswith("chrome-extension://")
          and _host_of(r["sw_url"]) in own]
    used, both = set(), 0
    for r in pw:
        hit = next((i for i, c in enumerate(cdp) if i not in used
                    and c.get("url") == r.get("url") and c.get("method") == r.get("method")
                    and abs((c.get("t") or 0) - (r.get("t") or 0)) <= MATCH_WINDOW_S), None)
        if hit is not None:
            used.add(hit)
            both += 1
    result = {"extension_ids": sorted(own), "cdp": len(cdp), "playwright": len(pw),
              "both": both, "cdp_only": len(cdp) - both, "playwright_only": len(pw) - both,
              "playwright_other_workers": len(events["pw_sw_requests"]) - len(pw)}
    events["sw_request_crosscheck"] = result
    return result
