"""v3.1-probe explorer (eval/v3_1_probe/DESIGN.md §2-§3).

Opens the pages the manifest declares (popup, then options) as tabs, enumerates the visible interactive
elements and clicks them in priority order (v31_policy), over the states it reaches (depth <= MAX_DEPTH,
at most MAX_ACTIONS clicks and BUDGET_S seconds for the whole explorer). An element is never clicked twice
(key = tag + label + position). Forms are filled with PROBE-tagged honeypot values first. A click that an
overlay intercepts is dispatched on the element itself.

After every click: a snapshot from inside the extension page (same permissions as the extension) -- the
number of declarativeNetRequest dynamic / session rules, chrome.storage.local keys with value sizes (no values)
-- and the new tabs. Proxy calls are not handled here: v31_guard records and neutralises every
chrome.proxy.settings call in every extension context from the load phase on (managed policy + wrapper +
monitor), so nothing the explorer makes the extension do can route traffic through a proxy.

Causal evidence for v31_split (probe["ui"]): every tab the explorer opens ("explored") and every page created
while it runs is watched -- "opened_by_ui" when its opener (Playwright) is a watched UI tab, else "other" (a
UI-linked SW call may still have asked for it: decided in v31_split) -- with its main-frame URLs and the
requests Playwright attributes to it.
"""
import asyncio
import os
import time

from v3_common import now_ms
from v31_policy import FORM_VALUES, ext_pages, login_gate, priority, skip_reason, state_hash

BUDGET_S = int(os.environ.get("PROBE_EXPLORE_BUDGET", 30))
MAX_ACTIONS = 15
MAX_DEPTH = 3
SETTLE_MS = 1200
CLICK_COST_S = 3.0                    # worst case of one click + settle + snapshot: no click starts later than BUDGET_S - this

ENUM_JS = r"""
() => {
  const sel = 'button,[role=button],[role=switch],[role=checkbox],[role=tab],[role=menuitem],a[href],' +
              'input[type=checkbox],input[type=radio],input[type=submit],input[type=button],select,summary,[onclick]';
  const out = [];
  // checkbox / radio: aria-label -> aria-labelledby -> el.labels (<label for> and a wrapping <label>) -> title;
  // never value (its default is "on"); empty -> unlabeled (v31_policy.skip_reason)
  const choiceLabel = (el) => {
    let t = (el.getAttribute('aria-label') || '').trim();
    if (!t && el.getAttribute('aria-labelledby'))
      t = el.getAttribute('aria-labelledby').split(/\s+/).map(id => { const n = document.getElementById(id); return n ? n.innerText || n.textContent || '' : ''; }).join(' ').trim();
    if (!t && el.labels) t = Array.from(el.labels).map(l => l.innerText || l.textContent || '').join(' ').trim();
    if (!t) t = (el.title || '').trim();
    return t;
  };
  document.querySelectorAll(sel).forEach((el, i) => {
    const r = el.getBoundingClientRect(), st = getComputedStyle(el);
    if (r.width < 2 || r.height < 2 || st.visibility === 'hidden' || st.display === 'none' || el.disabled) return;
    const choice = el.tagName === 'INPUT' && (el.type === 'checkbox' || el.type === 'radio');
    let text = choice ? choiceLabel(el) : (el.getAttribute('aria-label') || el.innerText || el.value || el.title || el.alt || '').trim();
    if (!text && !choice && el.id) { const l = document.querySelector('label[for="' + el.id + '"]'); if (l) text = l.innerText; }
    text = text.replace(/\s+/g, ' ').slice(0, 60);
    el.setAttribute('data-xp', String(i));
    out.push({xp: String(i), tag: el.tagName.toLowerCase(), role: el.getAttribute('role') || '', type: el.type || '',
              text, href: (el.getAttribute('href') || '').slice(0, 160), checked: !!el.checked,
              inForm: !!el.closest('form')});
  });
  return {items: out, title: document.title, textLen: (document.body ? document.body.innerText.length : 0),
          inputs: document.querySelectorAll('input:not([type=hidden]),textarea').length,
          password_inputs: document.querySelectorAll('input[type=password]').length};
}
"""


SNAP_JS = r"""
async () => {
  const s = {};
  try { s.dnrDynamic = (await chrome.declarativeNetRequest.getDynamicRules()).length; } catch (e) { s.dnrDynamic = null; }
  try { s.dnrSession = (await chrome.declarativeNetRequest.getSessionRules()).length; } catch (e) { s.dnrSession = null; }
  try { const all = await chrome.storage.local.get(null);
        s.storage = Object.fromEntries(Object.entries(all).map(([k, v]) => [k, JSON.stringify(v === undefined ? null : v).length])); }
  catch (e) { s.storage = null; }
  return s;
}
"""
FILL_JS = """(H) => document.querySelectorAll('input:not([type=hidden]),textarea').forEach(i => {
    if (i.type === 'checkbox' || i.type === 'radio' || i.value) return;
    i.value = H[i.type] || H.text; i.dispatchEvent(new Event('input', {bubbles: true})); })"""
DISPATCH_JS = "(x) => { const el = document.querySelector(`[data-xp=\"${x}\"]`); if (!el) return false; el.click(); return true; }"


class UITracker:
    MAX_REQUESTS = 3000

    def __init__(self, context, probe):
        self.context = context
        self.ui = probe.setdefault("ui", {"tabs": [], "requests": []})
        self.pages = {}                                   # page -> tab number
        self.handler = None

    def watch(self, page, why):
        if page in self.pages:
            if why == "explored":                      # the context "page" event may come first
                self.ui["tabs"][self.pages[page]]["why"] = why
            return
        n = len(self.ui["tabs"])
        self.pages[page] = n
        rec = {"tab": n, "why": why, "ts": now_ms(), "urls": [page.url[:300]] if page.url else []}
        self.ui["tabs"].append(rec)
        reqs = self.ui["requests"]

        def on_request(r):
            if len(reqs) < self.MAX_REQUESTS:
                reqs.append({"url": r.url[:2000], "ts": now_ms(), "tab": n})

        def on_nav(f):
            if f == page.main_frame and len(rec["urls"]) < 50:
                rec["urls"].append(f.url[:300])
        page.on("request", on_request)
        page.on("framenavigated", on_nav)

    def start(self):
        async def classify(page):
            try:
                op = await page.opener()
            except Exception:
                op = None
            ui = op is not None and op in self.pages and self.ui["tabs"][self.pages[op]]["why"] in ("explored", "opened_by_ui")
            self.watch(page, "opened_by_ui" if ui else "other")

        def on_page(page):
            asyncio.ensure_future(classify(page))
        self.handler = on_page
        self.context.on("page", on_page)

    def stop(self):
        if self.handler:
            try:
                self.context.remove_listener("page", self.handler)
            except Exception:
                pass


def _delta(a, b, k):
    return (a.get(k) - b.get(k)) if isinstance(a.get(k), int) and isinstance(b.get(k), int) else None


async def explore(context, events, probe):
    t_start = time.monotonic()
    ext_id = (events.get("v3_load") or {}).get("id")
    pages = ext_pages(events.get("manifest") or {})
    probe.update(ext_id_known=bool(ext_id), pages_declared=[k for k, _ in pages], pages=[], stimuli=[],
                 login_gate=False)
    if not ext_id or not pages:
        probe["explore_s"] = round(time.monotonic() - t_start, 1)
        return
    tracker = UITracker(context, probe)
    tracker.start()
    try:
        await _explore_pages(context, probe, pages, ext_id, t_start, tracker)
    finally:
        tracker.stop()
    probe["explore_s"] = round(time.monotonic() - t_start, 1)


async def _explore_pages(context, probe, pages, ext_id, t_start, tracker):
    n_actions, sid = 0, 0
    for kind, path in pages:
        if time.monotonic() - t_start > BUDGET_S or n_actions >= MAX_ACTIONS:
            break
        url = f"chrome-extension://{ext_id}/{path}"
        rec = {"kind": kind, "opened": False, "elements": 0, "states": 0, "clicks": 0, "login_gate": False}
        probe["pages"].append(rec)
        tab = None
        try:
            tab = await context.new_page()
            tracker.watch(tab, "explored")
            await tab.set_viewport_size({"width": 420, "height": 640} if kind == "popup" else {"width": 1100, "height": 720})
            await tab.goto(url, wait_until="domcontentloaded", timeout=5000)
            await tab.wait_for_timeout(800)
            rec["opened"] = True
            snap = await tab.evaluate(ENUM_JS)
            rec.update(elements=len(snap["items"]), inputs=snap["inputs"], login_gate=login_gate(snap),
                       candidates=[[i["text"][:24], priority(i)] for i in snap["items"]][:30], skipped={})
            skipped_keys = set()

            def count_skips(s):
                for i in s["items"]:
                    why = skip_reason(i)
                    if why and (i["tag"], i["text"], i["xp"]) not in skipped_keys:
                        skipped_keys.add((i["tag"], i["text"], i["xp"]))
                        rec["skipped"][why] = rec["skipped"].get(why, 0) + 1
            count_skips(snap)
            probe["login_gate"] = probe["login_gate"] or rec["login_gate"]
            seen = {state_hash(snap)}
            frontier = [(snap, 0)]
            before = await tab.evaluate(SNAP_JS)
            clicked = set()
            while frontier and n_actions < MAX_ACTIONS and time.monotonic() - t_start < BUDGET_S:
                snap, depth = frontier.pop(0)
                cands = sorted(((p, int(i["xp"]), i) for i in snap["items"] if (p := priority(i)) is not None),
                               key=lambda x: (x[0], x[1]))
                for _, _, item in cands:
                    if n_actions >= MAX_ACTIONS or time.monotonic() - t_start + CLICK_COST_S > BUDGET_S:
                        break
                    key = (item["tag"], item["text"], item["xp"])
                    if key in clicked:
                        continue
                    clicked.add(key)
                    if item["inForm"]:
                        await tab.evaluate(FILL_JS, FORM_VALUES)
                    sid += 1
                    stim = {"stimulus_id": f"s{sid}", "page": kind, "depth": depth, "label": item["text"][:60],
                            "tag": item["tag"], "role": item["role"], "ts": now_ms(), "state_before": state_hash(snap)}
                    n_tabs = len(context.pages)
                    try:
                        await tab.locator(f'[data-xp="{item["xp"]}"]').first.click(timeout=1500)
                        stim["clicked"] = True
                    except Exception as e:
                        stim["error"] = str(e).split("\n")[0][:80]
                        try:
                            stim["clicked"] = bool(await tab.evaluate(DISPATCH_JS, item["xp"]))
                            stim["clicked_via"] = "dispatch"
                        except Exception:
                            stim["clicked"] = False
                    await asyncio.sleep(SETTLE_MS / 1000)
                    stim["ts_end"] = now_ms()
                    stim["new_tabs"] = max(0, len(context.pages) - n_tabs)
                    n_actions += 1
                    if tab.is_closed():
                        stim["page_closed"] = True
                        probe["stimuli"].append(stim)
                        break
                    try:
                        if not tab.url.startswith(f"chrome-extension://{ext_id}/"):
                            stim["navigated_away"] = True
                            await tab.goto(url, wait_until="domcontentloaded", timeout=5000)
                        after = await tab.evaluate(SNAP_JS)
                        new = await tab.evaluate(ENUM_JS)
                    except Exception as e:
                        stim["error"] = str(e).split("\n")[0][:80]
                        probe["stimuli"].append(stim)
                        continue
                    stim["state_after"] = state_hash(new)
                    count_skips(new)
                    stim["dnr_dynamic_delta"] = _delta(after, before, "dnrDynamic")
                    stim["dnr_session_delta"] = _delta(after, before, "dnrSession")
                    sb, sa = before.get("storage") or {}, after.get("storage") or {}
                    stim["storage_new_keys"] = len(set(sa) - set(sb))
                    stim["storage_changed_keys"] = sum(1 for k in set(sa) & set(sb) if sa[k] != sb[k])
                    before = after
                    probe["stimuli"].append(stim)
                    rec["clicks"] += 1
                    if stim["state_after"] not in seen and depth + 1 < MAX_DEPTH:
                        seen.add(stim["state_after"])
                        frontier.append((new, depth + 1))
                        break
            rec["states"] = len(seen)
            for why in ("unlabeled", "non_english"):
                probe[f"skipped_{why}"] = probe.get(f"skipped_{why}", 0) + rec["skipped"].get(why, 0)
        except Exception as e:
            rec["error"] = str(e).split("\n")[0][:100]
        finally:
            if tab and not tab.is_closed():
                try:
                    await tab.close()
                except Exception:
                    pass
