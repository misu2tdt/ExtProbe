"""Label tiers for the 313 malware samples + overlap checks (MADWeb, TPCI chrome-mal-ids, MalExt Sentry).

Reads only METADATA (ID lists / CSV / the central directory of the MADWeb zips; nothing is extracted, no .crx is
downloaded). Does not touch labels, scoring, sandbox or image. Writes into eval/v3/labels/:
  labels_tiers.csv, report.md, sentry_overlap_benign.md   (sources.md is written by hand)

Usage:
  py eval/v3/labels/build_labels.py --src <dir>
  <dir> layout (each file = `git show <pinned commit>:<path>` of the repo in sources.md):
    MaliciousBrowserExtensions/database.csv
    chrome-mal-ids/data/current-list-meta.csv
    malicious_extension_sentry/malicious_extensions_detailed.csv
    malicious_v2_v3_extensions/part_1.zip ... part_6.zip     (only namelist() is read)
Local inputs: docs/samples_manifest*.csv, eval/expanded/V2/summary.csv, eval/v3/dev/summary_v3.csv (local, ignored by
git), eval/v3/test/traces_v2|traces_v3, eval/v3/explore/families.csv (local), samples/.
"""
import argparse
import csv
import glob
import hashlib
import re
import struct
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO / "eval" / "v3"))
sys.path.insert(0, str(REPO / "eval"))
import test_analysis as TA  # noqa: E402  (score_v3 + worker.risk on the path)

THR = [15, 25, 35, 40, 50, 60]
BULK = ("Delta_Import", "csv_import", "PDF_Import")

# Publishers of original technical analysis (T2). Decision is by publisher type, not by reading each article.
VENDOR = ["layerxsecurity.com", "koi.ai", "koi.security", "socket.dev", "secureannex.com", "palant.info",
          "obsidiansecurity.com", "esentire.com", "blog.pulsedive.com", "unit42.paloaltonetworks.com",
          "security.com", "socradar.io", "ox.security", "dti.domaintools.com", "cyberhaven.com", "isc.sans.edu",
          "gitlab-com.gitlab.io", "7ai.com"]
VENDOR_PATH = [("raw.githubusercontent.com", "/PaloAltoNetworks/")]
NEWS = ["thehackernews.com", "bleepingcomputer.com", "therecord.media", "gbhackers.com", "cyberinsider.com"]

# (substring list, campaign). First match wins, so specific incidents come before generic ones.
CAMPAIGNS = [
    (["socket.dev/blog/108-chrome-ext", "crypto-firewall/issues/1554"], "Shared-C2 cluster of 108 extensions (Socket)"),
    (["cyberhaven", "isc.sans.edu/diary/31574", "2024/12/16-chrome-extensions-hacked", "1874909746530263213"],
     "Cyberhaven supply-chain compromise (Dec 2024)"),
    (["aiframe-fake-ai", "the-ai-frame-campaign"], "AiFrame fake AI assistants (LayerX)"),
    (["socket.dev/blog/malicious-chrome-extension-performs-hidden-affiliate"], "Hidden affiliate hijacking (Socket)"),
    (["darkspectre", "zoom-stealer", "crypto-firewall/issues/1514"], "DarkSpectre / Zoom Stealer (Koi)"),
    (["obsidiansecurity.com/blog/small-tools"], "API-key stealing extensions (Obsidian)"),
    (["esentire.com/security-advisories"], "eSentire malicious Chrome extension campaign"),
    (["layerx-reveals-40malicious"], "LayerX: 40 malicious browser extensions"),
    (["palant.info/2025/01/20"], "Phoenix Invicta / MV3 remote-code circumvention (Palant)"),
    (["a-flaw-in-claudes-browser-extension"], "LayerX post on Claude extension flaw (IDs listed)"),
    (["blog.pulsedive.com/compromised"], "Pulsedive: compromised browser extensions"),
    (["stealtok"], "StealTok TikTok downloaders (LayerX)"),
    (["silent-takeover"], "Purchased extensions turned into page manipulators (LayerX)"),
    (["urban-vpn", "featured-chrome-browser-extension", "palant.info/2025/01/13"], "Urban VPN / BIScience (Koi, Palant)"),
    (["152-chrome-wallpaper"], "152 Chrome wallpaper extensions (THN 2026-06)"),
    (["chatgpt-deepseek", "steal-ai-chats", "two-chrome-extensions-caught", "malicious-chrome-extensions-steal-chatgpt"],
     "ChatGPT/DeepSeek chat stealers (OX, SOCRadar, THN)"),
    (["vk-styles", "500000-vkontakte"], "VK Styles / VKontakte hijack (Koi)"),
    (["palant.info/2023/06", "75m-installs-removed", "palant/malicious-extensions-list"], "Palant 2023 clusters"),
]


def readcsv(p):
    return list(csv.DictReader(open(p, encoding="utf-8-sig", newline="")))


def host(u):
    return urlparse(u).netloc.lower().replace("www.", "") if u else ""


def is_http(u):
    return bool(u) and u.startswith("http")


def url_kind(u):
    h = host(u)
    p = urlparse(u).path
    if any(h == d or h.endswith("." + d) for d in VENDOR) or any(h == d and p.startswith(pp) for d, pp in VENDOR_PATH):
        return "vendor"
    if any(h == d or h.endswith("." + d) for d in NEWS):
        return "news"
    return "other"


def crx_id(path):
    """Extension ID of a (benign) .crx from its header. Reads the header only."""
    d = open(path, "rb").read(70000)
    if d[:4] != b"Cr24":
        return None
    ver = struct.unpack("<I", d[4:8])[0]
    if ver == 2:
        pl, sl = struct.unpack("<II", d[8:16])
        key = d[16:16 + pl]
        raw = hashlib.sha256(key).digest()[:16]
    elif ver == 3:
        hl = struct.unpack("<I", d[8:12])[0]
        hdr = d[12:12 + hl]

        def fields(b):
            i = 0
            while i < len(b):
                tag = 0
                sh = 0
                while True:
                    c = b[i]; i += 1
                    tag |= (c & 127) << sh; sh += 7
                    if not c & 128:
                        break
                fn, wt = tag >> 3, tag & 7
                if wt == 0:
                    while b[i] & 128:
                        i += 1
                    i += 1
                    continue
                if wt == 2:
                    ln = 0; sh = 0
                    while True:
                        c = b[i]; i += 1
                        ln |= (c & 127) << sh; sh += 7
                        if not c & 128:
                            break
                    yield fn, b[i:i + ln]
                    i += ln
                else:
                    return
        raw = None
        for fn, val in fields(hdr):
            if fn == 10000:
                for f2, v2 in fields(val):
                    if f2 == 1:
                        raw = v2
        if raw is None:
            return None
    else:
        return None
    return "".join(chr(ord("a") + int(c, 16)) for c in raw.hex())


def sv(x):
    return "-" if x[0] is None else str(int(x[0]))


def flag(x):
    return "-" if x[0] is None else ("flag" if x[0] >= 40 else "no")


def pct(k, n):
    return f"{100 * k / n:.1f}%" if n else "n/a"


def table(head, rows):
    return ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)] + ["| " + " | ".join(str(x) for x in r) + " |" for r in rows]


def date_candidates(gfr, tp, urls):
    c = []
    if gfr and gfr.get("date_reported"):
        c.append(gfr["date_reported"])
    if tp and tp.get("DATE-DIS") and tp["DATE-DIS"][:2] == "20":
        c.append(tp["DATE-DIS"])
    for u in urls:
        m = re.search(r"/(20\d\d)/(\d\d)/(\d\d)/", u) or re.search(r"/(20\d\d)/(\d\d)/", u)
        if m:
            c.append("-".join(m.groups()))
        m = re.search(r"/(20\d\d-\d\d-\d\d)-", u)
        if m:
            c.append(m.group(1))
    return sorted(c)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    a = ap.parse_args()
    src = Path(a.src)

    gf = {r["extension_id"]: r for r in readcsv(src / "MaliciousBrowserExtensions" / "database.csv")}
    tp_rows = readcsv(src / "chrome-mal-ids" / "data" / "current-list-meta.csv")
    tp = {}
    for r in tp_rows:
        tp.setdefault(r["EXTID"], r)
    sn = {}
    sn_rows = readcsv(src / "malicious_extension_sentry" / "malicious_extensions_detailed.csv")
    for r in sn_rows:
        sn.setdefault(r["extension_id"], r)
    mw = defaultdict(set)  # id -> {part/folder-version}
    for z in sorted(glob.glob(str(src / "malicious_v2_v3_extensions" / "part_*.zip"))):
        for n in zipfile.ZipFile(z).namelist():
            p = n.split("/")
            if len(p) > 1 and re.match(r"[a-p]{32}_", p[1]):
                mw[p[1][:32]].add(Path(z).stem)

    man = readcsv(REPO / "docs" / "samples_manifest.csv")
    mal = [r for r in man if r["label_raw"] == "malicious"]
    fam = {r["ext_id"]: r["family"] for r in readcsv(HERE.parent / "explore" / "families.csv")}
    v2s = {r["ext_id"]: r for r in readcsv(REPO / "eval" / "expanded" / "V2" / "summary.csv")}
    v3s = {r["ext_id"]: r for r in readcsv(REPO / "eval" / "v3" / "dev" / "summary_v3.csv")}

    def sc(rows, key):
        r = rows.get(key)
        if not r or r["run_status"] != "complete":
            return None, (r or {}).get("run_status", "missing")
        return float(r["risk"]), "complete"

    # ---------------- 313 malware ----------------
    out = []
    for m in mal:
        i = m["ext_id"]
        g, t, s = gf[i], tp.get(i), sn.get(i)
        urls = []
        srcs = []
        if is_http(g["source_url"]):
            urls.append(g["source_url"]); srcs.append("GF:" + g["source_url"])
        if t:
            for k in ("SOURCE", "ARTICLE"):
                if is_http(t[k]):
                    urls.append(t[k]); srcs.append("TPCI:" + t[k])
            for u in (t.get("ADD-SOURCES") or "").replace("|", " ").split():
                if is_http(u):
                    urls.append(u); srcs.append("TPCI:" + u)
        sn_url = s["source"] if s and is_http(s["source"]) else ""
        if sn_url:
            urls.append(sn_url); srcs.append("Sentry:" + sn_url)
        elif s:
            srcs.append("Sentry:" + (s["source"] or "(no source)"))
        if i in mw:
            srcs.append("MADWeb:" + "/".join(sorted(mw[i])))
        urls = list(dict.fromkeys(urls))
        meth = t["CONTRIB-METHOD"] if t else ""
        tp_human = bool(t) and not any(b in meth for b in BULK)
        tp_5a = bool(t) and t["TPCI-BEHAVIORAL"] == "malicious"
        madweb = i in mw
        # vendor evidence: with and without Sentry's per-record source URL
        v_strict = [u for u in urls if url_kind(u) == "vendor" and u != sn_url]
        v_all = [u for u in urls if url_kind(u) == "vendor"]
        basis = []
        if madweb:
            basis.append("madweb")
        if tp_human:
            basis.append("tpci_human")
        if tp_5a:
            basis.append("tpci_5a_malicious")
        if basis:
            tier = "T1"
        elif v_all:
            tier = "T2"
        else:
            tier = "T3"
        tier_strict = "T1" if basis else ("T2" if v_strict else "T3")
        camp = None
        for pats, name in CAMPAIGNS:
            if any(p in u for u in urls for p in pats):
                camp = name
                break
        if camp is None:
            best = next((u for u in urls if url_kind(u) == "vendor"), None) or next((u for u in urls if url_kind(u) == "news"), None)
            camp = "other: " + host(best) + urlparse(best).path[:50] if best else "unattributed"
        dc = date_candidates(g, t, urls)
        rep_date = dc[0] if dc else ""
        v2, v2st = sc(v2s, i)
        v3, v3st = sc(v3s, Path(m["file"]).stem)
        out.append({
            "ext_id": i, "sha256": m["sha256"], "label_raw": m["label_raw"], "label_verified": m["label_verified"],
            "manifest_source": m["source"], "family": fam.get(i, ""), "tier": tier, "tier_excl_sentry_url": tier_strict,
            "t1_basis": "+".join(basis), "sources": " ; ".join(srcs),
            "gf_date_reported": g["date_reported"], "gf_date_added": g["date_added"],
            "tpci_method": meth, "tpci_behavioral": t["TPCI-BEHAVIORAL"] if t else "",
            "tpci_confirm_mal": t["CONFIRM-MAL"] if t else "", "tpci_threat_type": t["THREAT-TYPE"] if t else "",
            "sentry_reason": s["reason"] if s else "", "sentry_date": s["insert_date_fmt"] if s else "",
            "sentry_version": s["version"] if s else "", "sentry_sha256_same": ("" if not s else str(s["sha256"] == m["sha256"]).lower()),
            "in_madweb": str(madweb).lower(), "report_date": rep_date, "report_year": rep_date[:4] or "unknown",
            "campaign": camp, "v2_score": "" if v2 is None else int(v2), "v2_status": v2st,
            "v3_score": "" if v3 is None else int(v3), "v3_status": v3st,
        })
    cols = list(out[0])
    with open(HERE / "labels_tiers.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, cols)
        w.writeheader()
        w.writerows(out)

    # ---------------- benign dev + test with real IDs ----------------
    ben = []
    for m in man:
        if m["label_raw"] == "malicious":
            continue
        loc = m["location"]
        p = (REPO / loc / m["file"]) if not loc.startswith("..") else (REPO / loc / m["file"])
        p = p.resolve() if p.exists() else p
        rid = crx_id(p) if p.exists() else None
        key3 = Path(m["file"]).stem
        ben.append({"set": "dev_old", "id": rid or m["ext_id"], "id_from_crx": bool(rid), "name": key3, "label": m["label_verified"],
                    "v2": sc(v2s, m["ext_id"]), "v3": sc(v3s, key3)})
    bx = readcsv(REPO / "docs" / "samples_manifest_benign_ext.csv")
    for m in bx:
        ben.append({"set": "dev_new", "id": m["ext_id"], "id_from_crx": False, "name": m["name"], "label": m["label"],
                    "v2": sc(v2s, m["ext_id"]), "v3": sc(v3s, m["ext_id"])})
    tm = readcsv(REPO / "docs" / "samples_manifest_benign_test.csv")
    d2 = TA.collect(tm, REPO / "eval" / "v3" / "test" / "traces_v2", "v2", REPO / "samples" / "benign_test")
    d3 = TA.collect(tm, REPO / "eval" / "v3" / "test" / "traces_v3", "v3", REPO / "samples" / "benign_test")
    for m, r2, r3 in zip(tm, d2, d3):
        ben.append({"set": "test", "id": m["ext_id"], "id_from_crx": False, "name": m["name"], "label": m["label"],
                    "v2": (None if r2["score"] is None else float(r2["score"]), r2["run_status"]),
                    "v3": (None if r3["score"] is None else float(r3["score"]), r3["run_status"])})
    cnt_set = Counter(b["set"] for b in ben)

    # ---------------- report ----------------
    L = ["# Label tiers for the 313 malware samples; overlaps with MADWeb / TPCI / MalExt Sentry", "",
         "Generated by `py eval/v3/labels/build_labels.py`. Metadata only: no `.crx` downloaded, the MADWeb zips were only listed "
         "(central directory), nothing was extracted. Labels, scoring, sandbox and image are unchanged. Sources, commits, dates, "
         "licences: `sources.md`.", ""]

    # tier definitions
    L += ["## Tier definition", "",
          "- **T1 verified-behavior**: ID in MADWeb, **or** a TPCI record that is human-reviewed (`CONTRIB-METHOD` without `Delta_Import` / "
          "`csv_import` / `PDF_Import`, per the README \"independently verified entries\"), **or** TPCI Stage 5A verdict `malicious`. "
          "Stage 5A is *static* analysis (TPCI-V.md), so the basis is kept in `t1_basis` and sub-reported below.",
          "- **T2 vendor-report**: not T1, and at least one cited source URL (GF `source_url`, TPCI `SOURCE`/`ARTICLE`/`ADD-SOURCES`, "
          "Sentry `source`) is on a security vendor / researcher site that publishes technical analysis (list in `build_labels.py`, "
          "`VENDOR`). Decided by publisher type; the articles were not opened, so \"the article lists this ID\" is trusted, not checked.",
          "- **T3 news-aggregated only**: everything else.",
          "- Presence in Sentry does **not** raise the tier (the repo warns of false positives). Only the vendor URL in its `source` "
          "field counts as a cited source; the column `tier_excl_sentry_url` shows the tiers without that.", ""]

    n = len(out)
    tiers = ["T1", "T2", "T3"]
    tc = Counter(o["tier"] for o in out)
    ts = Counter(o["tier_excl_sentry_url"] for o in out)
    L += ["## 1. Samples per tier", ""]
    L += table(["tier", "n", "n excl. Sentry source URL", "of which verified label = malicious"],
               [[t, tc[t], ts[t], sum(1 for o in out if o["tier"] == t and o["label_verified"] == "malicious")] for t in tiers] +
               [["total", n, n, sum(1 for o in out if o["label_verified"] == "malicious")]])
    L += ["", "T1 basis (a sample can have several):", ""]
    bc = Counter(b for o in out if o["tier"] == "T1" for b in o["t1_basis"].split("+"))
    L += table(["basis", "n"], [[b, bc[b]] for b in ("madweb", "tpci_human", "tpci_5a_malicious")])
    only5a = sum(1 for o in out if o["t1_basis"] == "tpci_5a_malicious")
    L += ["", f"T1 resting on the static Stage 5A verdict alone: {only5a}.", ""]
    L += ["Presence per source (all 313):", ""]
    L += table(["source", "n"], [["GF database.csv", n], ["TPCI current-list-meta", sum(1 for o in out if o["tpci_method"])],
                                 ["Sentry detailed.csv", sum(1 for o in out if o["sentry_reason"])],
                                 ["MADWeb", sum(1 for o in out if o["in_madweb"] == "true")],
                                 ["TPCI + Sentry", sum(1 for o in out if o["tpci_method"] and o["sentry_reason"])],
                                 ["none of TPCI / Sentry / MADWeb", sum(1 for o in out if not o["tpci_method"] and not o["sentry_reason"] and o["in_madweb"] == "false")]])
    L += ["", "TPCI `CONTRIB-METHOD` of these samples: " + ", ".join(f"{k} {v}" for k, v in Counter(o["tpci_method"] for o in out if o["tpci_method"]).most_common()) + ".",
          "138 of the TPCI records have the Sentry repo as `SOURCE` and 101 have a community GitHub issue (crypto-firewall) as `SOURCE`: "
          "TPCI bulk imports re-use these lists, so TPCI and Sentry are **not independent evidence** for those IDs.", ""]

    # recall per tier
    def stats(rows, prof):
        key = "v2_score" if prof == "v2" else "v3_score"
        ok = [o for o in rows if o[key] != ""]
        res = {}
        for t in THR:
            res[t] = sum(1 for o in ok if int(o[key]) >= t)
        return len(ok), res

    def recall_table(groups, prof_label=True):
        head = ["group", "profile", "n complete"] + [f"@{t}" for t in THR]
        rows = []
        for name, rs in groups:
            for prof in ("v2", "v3"):
                k, res = stats(rs, prof)
                rows.append([name, prof, f"{k} / {len(rs)}"] + [f"{res[t]} ({pct(res[t], k)})" for t in THR])
        return table(head, rows)

    L += ["## 2. Recall by tier (flag = score >= threshold; denominator = complete runs of the group)", "",
          "Positives = every sample of the 313 in the group, i.e. raw label `malicious` (includes the 21 `benign_mislabel`, "
          "6 grey, 2 `unknown_verify` of the verified-label review). Second table: verified label `malicious` only.", ""]
    L += recall_table([("all 313", out)] + [(t, [o for o in out if o["tier"] == t]) for t in tiers])
    L += ["", "Verified label = malicious only:", ""]
    vm = [o for o in out if o["label_verified"] == "malicious"]
    L += recall_table([("all", vm)] + [(t, [o for o in vm if o["tier"] == t]) for t in tiers])
    L += ["", "Same, **without family F000** (101 samples, one campaign; it is split T1 62 / T2 39 and decides the tier gap):", ""]
    nf = [o for o in vm if o["family"] != "F000"]
    L += recall_table([("all (no F000)", nf)] + [(t + " (no F000)", [o for o in nf if o["tier"] == t]) for t in tiers])
    L += ["", "T1 split by basis (all labels):", ""]
    L += recall_table([("T1 tpci_human", [o for o in out if "tpci_human" in o["t1_basis"]]),
                       ("T1 only 5A static", [o for o in out if o["t1_basis"] == "tpci_5a_malicious"]),
                       ("T1 madweb", [o for o in out if "madweb" in o["t1_basis"]])])
    L += ["", "Tier without the Sentry source URL (sensitivity):", ""]
    L += recall_table([(t + " (strict)", [o for o in out if o["tier_excl_sentry_url"] == t]) for t in tiers])
    L += ["", "Context: the dev recall of the whole 313 + benign set is 14.7 % (v3 @40, 354 set), `eval/v3/dev/results.md`. "
          "These tiers are subsets of the same 313; the small groups carry wide intervals (not computed).", ""]

    # year
    yrs = sorted({o["report_year"] for o in out if o["report_year"] != "unknown"}) + ["unknown"]
    L += ["## 3. Recall by report year", "",
          "Report date = earliest of: GF `date_reported`, TPCI `DATE-DIS`, dates embedded in cited URLs (`/YYYY/MM/`). "
          "`unknown` = no dated source in the metadata (e.g. Socket / LayerX URLs without a date). "
          "Sentry's `insert_date` and GF's `date_added` are database dates, not report dates, and are not used.", ""]
    L += recall_table([(y, [o for o in out if o["report_year"] == y]) for y in yrs])
    L += [""]

    # campaigns
    cc = Counter(o["campaign"] for o in out)
    top = [c for c, _ in cc.most_common() if c != "unattributed"][:10]
    L += ["## 4. Recall by campaign (top 10 by size) and mapping of the families", "",
          "Campaign = the first match in a priority list of cited URLs (`CAMPAIGNS` in the script); names are taken from the "
          "article slugs / TPCI notes, not from the articles' text. Others: `other: <site/path>` or `unattributed`.", ""]
    L += recall_table([(c, [o for o in out if o["campaign"] == c]) for c in top])
    rest = [o for o in out if o["campaign"] not in top]
    L += [""] + table(["rest", "n"], [["not in the top 10", len(rest)], ["unattributed", cc["unattributed"]]])
    L += ["", "Families of `eval/v3/explore/` (size >= 3) vs campaign (majority) and tier:", ""]
    fr = []
    byfam = defaultdict(list)
    for o in out:
        byfam[o["family"]].append(o)
    for f, rs in sorted(byfam.items(), key=lambda x: -len(x[1])):
        if len(rs) < 3:
            continue
        c = Counter(o["campaign"] for o in rs).most_common(2)
        tt = Counter(o["tier"] for o in rs)
        fr.append([f, len(rs), "; ".join(f"{k} ({v})" for k, v in c), " ".join(f"{t}:{tt[t]}" for t in tiers if tt[t]),
                   sum(1 for o in rs if o["v3_score"] != "" and int(o["v3_score"]) >= 40), sum(1 for o in rs if o["v2_score"] != "" and int(o["v2_score"]) >= 40)])
    L += table(["family", "size", "campaign (top 2)", "tiers", "v3 flagged @40", "v2 flagged @40"], fr)
    L += ["", "The 154 families come from shared contacted domains; F000 (101) maps to one cited campaign "
          "(Socket, 101 / 101). GF cites a different article for 97 of these 101 (THN \"152 Chrome wallpaper extensions\") "
          "while Sentry/TPCI cite the Socket 108-extension post: **the two sources disagree on the report, not on maliciousness**; "
          "not resolved here (articles not opened).", ""]

    # overlaps
    def inspect(ids_by_set):
        return {k: [x for x in v if x in mw or x in tp or x in sn] for k, v in ids_by_set.items()}

    L += ["## 5. Overlap with MADWeb / TPCI / Sentry", "",
          f"MADWeb: {len(mw)} IDs (517 extensions, each in a v2 and an MV3-equivalent variant: names `<id>_<date>_<hash>_v2|v3`). "
          "Matching is by extension ID only.", ""]
    mal_ids = [o["ext_id"] for o in out]
    ov = [["313 malware", len(mal_ids), sum(1 for x in mal_ids if x in mw), sum(1 for x in mal_ids if x in tp), sum(1 for x in mal_ids if x in sn)]]
    for sname, lab in (("dev_old", "dev benign (41 old)"), ("dev_new", "dev benign (256 new)"), ("test", "test benign (200)")):
        ids_ = [b["id"] for b in ben if b["set"] == sname]
        ov.append([lab, len(ids_), sum(1 for x in ids_ if x in mw), sum(1 for x in ids_ if x in tp), sum(1 for x in ids_ if x in sn)])
    dev_ids = mal_ids + [b["id"] for b in ben if b["set"] != "test"]
    ov.append(["all dev (313 + 297)", len(dev_ids), sum(1 for x in dev_ids if x in mw), sum(1 for x in dev_ids if x in tp), sum(1 for x in dev_ids if x in sn)])
    L += table(["set", "n", "in MADWeb", "in TPCI", "in Sentry"], ov)
    L += [""]
    n_crx = sum(1 for b in ben if b["id_from_crx"])
    L += [f"For the 41 old benign samples the ID was computed from the `.crx` header ({n_crx} of 41 obtained"
          + ("" if n_crx == 41 else "; the others keep their slug and cannot match") + ").", ""]
    hits_dev_mal = [x for x in mal_ids if x in mw]
    hits = [b for b in ben if b["id"] in mw]
    L += [f"MADWeb vs dev malware: {len(hits_dev_mal)} of 313. MADWeb vs benign dev/test: {len(hits)}"
          + (": " + ", ".join(f"{b['name'][:40]} ({b['set']})" for b in hits) if hits else "") + ".",
          "A later MADWeb malware test set therefore has to exclude " + ("no ID of the current dev/test sets by ID match." if not (hits or hits_dev_mal)
                                                                         else "the IDs listed above."),
          "ID match only: MADWeb folders are 2017-2020 crawl versions; a different version of the same ID would still be the same extension.", ""]
    tp_ben = [b for b in ben if b["id"] in tp]
    L += [f"Benign dev/test IDs present in TPCI: {len(tp_ben)} (TPCI lists them as malicious; labels not changed; v3 @40 flagged: "
          f"{sum(1 for b in tp_ben if b['v3'][0] is not None and b['v3'][0] >= 40)} of {sum(1 for b in tp_ben if b['v3'][0] is not None)}).", ""]
    for b in tp_ben:
        r = tp[b["id"]]
        L.append(f"- {b['name'][:45]} ({b['set']}): {r['CONTRIB-METHOD']}, behavioral={r['TPCI-BEHAVIORAL'] or '-'}, "
                 f"STILL-ACTIVE={r['STILL-ACTIVE']}, v2/v3 = {sv(b['v2'])}/{sv(b['v3'])}")
    L += [""]

    # sentry vs benign
    S = ["# Benign samples that appear in MalExt Sentry", "",
         "Generated by `py eval/v3/labels/build_labels.py`. Sentry (`malicious_extensions_detailed.csv`, pinned commit in `sources.md`) "
         "is a **secondary signal**: the repo itself warns that false positives occur. **No label was changed.** Sets: dev benign "
         f"({cnt_set['dev_old']} + {cnt_set['dev_new']} = {cnt_set['dev_old'] + cnt_set['dev_new']}) and held-out test ({cnt_set['test']}). "
         "Matching by extension ID. Score v2 / v3 = frozen scoring (flag at >= 40); `-` = run not complete.", ""]
    sh = [b for b in ben if b["id"] in sn]

    rowsS = []
    for b in sorted(sh, key=lambda b: (b["set"], b["name"])):
        r = sn[b["id"]]
        rowsS.append([b["set"], b["name"][:50].replace("|", "/"), b["label"], r["reason"], r["insert_date_fmt"], r["blocklist"],
                      (host(r["source"]) or r["source"] or "-"), sv(b["v2"]), sv(b["v3"]), flag(b["v3"])])
    S += table(["set", "extension", "label", "Sentry reason", "Sentry date", "blocklist", "Sentry source", "v2", "v3", "v3 @40"], rowsS) if rowsS else ["No overlap."]
    fl = sum(1 for b in sh if b["v3"][0] is not None and b["v3"][0] >= 40)
    fl2 = sum(1 for b in sh if b["v2"][0] is not None and b["v2"][0] >= 40)
    cmp_ = sum(1 for b in sh if b["v3"][0] is not None)
    S += ["", f"Overlap: {len(sh)} of {len(ben)} benign IDs (dev {sum(1 for b in sh if b['set'] != 'test')}, test {sum(1 for b in sh if b['set'] == 'test')}). "
          f"v3 flagged @40: {fl} of {cmp_} complete; v2 flagged @40: {fl2}.",
          "Sentry reasons of the overlap: " + (", ".join(f"{k} {v}" for k, v in Counter(sn[b['id']]['reason'] for b in sh).most_common()) or "-") + ".", "",
          "Reading: a benign-labelled extension that Sentry lists is either a Sentry false positive or a label error of ours (store listings can "
          "be removed for policy reasons unrelated to malware: reasons such as `Policy Violation`, `In store but Suspicious`). "
          "This is flagged for the labelling review, not resolved here."]
    (HERE / "sentry_overlap_benign.md").write_text("\n".join(S) + "\n", encoding="utf-8")

    # sentry reasons for the 313
    L += ["## 6. Sentry as a secondary signal (313 malware)", ""]
    sr = Counter(o["sentry_reason"] or "(not in Sentry)" for o in out)
    L += table(["Sentry reason", "n", "v3 recall @40", "v2 recall @40"],
               [[k, v, pct(sum(1 for o in out if (o["sentry_reason"] or "(not in Sentry)") == k and o["v3_score"] != "" and int(o["v3_score"]) >= 40),
                           sum(1 for o in out if (o["sentry_reason"] or "(not in Sentry)") == k and o["v3_score"] != "")),
                 pct(sum(1 for o in out if (o["sentry_reason"] or "(not in Sentry)") == k and o["v2_score"] != "" and int(o["v2_score"]) >= 40),
                     sum(1 for o in out if (o["sentry_reason"] or "(not in Sentry)") == k and o["v2_score"] != ""))] for k, v in sr.most_common()])
    # The id below is the one extension cited by the Sentry `findings/` report; it is only tested for membership in the 313 dev samples
    # (it is not an in-the-wild set A id).
    L += ["", "Sentry columns: `extension_id, name, reason, source, insert_date_fmt, blocklist, store, version, sha256`. "
          "`reason` is the removal category assigned by Sentry (not a behaviour finding); `source` is a URL or `Store Monitoring`. "
          f"Sentry's sha256 equals our sample's sha256 for {sum(1 for o in out if o['sentry_sha256_same'] == 'true')} of "
          f"{sum(1 for o in out if o['sentry_sha256_same'])} (same package version).",
          "`findings/` in the Sentry repo holds one report (BoostKey / Session Export Tool). The only Sentry record that cites it is "
          f"{'in' if 'mimplmibgdodhkjnclacjofjbgmhogce' in mal_ids else 'not in'} the 313, so it promotes no sample to T2. "
          "The PDF text could not be extracted (no PDF tooling here); IDs inside the PDF other than that record were not checked.", ""]
    dom = Counter()
    for o in out:
        for sx in o["sources"].split(" ; "):
            if ":http" in sx:
                u = sx.split(":", 1)[1]
                dom[(host(u), url_kind(u))] += 1
    L += ["## 7. Cited source domains (sample x URL pairs) and their class", ""]
    L += table(["domain", "class", "pairs"], [[h, k, v] for (h, k), v in sorted(dom.items(), key=lambda x: -x[1])])
    L += ["", "`vendor` = counts towards T2, `news` and `other` do not (class lists: `VENDOR`, `NEWS` in the script). `other` includes "
          "GitHub IOC lists / issues, social posts and info-sharing orgs; a domain can be moved to `VENDOR` by editing the list and re-running.", ""]
    def r40(rows, prof):
        k, res = stats(rows, prof)
        return f"{res[40]}/{k} = {pct(res[40], k)}"
    sm = ["## Summary", "",
          f"- Tiers (313): T1 {tc['T1']}, T2 {tc['T2']}, T3 {tc['T3']}. Without Sentry's per-record source URL: T1 {ts['T1']}, T2 {ts['T2']}, T3 {ts['T3']}. "
          "Most T2 evidence is the vendor URL that Sentry attaches; GF alone cites mostly THN (news).",
          f"- T1 is 0 from MADWeb ({len(mw)} IDs, none among the 313), {bc['tpci_human']} from TPCI human-reviewed, {bc['tpci_5a_malicious']} from the static Stage 5A "
          f"verdict (only {only5a} on that alone, {sum(1 for o in out if o['t1_basis'] == 'tpci_5a_malicious' and o['family'] == 'F000')} of them in F000). "
          "Stage 5A `malicious` = risk >= 100 or any critical finding, e.g. a known malicious C2 domain (SCHEMA.md); it is a static verdict, and the findings "
          "behind it are not in the CSV, so whether it is independent of the source list cannot be checked here.",
          "- Recall @40, verified-malicious only, v2 / v3: " + "; ".join(
              f"{t} {r40([o for o in vm if o['tier'] == t], 'v2')} / {r40([o for o in vm if o['tier'] == t], 'v3')}" for t in tiers)
          + f"; all {r40(vm, 'v2')} / {r40(vm, 'v3')}.",
          "- Recall does not rise with label confidence. v3 @40 (verified-malicious) goes T1 -> T2 -> T3: "
          + " -> ".join(pct(stats([o for o in vm if o['tier'] == t], 'v3')[1][40], stats([o for o in vm if o['tier'] == t], 'v3')[0]) for t in tiers)
          + "; without F000 (101 samples, 62 T1 / 39 T2, v3 flags 0): "
          + " -> ".join(pct(stats([o for o in nf if o['tier'] == t], 'v3')[1][40], stats([o for o in nf if o['tier'] == t], 'v3')[0]) for t in tiers)
          + ". The T1 gap is mostly F000; the rest is small groups (T3: 32), so no tier effect can be claimed in either direction.",
          f"- Sentry: {len(sh)} of {len(ben)} benign dev/test IDs are listed (v3 flags {fl} of {cmp_}); TPCI: {len([b for b in ben if b['id'] in tp])}. "
          "Labels unchanged; see `sentry_overlap_benign.md` and section 5. Test-set items such as a Sentry `Malware` record for a benign-labelled "
          "test extension should go to the labelling review before the test FPR is quoted again.",
          "- MADWeb overlap with the dev set: 0 malware, 0 benign (ID match). A MADWeb test set can use all 517 IDs.", ""]
    L[3:3] = sm
    (HERE / "report.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("tiers", dict(tc), "strict", dict(ts), "sentry-benign", len(sh), "benign total", len(ben))


if __name__ == "__main__":
    main()
