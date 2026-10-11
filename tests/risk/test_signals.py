"""
Test tang phan tich TACH KHOI sandbox: khong can Docker/browser,
chi can du lieu events -> kiem tra dien giai dung.
Chay: python worker/test_undeclared.py

LUU Y domain gia lap: dung hau to ".evil-test" (KHONG dung ".invalid") cho cac host
"doc hai" mo phong trong fixture, vi ".invalid" gio bi _is_harness_host() loai (RFC 6761,
domain nay khong bao gio resolve that => that ra la dau hieu chac chan cua canary/test
infra trong PRODUCTION, xem HARNESS_HOSTS). Neu dung ".invalid" o day cac assert ve
"phai bi phat hien" se that bai vi bi loc mat.
"""
from risk import (
    detect_undeclared_domains, detect_unsolicited_tabs, detect_script_injection,
    detect_local_harvest, detect_beaconing, build_behavioral_report, compute_risk_score,
    _manifest_declared_hosts, _is_declared_host, _is_known_infra_host, _own_extension_ids,
)

# events toi gian mo phong canary: SW goi domain la, page goi domain la,
# khai bao rong, co ca example.com (harness) de kiem tra loc.
fake_events = {
    "manifest": {"name": "canary", "host_permissions": [], "permissions": []},
    "network_requests": [
        {"url": "https://canary-c2.evil-test/collect", "origin": "service_worker"},
        {"url": "https://canary-inject.evil-test/x.js", "origin": "page"},
        {"url": "https://canary-frame.evil-test/y.html", "origin": "page"},
        {"url": "https://example.com/", "origin": "page"},          # harness -> phai loc
    ],
    # GD3: provenance quyet dinh host "page" nao thuc ra la content-script khoi tao.
    "request_provenance": {
        "canary-inject.evil-test": True,    # content script (isolated world) tu chen -> tinh
        "canary-frame.evil-test": False,    # trang tu tai -> BO (khong phai hanh vi extension)
    },
    "honeypot_exfil": True,
    "page_hang_count": 0,
}

r = detect_undeclared_domains(fake_events)
assert r["has_undeclared"] is True, "phai phat hien undeclared"
assert "canary-c2.evil-test" in r["undeclared_from_sw"], "SW C2 phai bi bat"
assert "canary-inject.evil-test" in r["undeclared_from_cs"], "content-script domain phai bi bat"
assert "canary-frame.evil-test" not in r["undeclared_total"], "page-initiated phai bi loc (GD3)"
assert "example.com" not in r["undeclared_total"], "harness phai bi loc"
print("detect PASS:", r)

report = build_behavioral_report(fake_events)
score, level, _ = compute_risk_score(report)
assert report["indicators"]["undeclared_domain_contact"] is True, "indicator phai bat"
assert "dynamic" in report, "report phai co khoi dynamic"
print(f"score PASS: {score} ({level})")
print("dynamic block:", report["dynamic"])


print("\n=== TEST TACH STATIC/DYNAMIC ===")

def score_of(events):
    rep = build_behavioral_report(events)
    return compute_risk_score(rep)

# KB1: manifest xau, runtime im lang => static cao, dynamic ~0
kb1 = {
    "manifest": {"name": "x", "permissions": ["cookies", "tabs", "history", "webRequest", "scripting"],
                 "host_permissions": ["<all_urls>"],
                 "content_scripts": [{"matches": ["<all_urls>"], "js": ["a.js"]}]},
    "network_requests": [], "honeypot_exfil": False, "page_hang_count": 0,
}
r1, l1, b1 = score_of(kb1)
print(f"KB1 manifest xau, runtime im: risk={r1} ({l1}) | static={b1['static_score']} dynamic={b1['dynamic_score']} eff={b1['static_effective']}")
assert b1["static_score"] > 0 and b1["dynamic_score"] == 0
assert r1 <= 35 and l1 in ("LOW", "MINIMAL"), \
    f"static MOT MINH (dynamic im) khong duoc flag MEDIUM+, duoc risk={r1} ({l1})"

# KB2: manifest SACH, runtime goi C2 tu SW => static ~0, dynamic cao  <-- DYNAMIC TOA SANG
kb2 = {
    "manifest": {"name": "y", "permissions": [], "host_permissions": []},
    "network_requests": [{"url": "https://evil-c2.xyz/beacon", "origin": "service_worker"}],
    "honeypot_exfil": False, "page_hang_count": 0,
}
r2, l2, b2 = score_of(kb2)
print(f"KB2 manifest sach, runtime C2: risk={r2} ({l2}) | static={b2['static_score']} dynamic={b2['dynamic_score']}")
assert b2["dynamic_score"] > 0, "dynamic phai bat duoc C2 du manifest sach"
assert b2["static_score"] == 0, "manifest sach thi static phai ~0"

# KB3: ca hai cung xau => corroboration
kb3 = {
    "manifest": {"name": "z", "permissions": ["cookies", "webRequest", "scripting", "tabs"],
                 "host_permissions": ["<all_urls>"]},
    "network_requests": [{"url": "https://evil-c2.xyz/x", "origin": "service_worker"}],
    "honeypot_exfil": True, "page_hang_count": 0,
}
r3, l3, b3 = score_of(kb3)
print(f"KB3 ca hai xau:              risk={r3} ({l3}) | static={b3['static_score']} dynamic={b3['dynamic_score']}")
assert r3 >= max(b3["static_score"], b3["dynamic_score"]), "corroboration phai >= max"

print("\n=== TEST UNSOLICITED TAB ===")
ev_tab = {
    "manifest": {"name": "t", "host_permissions": [], "permissions": []},
    "network_requests": [],
    "new_tabs": [
        {"url": "https://evil.site/pop", "phase": "load"},          # extension mo -> tinh
        {"url": "about:blank", "phase": "honeypot_pages"},          # harness -> bo
        {"url": "https://ad.site/x", "phase": "extension_pages"},   # harness phase -> bo
    ],
    "honeypot_exfil": False, "page_hang_count": 0,
}
res = detect_unsolicited_tabs(ev_tab)
assert res["has_unsolicited"] is True
assert res["count"] == 1, f"chi 1 tab extension, duoc {res['count']}"
assert res["unsolicited_tabs"][0]["url"] == "https://evil.site/pop"
print("PASS:", res)

print("\n=== TEST SCRIPT INJECTION ===")
ev_inj = {
    "manifest": {"name": "i", "host_permissions": [], "permissions": []},
    "network_requests": [],
    "dom_activity": [
        {"type": "node_injected", "tag": "SCRIPT",
         "src": "https://evil-cdn.xyz/x.js", "page_url": "http://localhost:8888/bank.html"},  # cross-origin -> tinh
        {"type": "node_injected", "tag": "FORM",
         "src": "http://localhost:8888/bank.html", "page_url": "http://localhost:8888/bank.html"},  # same-origin -> bo
        {"type": "node_injected", "tag": "SCRIPT",
         "src": "(inline)", "page_url": "http://localhost:8888/bank.html"},  # inline -> bo
        {"type": "mutation_summary", "injected_nodes": 5, "page_url": "x"},  # khong phai node_injected -> bo
    ],
    "honeypot_exfil": False, "page_hang_count": 0,
}
res = detect_script_injection(ev_inj)
assert res["has_injection"] is True
assert res["count"] == 1, f"chi 1 node cross-origin, duoc {res['count']}"
assert res["injected_nodes"][0]["host"] == "evil-cdn.xyz"
print("PASS:", res)

print("\n=== TEST SCRIPT INJECTION - TIER-2 welcome-tab discount ===")
# Mo phong dung pattern phat hien o grammarly/rakuten/honey: extension tu mo tab
# welcome toi domain ngoai (vendor.example), trang do tu tai script quang cao cua
# CHINH NO -> phai bi loai. Nhung injection tren trang honeypot (localhost) cua minh
# thi PHAI GIU NGUYEN, du cung mau.
ev_welcome = {
    "manifest": {"name": "w", "host_permissions": [], "permissions": []},
    "network_requests": [],
    "new_tabs": [
        {"url": "https://vendor.example/welcome?utm=chrome", "phase": "load"},
    ],
    "dom_activity": [
        # script cua CHINH trang welcome (vd GTM/ads tu vendor.example tu tai) -> LOAI
        {"type": "node_injected", "tag": "SCRIPT", "src": "https://ads.doubleclick.net/x.js",
         "page_url": "https://vendor.example/welcome?utm=chrome"},
        # extension van inject that tren trang honeypot cua minh -> GIU
        {"type": "node_injected", "tag": "SCRIPT", "src": "https://evil-cdn.xyz/y.js",
         "page_url": "http://localhost:8888/bank.html"},
    ],
    "honeypot_exfil": False, "page_hang_count": 0,
}
res = detect_script_injection(ev_welcome)
assert res["count"] == 1, f"chi giu 1 node (honeypot page), duoc {res['count']}: {res['injected_nodes']}"
assert res["injected_nodes"][0]["host"] == "evil-cdn.xyz", "phai giu injection tren honeypot page"
assert not any(n["host"] == "ads.doubleclick.net" for n in res["injected_nodes"]), \
    "script cua CHINH trang welcome-tab-vendor phai bi loai (Tier-2)"
print("PASS Tier-2 discount (welcome page bo, honeypot page giu):", res)

# Doi chung: neu host welcome-tab TRUNG voi target_matched_hosts (extension co ly do
# rieng nham vao domain do, vd rakuten.com vua la welcome-host vua la target host) ->
# KHONG duoc loai, phai giu nguyen (uu tien khong bo oan).
ev_welcome_target = dict(ev_welcome)
ev_welcome_target["target_matched_hosts"] = ["vendor.example"]
res2 = detect_script_injection(ev_welcome_target)
assert res2["count"] == 2, \
    f"host vua la welcome vua la target_matched -> KHONG duoc loai, duoc {res2['count']}"
print("PASS Tier-2 khong over-discount khi host trung target_matched:", res2)

print("\n=== TEST LOCAL HARVEST ===")
ev_harvest = {
    "manifest": {"name": "h", "host_permissions": [], "permissions": []},
    "network_requests": [],           # KHONG gui ra network
    "extension_storage": {
        "total_bytes": 200,
        "honeypot_hits": [
            {"ext_id": "abc", "file": "000003.log",
             "markers": ["HONEYPOT", "HONEYPOT-PASSWORD"], "snippet": "..."},
        ],
    },
    "honeypot_exfil": False,          # exfil = False (chua gui)
    "page_hang_count": 0,
}
res = detect_local_harvest(ev_harvest)
assert res["has_harvest"] is True, "phai phat hien harvest trong storage"
assert "HONEYPOT-PASSWORD" in res["harvested_markers"]
print("PASS:", res)

# Kiem tra: harvest bat duoc DU exfil=False (storage thay cai network bo sot)
rep = build_behavioral_report(ev_harvest)
score, level, bd = compute_risk_score(rep)
assert rep["indicators"]["local_harvest"] is True
assert rep["indicators"]["credential_exfil"] is False, "network khong thay gi"
assert bd["dynamic_score"] >= 30, "harvest phai dong gop diem dynamic"
print(f"score PASS: dynamic={bd['dynamic_score']} (harvest bat duoc du network im lang)")

print("\n=== TEST BEACONING ===")

def _req(url, t, phase="honeypot_pages", origin="service_worker"):
    return {"url": url, "host": url.split("/")[2], "t": t, "phase": phase, "origin": origin}

# (1) DUONG: SW beacon deu tuyet doi toi host KHONG khai bao => C2.
ev_beacon = {
    "manifest": {"name": "b", "host_permissions": [], "permissions": []},
    "network_requests": [
        _req("https://beacon-c2.evil-test/p", 1.0, "honeypot_pages"),
        _req("https://beacon-c2.evil-test/p", 3.0, "honeypot_pages"),
        _req("https://beacon-c2.evil-test/p", 5.0, "target_matched"),
        _req("https://beacon-c2.evil-test/p", 7.0, "extension_pages"),
        _req("https://beacon-c2.evil-test/p", 9.0, "delayed_observation"),
    ],
    "honeypot_exfil": False, "page_hang_count": 0,
}
res = detect_beaconing(ev_beacon)
assert res["has_beaconing"] is True
assert res["count"] == 1, f"chi 1 beacon, duoc {res['count']}"
b0 = res["beacons"][0]
assert b0["host"] == "beacon-c2.evil-test"
assert b0["count"] == 5, f"5 request, duoc {b0['count']}"
assert b0["cv"] == 0.0, f"deu tuyet doi cv phai 0.0, duoc {b0['cv']}"
assert b0["interval_mean_s"] == 2.0
assert b0["host_undeclared"] is True, "host la phai bi danh dau undeclared"
assert b0["spans_phases"] == 4, f"trai 4 phase, duoc {b0['spans_phases']}"
assert res["has_undeclared_beacon"] is True
print("PASS undeclared beacon:", b0)

rep = build_behavioral_report(ev_beacon)
_, _, bd = compute_risk_score(rep)
assert rep["indicators"]["beaconing"] is True
assert bd["dynamic_score"] == 50, f"undeclared_sw(30)+beacon(20)=50, duoc {bd['dynamic_score']}"
print(f"score PASS: dynamic={bd['dynamic_score']} (undeclared_sw 30 + beacon 20)")

# (2) AM - jitter: interval khong deu => cv > nguong => KHONG phai beacon.
ev_jitter = {
    "manifest": {"name": "j", "host_permissions": [], "permissions": []},
    "network_requests": [
        _req("https://jitter.evil-test/x", 1.0),
        _req("https://jitter.evil-test/x", 1.5),
        _req("https://jitter.evil-test/x", 4.0),
        _req("https://jitter.evil-test/x", 4.2),
        _req("https://jitter.evil-test/x", 9.0),
    ],
    "honeypot_exfil": False, "page_hang_count": 0,
}
assert detect_beaconing(ev_jitter)["has_beaconing"] is False, "traffic khong deu khong duoc tinh beacon"
print("PASS jitter -> khong beacon")

# (3) AM - it mau: 3 request (<MIN_BEACON_REQUESTS) => khong phan quyet.
ev_sparse = {
    "manifest": {"name": "s", "host_permissions": [], "permissions": []},
    "network_requests": [
        _req("https://sparse.evil-test/x", 2.0),
        _req("https://sparse.evil-test/x", 4.0),
        _req("https://sparse.evil-test/x", 6.0),
    ],
    "honeypot_exfil": False, "page_hang_count": 0,
}
assert detect_beaconing(ev_sparse)["has_beaconing"] is False, "3 request thi chua ket luan"
print("PASS sparse -> insufficient samples")

# (4) AM - tight loop: interval 0.1s < MIN_PERIOD_S du cv=0 => khong phai beacon.
ev_loop = {
    "manifest": {"name": "l", "host_permissions": [], "permissions": []},
    "network_requests": [_req("https://loop.evil-test/x", 1.0 + i * 0.1) for i in range(5)],
    "honeypot_exfil": False, "page_hang_count": 0,
}
assert detect_beaconing(ev_loop)["has_beaconing"] is False, "tight loop khong phai beacon"
print("PASS tight loop -> khong beacon")

# (5) AM ve DE DOA - beacon toi host DA KHAI BAO (telemetry lanh tinh): chi base(8).
ev_telemetry = {
    "manifest": {"name": "t", "host_permissions": ["https://api.myext.io/*"], "permissions": []},
    "network_requests": [
        _req("https://api.myext.io/ping", 1.0),
        _req("https://api.myext.io/ping", 3.0),
        _req("https://api.myext.io/ping", 5.0),
        _req("https://api.myext.io/ping", 7.0),
        _req("https://api.myext.io/ping", 9.0),
    ],
    "honeypot_exfil": False, "page_hang_count": 0,
}
res = detect_beaconing(ev_telemetry)
assert res["has_beaconing"] is True, "van phat hien nhip"
assert res["has_undeclared_beacon"] is False, "host da khai bao => khong phai C2"
assert res["beacons"][0]["host_undeclared"] is False
rep = build_behavioral_report(ev_telemetry)
_, _, bd = compute_risk_score(rep)
assert bd["dynamic_score"] == 8, f"beacon toi host khai bao chi base 8, duoc {bd['dynamic_score']}"
print(f"score PASS: telemetry host khai bao => dynamic={bd['dynamic_score']} (chi base, khong phat oan)")

print("\n=== TEST FINDINGS (MITRE A2) ===")

# Da tin hieu: credential_exfil(CRIT) + local_harvest(HIGH) + script_injection(HIGH)
# + unsolicited_tab(LOW,null). Kiem thu tu severity + ma dung + null cho tab.
ev_rich = {
    "manifest": {"name": "r", "host_permissions": [], "permissions": []},
    "network_requests": [],
    "dom_activity": [
        {"type": "node_injected", "tag": "SCRIPT",
         "src": "https://evil-cdn.xyz/x.js", "page_url": "http://localhost:8888/bank.html"},
    ],
    "extension_storage": {
        "total_bytes": 100,
        "honeypot_hits": [{"ext_id": "a", "file": "f",
                           "markers": ["HONEYPOT-PASSWORD"], "snippet": "x"}],
    },
    "new_tabs": [{"url": "https://ad.evil/pop", "phase": "load"}],
    "honeypot_exfil": True,
    "page_hang_count": 0,
}
rep = build_behavioral_report(ev_rich)
f = rep["findings"]
ids = [x["technique_id"] for x in f]
assert len(f) == 4, f"4 finding, duoc {len(f)}"
assert ids == ["T1041", "T1074.001", "T1059.007", None], f"sai thu tu/ma: {ids}"
assert f[0]["severity"] == "CRITICAL" and f[0]["tactic"] == "Exfiltration"
assert f[-1]["signal"] == "unsolicited_tab" and f[-1]["technique_id"] is None
assert "note" in f[-1], "tab abuse phai ghi chu khoang trong ATT&CK"
# findings ADDITIVE: khong doi score. dynamic=80+30+15+15=140 -> cap 100.
_, _, bd = compute_risk_score(rep)
assert bd["dynamic_score"] == 100, f"score tu tin hieu (khong tu findings): {bd['dynamic_score']}"
print("PASS rich findings:", [(x["signal"], x["technique_id"], x["severity"]) for x in f])

# Beacon undeclared => 2 finding cung MEDIUM: beaconing + undeclared_domain_contact.
rep_b = build_behavioral_report(ev_beacon)
bids = sorted(x["technique_id"] for x in rep_b["findings"])
assert bids == ["T1071", "T1071.001"], f"beacon findings sai: {bids}"
print("PASS beacon findings:", bids)

# Heuristic TINH (overprivileged...) KHONG sinh finding MITRE.
ev_static = {
    "manifest": {"name": "s", "host_permissions": ["<all_urls>"],
                 "permissions": ["tabs", "webRequest", "cookies", "scripting"]},
    "network_requests": [], "honeypot_exfil": False, "page_hang_count": 0,
}
rep_s = build_behavioral_report(ev_static)
assert rep_s["indicators"]["overprivileged"] is True, "van la overprivileged"
assert rep_s["findings"] == [], "heuristic tinh KHONG map MITRE"
print("PASS static-only => 0 findings (overprivileged khong phai technique)")

print("\n=== TEST UNDECLARED DOMAIN FILTERING (fix nhieu) ===")
ev_filter = {
    "manifest": {"name": "f", "host_permissions": [], "permissions": []},
    "network_requests": [
        {"url": "chrome-extension://ddbnhhjangoagiipejagamkakncbpipp/sw.js",
         "host": "ddbnhhjangoagiipejagamkakncbpipp", "origin": "service_worker"},
        {"url": "https://ddbnhhjangoagiipejagamkakncbpipp/x",
         "host": "ddbnhhjangoagiipejagamkakncbpipp", "origin": "service_worker"},
        {"url": "https://fonts.googleapis.com/css", "host": "fonts.googleapis.com", "origin": "page"},
        {"url": "https://challenges.cloudflare.com/turnstile", "host": "challenges.cloudflare.com", "origin": "page"},
        {"url": "https://mc.yandex.ru/watch", "host": "mc.yandex.ru", "origin": "page"},
        {"url": "https://cloudapi.stream/gate", "host": "cloudapi.stream", "origin": "service_worker"},
        {"url": "https://julia-info.kiev.ua/c", "host": "julia-info.kiev.ua", "origin": "page"},
    ],
    # GD3: julia-info.kiev.ua thuc ra do content script goi (isolated world) -> tinh.
    # Cac host page-initiated khac (fonts/cloudflare/yandex) khong co provenance => bi loc.
    "request_provenance": {"julia-info.kiev.ua": True},
    "honeypot_exfil": False, "page_hang_count": 0,
}
res = detect_undeclared_domains(ev_filter)
assert res["undeclared_total"] == ["cloudapi.stream", "julia-info.kiev.ua"], \
    f"chi 2 domain that duoc tinh, duoc {res['undeclared_total']}"
assert "ddbnhhjangoagiipejagamkakncbpipp" not in res["undeclared_total"], "extension-id phai bi loai"
assert "fonts.googleapis.com" not in res["undeclared_total"], "ha tang lanh phai bi loai"
print("PASS loc undeclared:", res["undeclared_total"])

print("\n=== TEST PHAN A: *.invalid (canary/test host) phai bi loai khoi undeclared ===")
# RFC 6761: .invalid khong bao gio resolve that => trong PRODUCTION chi co the la
# artifact cua canary/harness (vd sponsorblock bi leak canary-page.invalid, xem
# eval/_verify/benign_fp/verdict.md), khong bao gio la C2 that (C2 that phai resolve
# duoc). Test nay khac voi cac fixture ".evil-test" o tren (mo phong domain doc hai gia
# lap, khong lien quan RFC 6761).
ev_dotinvalid = {
    "manifest": {"name": "di", "host_permissions": [], "permissions": []},
    "network_requests": [
        {"url": "https://real-c2.evil-test/collect", "host": "real-c2.evil-test",
         "origin": "service_worker"},
    ],
    "request_provenance": {
        "canary-page.invalid": True,   # artifact canary/harness -> PHAI bi loai
        "some-leaked.invalid": True,   # bat ky host *.invalid nao -> PHAI bi loai
    },
    "honeypot_exfil": False, "page_hang_count": 0,
}
res = detect_undeclared_domains(ev_dotinvalid)
assert res["undeclared_total"] == ["real-c2.evil-test"], \
    f"chi domain that (khong .invalid) duoc tinh, duoc {res['undeclared_total']}"
assert "canary-page.invalid" not in res["undeclared_total"], "canary-page.invalid phai bi loai"
assert "some-leaked.invalid" not in res["undeclared_total"], "moi host *.invalid phai bi loai"
print("PASS loc *.invalid (Phan A):", res["undeclared_total"])

print("\n=== TEST PROVENANCE: chi tinh domain do EXTENSION goi (GD3) ===")
ev_prov = {
    "manifest": {"name": "p", "host_permissions": [], "permissions": []},
    "network_requests": [
        {"url": "https://c2-sw.evil.top/g", "host": "c2-sw.evil.top", "origin": "service_worker"},
    ],
    "request_provenance": {
        "c2-cs.evil.top": True,        # content script goi => TINH
        "tracker-of-page.com": False,  # trang goi => BO
        "fonts.googleapis.com": False, # trang goi (ha tang) => BO
    },
    "honeypot_exfil": False, "page_hang_count": 0,
}
res = detect_undeclared_domains(ev_prov)
assert res["undeclared_total"] == ["c2-cs.evil.top", "c2-sw.evil.top"], \
    f"chi SW + CS-ext duoc tinh, duoc {res['undeclared_total']}"
assert "tracker-of-page.com" not in res["undeclared_total"], "page-initiated phai bi bo"
print("PASS provenance:", res["undeclared_total"])

print("\n=== TEST WILDCARD PERMISSION PARSE (fix #3) ===")
# https://*.example.com/* phai duoc phan loai la wildcard subdomain, KHONG phai host
# gia "x.example.com" (bug cu: replace("*","x") bien *.example.com -> x.example.com,
# 1 host LITERAL sai hoan toan, khien api.example.com bi coi undeclared oan).
declared_wc = _manifest_declared_hosts({"host_permissions": ["https://*.example.com/*"]})
assert "example.com" in declared_wc["wildcards"], declared_wc
assert _is_declared_host("api.example.com", declared_wc) is True, \
    "subdomain cua wildcard phai duoc coi la DA KHAI BAO"
assert _is_declared_host("example.com", declared_wc) is True, \
    "chinh base domain cua wildcard cung phai duoc coi la DA KHAI BAO"
assert _is_declared_host("api.other.com", declared_wc) is False, \
    "host khong lien quan KHONG duoc coi la khai bao"
print("PASS wildcard *.example.com -> api.example.com/example.com declared, api.other.com khong")

# <all_urls> (hoac *://*/*) bi BO QUA hoan toan khi tinh declared (KHONG "mien tru" host
# nao). Do luong tren malware that: coi <all_urls> la declares_all=True khien 22/22 mau
# injector mat flag undeclared_domain_contact (recall loi 0.938->0.600) vi <all_urls> la
# pattern PHO BIEN NHAT trong malware (broad permission grab) - qua nguy hiem de "mien
# tru". Nen host van la undeclared binh thuong du manifest co <all_urls>.
declared_all = _manifest_declared_hosts({"host_permissions": ["<all_urls>"]})
assert declared_all["exact"] == set() and declared_all["wildcards"] == set(), declared_all
assert _is_declared_host("bat-ky-domain-nao.xyz", declared_all) is False, \
    "<all_urls> KHONG duoc mien tru host nao khoi undeclared (an toan hon declares_all)"
print("PASS <all_urls> -> khong dong gop declared nao, host van bi tinh undeclared binh thuong")

# KNOWN_INFRA_HOSTS phai so khop EXACT/SUFFIX, KHONG phai substring: domain gia mao
# chua ten ha tang lanh (vd google.com.attacker.tld) KHONG duoc coi la infra.
assert _is_known_infra_host("google.com") is True
assert _is_known_infra_host("accounts.google.com") is True, "subdomain that cua infra phai khop"
assert _is_known_infra_host("google.com.attacker.tld") is False, \
    "domain gia mao CHUA ten ha tang lanh KHONG duoc coi la infra (substring bug cu)"
print("PASS KNOWN_INFRA_HOSTS exact/suffix match, khong con substring bug")

# End-to-end: undeclared_domain khong con flag oan khi extension khai bao dung wildcard.
# Dung domain KHONG nam trong KNOWN_INFRA_HOSTS (myservice-abc.io) de cach ly dung tin
# hieu dang test (declared-wildcard), khong lan voi infra-allowlist.
ev_wc_declared = {
    "manifest": {"name": "wc", "host_permissions": ["https://*.myservice-abc.io/*"], "permissions": []},
    "network_requests": [
        {"url": "https://api.myservice-abc.io/data", "origin": "service_worker"},
    ],
    "honeypot_exfil": False, "page_hang_count": 0,
}
res = detect_undeclared_domains(ev_wc_declared)
assert res["has_undeclared"] is False, \
    f"host da khai bao qua wildcard KHONG duoc flag undeclared, duoc {res}"
print("PASS end-to-end: wildcard declared -> khong con undeclared oan")

print("\n=== TEST FIX #3: script_injection loai node = chinh extension-id (id-robust) ===")
OWN_ID = "ddbnhhjangoagiipejagamkakncbpipp"
OTHER_ID = "eiaeiblijfjekdanodkjadfinkhbfgcd"

ev_selfnode = {
    "manifest": {"name": "sn", "host_permissions": [], "permissions": []},
    "network_requests": [],
    "service_workers": [{"url": f"chrome-extension://{OWN_ID}/background.js"}],
    "dom_activity": [
        # node xuat hien TREN mot trang noi bo cua CHINH no (page_host=own_id) -> LOAI
        {"type": "node_injected", "tag": "SCRIPT", "src": "https://cdn.example-lib.io/x.js",
         "page_url": f"chrome-extension://{OWN_ID}/options.html"},
        # node co SRC la chinh id extension NHUNG page_url la TRANG THU BA that (khong
        # phai trang cua chinh no) -> VAN TINH (khong loai theo node_host - xem docstring
        # detect_script_injection: day chinh la pattern credential-phishing that phat hien
        # tren malware that, self-hosted payload chen vao trang nan nhan qua
        # web_accessible_resources, KHONG duoc mien tru chi vi src la "cua chinh minh")
        {"type": "node_injected", "tag": "SCRIPT",
         "src": f"chrome-extension://{OWN_ID}/js/bridge.js",
         "page_url": "https://tiktok.com/"},
        # node tu mot extension KHAC (id khac) -> VAN TINH (khong phai chinh no)
        {"type": "node_injected", "tag": "SCRIPT",
         "src": f"chrome-extension://{OTHER_ID}/evil.js",
         "page_url": "http://localhost:8888/fake_bank.html"},
        # node domain ngoai binh thuong -> VAN TINH (hanh vi that, khong lien quan fix #3)
        {"type": "node_injected", "tag": "SCRIPT", "src": "https://evil-cdn.xyz/y.js",
         "page_url": "http://localhost:8888/fake_bank.html"},
    ],
    "honeypot_exfil": False, "page_hang_count": 0,
}
res = detect_script_injection(ev_selfnode)
hosts = {n["host"] for n in res["injected_nodes"]}
assert "cdn.example-lib.io" not in hosts, \
    f"node tren TRANG noi bo cua chinh no phai bi loai (page_host=own_id), con: {hosts}"
assert OWN_ID in hosts, \
    ("node co src=chinh-id NHUNG chen vao TRANG THU BA that (khong phai own page) PHAI van "
     f"duoc tinh (pattern credential-phishing that, khong duoc mien tru theo node_host), duoc: {hosts}")
assert OTHER_ID in hosts, "node cua extension KHAC (id khac) van phai duoc tinh"
assert "evil-cdn.xyz" in hosts, "node domain ngoai binh thuong van phai duoc tinh"
assert res["count"] == 3, f"3 node con lai (own-id-tren-trang-la + id-khac + domain-ngoai), duoc {res['count']}: {hosts}"
print("PASS fix#3: CHI loai node tren TRANG noi bo cua chinh no (page_host), "
      "KHONG loai theo node_host (an toan hon, giu duoc pattern self-payload-vao-trang-la):", hosts)

print("\n=== TEST FIX #2: unsolicited_tab loai tab toi trang NOI BO cua chinh no (id-robust) ===")
ev_owntab = {
    "manifest": {"name": "ot", "host_permissions": [], "permissions": []},
    "network_requests": [],
    "service_workers": [{"url": f"chrome-extension://{OWN_ID}/background.js"}],
    "new_tabs": [
        # tab toi TRANG NOI BO cua chinh no (id THAT, tu service_workers) -> LOAI
        {"url": f"chrome-extension://{OWN_ID}/setup.html?from=install", "phase": "load"},
        # tab toi mot extension KHAC (id khac) -> VAN TINH (khong phai chinh no)
        {"url": f"chrome-extension://{OTHER_ID}/page.html", "phase": "load"},
        # tab toi domain BEN NGOAI (vendor.com) -> VAN TINH, KHONG name-match du "trong
        # giong" trang vendor chinh chu (nguyen tac cot loi cua fix #2: khong doan theo ten)
        {"url": "https://vendor-welcome.example/onboarding", "phase": "load"},
    ],
    "honeypot_exfil": False, "page_hang_count": 0,
}
res = detect_unsolicited_tabs(ev_owntab)
urls = {t["url"] for t in res["unsolicited_tabs"]}
assert not any(u.startswith(f"chrome-extension://{OWN_ID}/") for u in urls), \
    f"tab toi trang noi bo cua CHINH no phai bi loai, con: {urls}"
assert any(u.startswith(f"chrome-extension://{OTHER_ID}/") for u in urls), \
    "tab toi extension KHAC (id khac) van phai duoc tinh"
assert "https://vendor-welcome.example/onboarding" in urls, \
    "tab toi domain BEN NGOAI van phai duoc tinh (KHONG name-match, du 'trong giong' vendor)"
assert res["count"] == 2, f"chi 2 tab (id-khac + domain-ngoai) con lai, duoc {res['count']}: {urls}"
print("PASS fix#2: loai tab toi own-page, giu nguyen tab id-khac/domain-ngoai:", urls)

print("\n=== GUARD: malware mo tab external luc install (vd julia-info.kiev.ua) KHONG duoc mien tru ===")
# Mo phong dung pattern xac nhan tren dataset that: malware mo tab toi C2/tracking BEN
# NGOAI luc phase=load (giong het "hinh dang" voi welcome-tab benign - chi khac o ban chat
# domain). Fix #2 CHI dua vao id (chrome-extension://<own-id>), KHONG dua vao "domain co
# trong giong dich vu/vendor khong" -> tab nay PHAI van bi tinh la unsolicited.
ev_malware_beacon = {
    "manifest": {"name": "PageLockerClone", "host_permissions": [], "permissions": []},
    "network_requests": [],
    "service_workers": [{"url": f"chrome-extension://{OWN_ID}/background.js"}],
    "new_tabs": [
        {"url": f"https://julia-info.kiev.ua/install/{OWN_ID}", "phase": "load"},
    ],
    "honeypot_exfil": False, "page_hang_count": 0,
}
res = detect_beacon = detect_unsolicited_tabs(ev_malware_beacon)
assert res["has_unsolicited"] is True, \
    "GUARD FAIL: tab beacon external luc install cua malware bi mien tru oan - fix #2 sai, phai revert"
assert res["count"] == 1
print("PASS guard: tab external luc install (malware-like) VAN giu nguyen tin hieu:",
      res["unsolicited_tabs"])

print("\nTAT CA PASS")