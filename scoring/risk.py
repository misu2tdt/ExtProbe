"""
Risk scoring + behavioral report builder.
Signal thiet ke dua tren hanh vi THAT tu 4 malware sample (chien dich 108-extension):
  - Overprivilege, suspicious host, broad content-script scope, page hang, honeypot exfil

==================== LIMITATION DA BIET: self-domain / self-brand ====================
Nhieu FP benign (Dark Reader, Bitwarden, Grammarly, NordPass, LanguageTool, Ghostery,
Dashlane, Evernote, Momentum...) bi tinh `undeclared_domain_contact` vi service worker cua
chinh ho goi domain CUA CHINH VENDOR (vd api.bitwarden.com, api.dashlane.com,
cdn.ghostery.com) ma khong khai trong host_permissions; hoac bi tinh `unsolicited_tab` vi
tu mo tab welcome toi domain vendor BEN NGOAI (vd bitwarden.com/browser-start,
darkreader.org/help).

KHONG allowlist theo ten/domain (name-match) cho hai truong hop nay, du "ve mat ten" ro
rang la cua chinh publisher: discriminator dung phai la HANH VI (goi domain xau da biet /
redirect ra ngoai), KHONG phai ten/domain co GIONG brand hay khong — vi ten/domain la thu
ke tan cong TU DO CHON. Ke tan cong hoan toan co the dat ten extension + dang ky domain
TRUNG NHAU de "qua mat" bat ky allowlist so khop-ten nao (Wang et al. 2018: self-referential
domain khong phai tin hieu an toan mot minh; Palo Alto Networks VB2025, chien dich
108-extension: C2 domain la mot host RIENG, nhung khong co gi ngan ke tan cong chon domain
"giong ten" neu ho muon evade kieu allowlist nay).

Da xu ly duoc (an toan, ID-ROBUST, KHONG name-match) — xem _own_extension_ids():
  - Fix #3 (detect_script_injection): loai node ma PAGE_HOST (trang node xuat hien tren) la
    CHINH id extension dang chay (chrome-extension://<own-id>/..., id lay tu
    service_workers[].url — Chrome tu sinh/xac thuc id nay luc load, KHONG phai chuoi
    ten/domain co the tu chon => khong gia mao duoc). CHI loai theo PAGE_HOST, KHONG loai
    theo NODE_HOST (src): ban dau du dinh ca loai node ma NODE_HOST la id cua chinh no (vd
    "widget UI tu chen"), nhung do luong tren malware that cho thay day KHONG an toan - nhieu
    mau credential-phishing that CHEN CHINH payload dong goi (chrome-extension://<own-id>/
    js/bridge.js) vao TRANG THU BA that (tiktok.com, notion.so) kem <form> phishing - loai
    theo node_host se xoa oan tin hieu nay, khien recall tren cohort injector tut 0.97->0.58
    (23/60 mau). Da REVERT phan node_host, CHI giu phan page_host (xem chi tiet trong
    docstring detect_script_injection).
  - Fix #2 (detect_unsolicited_tabs): loai tab toi trang NOI BO cua chinh extension
    (chrome-extension://<own-id>/...), cung dua tren id that nhu tren. Khong co doi ung ac y
    tuong duong (mo tab toi trang cua CHINH MINH khong the "tan cong" trang khac), nen giu
    nguyen ca 2 dieu kien (node/page) an toan hon truong hop script_injection.

CHUA xu ly duoc (limitation, ghi nhan thay vi ep fix):
  - undeclared_domain_contact: SW goi domain CUA CHINH VENDOR (vd api.dashlane.com) VAN bi
    tinh la "domain la" — khong co allowlist self-brand (se la name-match, evadable).
  - unsolicited_tab toi trang BEN NGOAI (vd bitwarden.com/browser-start) VAN giu nguyen tin
    hieu — khong phan biet duoc an toan voi tab malware mo luc install toi domain ngoai. Da
    xac nhan qua chinh dataset dang dung: hang loat mau MALWARE mo
    https://julia-info.kiev.ua/install/<id> luc phase=load — CUNG PATTERN voi tab welcome
    benign (mo tab luc load, URL "trong nhu" mot trang dich vu), chi khac o domain do co
    phai C2/tracking doc hai hay khong — thu KHONG suy duoc tu URL/ten mot minh.

Da can nhac va TU CHOI: dung `events["navigations"]` (danh sach toan cuc phang, KHONG gan
timestamp/tab-id, gom chung frame cua MOI trang dang mo song song — honeypot, target_matched,
welcome tab...) de suy "tab co redirect ra ngoai sau khi mo hay khong". Kiem tra thuc te tren
9 mau FP: hau het URL cua welcome-tab KHONG xuat hien lai trong navigations (frame-navigate
khong bat duoc tab moi trong nhieu truong hop), va vi danh sach khong gan tab/frame nao voi
navigation nao nen KHONG THE ket luan chac chan "navigation ke tiep" thuoc ve dung tab welcome
hay mot trang khac dang mo song song. Lam theo huong nay se la DOAN, khong phai bang chung.

Future work (huong literature): domain-reputation signal (domain moi dang ky - NRD,
threat-intel blocklist nhu Palo Alto dung) de FLAG domain XAU da biet thay vi MIEN TRU domain
"trong giong" cua chinh minh — danh gia ban than domain (tuoi, reputation, ha tang lien ket)
thay vi danh gia "co giong ten extension khong", nen khong bi evade boi domain chon trung ten.

==================== LIMITATION KHAC: BRAND/TRADEMARK IMPERSONATION ====================
Phat hien qua verify 4 mau (`aoemlgniakbojcecmjefonjkgnceklpg`,
`fgbieegonkgdlkmeaapmkejdlfalonkb`, `hafhkoalnlpoifpidohfjlmeemfifndi`,
`ifhigdhiifbnjanhacoedbadhmlkjgae` - xem eval/_verify/fn/brand_impersonation_verdict.md):
extension GIA DANH thuong hieu AI dang hot (Grok/DeepSeek/Perplexity, cung mot "factory"
`*.easytool.dev`) nhung KHONG co content_scripts, KHONG host_permissions
(permissions=["storage","sidePanel"] ma thoi) - VE MAT KY THUAT khong the inject/doc bat
ky trang nao nguoi dung dang xem. Toan bo tin hieu dynamic quan sat duoc (script_injection,
unsolicited_tab, undeclared_domain) deu chi la hoat dong TRONG trang welcome NOI BO cua
chinh no (tai bundle JS tu backend rieng) - hoan toan "sach" theo nghia dynamic-behavior.

Day la LOAI HAI KHAC voi cac tin hieu hien co: gia danh TEN GOI/thuong hieu de danh lua
luot cai, khong phai injection/exfil/C2 runtime. Dynamic-behavior detector (file nay)
KHONG co - va SE KHONG BAO GIO co - tin hieu nao bat duoc loai nay, vi ban chat no khong
lien quan hanh vi luc chay: mot extension gia danh thuong hieu van co the hoan toan "sach"
ve mat dynamic (dung nhu 4 mau tren). Can THEM mot tin hieu METADATA rieng (so sanh
ten/description/icon voi danh sach thuong hieu pho bien + kiem tra publisher/domain co
thuoc chinh chu hay khong) - day la huong khac hoan toan voi 5 tin hieu dynamic hien co,
ghi nhan la future work, KHONG ep vao pham vi file nay.
========================================================================================

==================== FUTURE WORK: INLINE SCRIPT/IFRAME INJECTION (#2) ====================
`detect_script_injection` CHU Y bo qua node inline (`src == "(inline)"`, tuc SCRIPT/IFRAME
duoc them vao DOM qua `textContent`/`innerHTML` thay vi thuoc tinh `src`). Day la loai bo
CO CHU DICH, KHONG phai thieu sot vo tinh - chan doan (doc `sandbox/sensors/dom.py`, xem
docstring `_setup_dom_sensor` o do) cho thay CHUA THE bat inline injection mot cach an toan,
vi 3 ly do gop lai:

  (a) `dom.py` hien chi ghi METADATA (`tag`, `src="(inline)"`), KHONG ghi NOI DUNG script
      (`textContent`/`innerHTML`) - du co muon ap dung heuristic phan biet "inline dang ngo"
      (chua eval/atob/fetch/document.cookie) voi "inline binh thuong" (analytics/config inline
      RAT PHO BIEN tren trang web thuong) thi risk.py cung KHONG CO DU LIEU de lam.
  (b) dedup key trong MutationObserver la `tag + '|' + src` (`dom.py` dong ~41) - voi node
      inline, `src` LUON la chuoi hang `"(inline)"`, nen dedup key la HANG SO cho moi
      SCRIPT/IFRAME/FORM inline tren CUNG 1 trang - SAU node inline DAU TIEN, moi injection
      inline TIEP THEO (noi dung khac han) bi drop, khong bao gio duoc ghi lai.
  (c) Thieu DOM-channel provenance (tuong tu GD3 da lam cho network - phan biet request do
      extension hay do TRANG khoi tao): khong co co che phan biet inline script do CONTENT
      SCRIPT cua extension chen vs do CHINH TRANG tu viet (vd Google Analytics inline,
      config JSON inline trong <script> - cai nay RAT PHO BIEN tren web thuong). Neu bat MOI
      inline injection ma khong co provenance nay, FP se no (moi trang co GA/GTM/config inline
      deu bi flag).

De trien khai #2 AN TOAN can sua `dom.py` (khong chi risk.py): (1) capture noi dung inline
(truncate, vd 500 ky tu dau) qua `_report`, (2) doi dedup key sang hash(tag+content) thay vi
tag+src, (3) can nhac them provenance nguon (isolated-world content-script vs main-world
trang) tuong tu co che da co cho network (`request_provenance`). Day la sensor surgery sau
hon pham vi cac fix hien tai, chua lam trong cac dot nay - ghi nhan future work.
========================================================================================
"""
import statistics
from urllib.parse import parse_qsl, urlparse

DANGEROUS_PERMISSIONS = {
    "webRequest", "webRequestBlocking", "declarativeNetRequest",
    "downloads", "scripting", "management", "cookies", "history",
    "tabs", "clipboardRead", "clipboardWrite", "debugger", "proxy",
    "<all_urls>",
}

BROAD_MATCH_PATTERNS = {"<all_urls>", "http://*/*", "https://*/*", "*://*/*"}

KNOWN_INFRA_HOSTS = {
    # Google infra / analytics / ads / fonts
    "clients2.google.com", "www.google.com", "google.com", "accounts.google.com",
    "apis.google.com", "gstatic.com", "fonts.googleapis.com", "fonts.gstatic.com",
    "googleapis.com", "googletagmanager.com", "google-analytics.com",
    "analytics.google.com", "doubleclick.net", "googleadservices.com",
    "googlesyndication.com", "gvt1.com", "gvt2.com",
    # CDN / thu vien tinh (chi subdomain lanh, KHONG whitelist cloud chung chung)
    "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com", "fontawesome.com",
    "challenges.cloudflare.com", "cloudflareinsights.com",
    # Social pixel / analytics / error-reporting (dual-use nhe, nhung khong phan biet duoc)
    "connect.facebook.net", "www.facebook.com", "facebook.com", "fbcdn.net",
    "sentry.io", "bat.bing.com", "c.bing.com", "bing.com", "mc.yandex.ru",
    # Harness / local
    "example.com", "localhost", "127.0.0.1",
    # LUU Y: KHONG whitelist amazonaws (S3 hay bi dung exfil) hay cloudflare-workers
    # (hay bi dung C2). Chi liet ke subdomain chac chan lanh.
}

# ==================== TIN HIEU DYNAMIC ====================
# Host do HARNESS chu dong ghe (khong phai extension goi) => loai khoi undeclared.
# Nang cap sau: thay bang loc theo phase thay vi danh sach cung.
HARNESS_HOSTS = {
    "localhost", "127.0.0.1", "example.com", "www.example.com",
}

# Phase ma HARNESS chu dong mo tab => tab o day khong phai extension tu mo.
HARNESS_PHASES = {"honeypot_pages", "extension_pages"}


def _is_harness_host(host: str) -> bool:
    """True neu host la cua HARNESS/canary test, khong phai internet that.
    .invalid la TLD danh rieng cho test theo RFC 6761 (khong bao gio hop le tren mang
    that) - dung cho moi domain canary trong sandbox/canary/, sandbox/honey_pages/ (vd
    canary-page.invalid, canary-cs.invalid, canary-c2.invalid, canary-beacon.invalid...)
    ma khong can liet ke tung ten. Phat hien qua verify FP (sponsorblock bi leak
    canary-page.invalid vao undeclared_domain do HARNESS_HOSTS truoc day chi liet ke
    cung 4 host, thieu *.invalid)."""
    return bool(host) and (host in HARNESS_HOSTS or host.endswith(".invalid"))

# affiliate_hijack weight -- the ONLY place it is set. 40, decided by the author on
# 2026-10-02. Why 40:
#  - highly specific behaviour: rewriting a shopping link to add / replace an affiliate code
#    has no benign explanation without user action, and it fired on 0 clean samples,
#    coupon extensions included (eval/sensitivity/affiliate_weight.md);
#  - it is named and prohibited by the Chrome Web Store affiliate ads policy update (2025),
#    https://developer.chrome.com/blog/cws-policy-update-affiliate-ads-2025 -- affiliate
#    links, codes or cookies only with disclosure, user action and a direct user benefit;
#  - 40 = MEDIUM on its own (the flag threshold), not HIGH, keeping it below
#    credential_exfil (80) in the severity order.
AFFILIATE_HIJACK_WEIGHT = 40

# Trong so cham diem dynamic. Gom mot cho de tinh chinh o chuong thuc nghiem.
DYNAMIC_WEIGHTS = {
    "undeclared_domain_sw": 30,     # SW goi domain la => C2 ngam, nang hon
    "undeclared_domain_page": 15,   # page goi domain la => nhe hon
    "undeclared_per_extra": 5,      # moi domain la them
    "undeclared_cap": 40,           # tran cho nhom undeclared
    "unsolicited_tab": 15,
    "script_injection": 15,
    "local_harvest": 30,
    # Beaconing: nhip deu tu than YEU (telemetry lanh tinh cung beacon: GA/Sentry).
    # Chi leo thang khi beacon toi host KHONG khai bao => cung co gia thuyet C2.
    # Bang chung field: Palo Alto DeepSeek case - C2 la mot host RIENG, khong khai bao.
    "beaconing_base": 8,               # co nhip, toi host bat ky
    "beaconing_undeclared_bonus": 12,  # nhip toi host la => tong 20, duoi undeclared_sw(30)
    "affiliate_hijack": AFFILIATE_HIJACK_WEIGHT,
}

# Nguong beaconing. Don vi phan tich la INTERVAL (khoang cach 2 request lien tiep
# cung host), khong phai request => k request cho k-1 interval.
MIN_BEACON_REQUESTS = 4     # >=3 interval moi noi duoc ve do deu; san than trong
BEACON_CV_MAX = 0.25        # coefficient of variation toi da; tunable [0.15-0.35],
                            # KHONG claim toi uu. C2 that jitter ~10-20% => cv ~0.06-0.12.
MIN_PERIOD_S = 0.5          # mean interval duoi nguong nay = tight loop, khong phai beacon


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


# Scheme noi bo / khong phai lien lac mang ra ngoai => bo qua khi tinh domain.
_INTERNAL_SCHEMES = ("chrome-extension://", "chrome://", "moz-extension://",
                     "edge://", "about:", "data:", "blob:", "filesystem:")


def _is_v2_trace(events: dict) -> bool:
    """True for traces recorded by the v2 sandbox profile (events["startup"]["profile"]).
    Corpus traces and traces without a profile keep the paper's (legacy) behaviour."""
    profile = (events.get("startup") or {}).get("profile") or events.get("profile")
    return profile == "v2"


def legacy_view(events: dict) -> dict:
    """A shallow copy of a trace to score with the corpus (legacy) rules whatever profile
    recorded it: every v2-only rule (beaconing on extension-initiated requests only,
    affiliate_hijack) is off, exactly as for a corpus trace. Used by eval/rescore.py
    --scoring legacy to derive an A' run from v2 traces without re-running the sandbox."""
    ev = dict(events)
    ev["startup"] = dict(events.get("startup") or {}, profile=None,
                         recorded_profile=(events.get("startup") or {}).get("profile"),
                         scored_as="legacy")
    ev.pop("profile", None)
    return ev


def _is_real_domain(host: str) -> bool:
    """Domain thuc su ra ngoai: co dau '.' (loai extension-id 32 ky tu, localhost-like)."""
    return bool(host) and "." in host


def _own_extension_ids(events: dict) -> set:
    """ID (chrome-extension://<id>) cua CHINH extension dang duoc phan tich trong run nay.

    ID-ROBUST, KHONG the gia mao bang ten/domain: lay tu `service_workers[].url` — day la
    service worker THAT SU duoc Chrome khoi tao cho extension duy nhat dang load trong
    sandbox (moi run chi load 1 mau, thiet ke ephemeral sandbox - xem README.md), nen host cua URL
    nay LA id cua chinh no, khong phai suy doan/so khop ten. KHONG dung `extension_ids_seen`
    (rong hon, `sandbox/phases/actions.py` gom ca chrome-extension:// url thay tren TRANG
    - co the la resource cua extension builtin/khac khong lien quan, xac nhan qua verify:
    grammarly co 3 id trong extension_ids_seen nhung chi 1 id trung voi service_workers).
    """
    ids = set()
    for sw in events.get("service_workers", []):
        h = _host_of(sw.get("url", ""))
        if h:
            ids.add(h)
    return ids


def _is_known_infra_host(host: str) -> bool:
    """True neu host la ha tang biet lanh (KNOWN_INFRA_HOSTS), so khop EXACT hoac SUFFIX
    (host == infra hoac host.endswith("."+infra)). Truoc day dung substring ("in") khien
    "google.com" khop ca "google.com.attacker.tld" (allowlist bi qua mat bang domain gia
    mao chua ten ha tang lanh)."""
    return bool(host) and any(host == infra or host.endswith("." + infra)
                               for infra in KNOWN_INFRA_HOSTS)


def _extract_suspicious_hosts(manifest: dict) -> list:
    name = (manifest.get("name", "") or "").lower()
    desc = (manifest.get("description", "") or "").lower()

    hosts = set()
    for hp in manifest.get("host_permissions", []):
        h = _host_of(hp.replace("*://", "https://").replace("*", "x"))
        if h:
            hosts.add(h)
    for cs in manifest.get("content_scripts", []):
        for m in cs.get("matches", []):
            h = _host_of(m.replace("*://", "https://").replace("*", "x"))
            if h:
                hosts.add(h)

    suspicious = []
    for h in hosts:
        if _is_known_infra_host(h):
            continue
        if "amazon" in h or "google" in h or "facebook" in h:
            continue
        core = h.split(".")[-2] if "." in h else h
        if core and core not in name and core not in desc:
            suspicious.append(h)
    return sorted(set(suspicious))


ALL_HOSTS_PATTERNS = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}


def _classify_declared_pattern(pattern: str, wildcards: set, exact: set) -> None:
    """Phan loai 1 match pattern (host_permission hoac content_script match) vao
    declared_wildcards / declared_exact.

    Match-all pattern (<all_urls>, *://*/*...) bi BO QUA hoan toan (khong dong gop gi
    vao declared): neu coi no la "khai bao moi host" thi undeclared_domain_contact se
    KHONG BAO GIO bat duoc extension nao xin <all_urls> - ma day la pattern PHO BIEN
    NHAT trong malware that (broad permission grab). Do luong: 22/22 mau injector bi
    mat flag khi thu declares_all=True (recall lõi 0.938 -> 0.600) deu do <all_urls>,
    KHONG phai do wildcard subdomain - nen bo phuong an declares_all, chon huong an
    toan hon: <all_urls> khong "mien tru" host nao ca."""
    if pattern in ALL_HOSTS_PATTERNS:
        return
    # Bo scheme truoc khi xet wildcard subdomain, tranh "*://*.example.com/*"
    # bi hong khi replace "*://" -> "https://" (con lai "https:*.example.com").
    p = pattern.split("://", 1)[-1]
    host_part = p.split("/", 1)[0]
    if host_part.startswith("*."):
        base = host_part[2:].lower()
        if base and "*" not in base:
            wildcards.add(base)
            return
    h = _host_of(pattern.replace("*://", "https://").replace("*", "x"))
    if h:
        exact.add(h)


def _manifest_declared_hosts(manifest: dict) -> dict:
    """Host ma extension KHAI BAO trong manifest (host_permissions + content_scripts).
    Tra ve dict {exact, wildcards} thay vi set phang, vi wildcard (*.example.com) khong
    the quy ve 1 host cu the ma phai so khop theo suffix luc dung (xem _is_declared_host).
    Truoc day "*" bi thay bang ky tu "x" -> *.example.com thanh "x.example.com" (host
    GIA, sai hoan toan) khien api.example.com bi coi la undeclared oan du extension da
    khai bao dung wildcard cha no."""
    wildcards, exact = set(), set()
    for hp in manifest.get("host_permissions", []):
        _classify_declared_pattern(hp, wildcards, exact)
    for cs in manifest.get("content_scripts", []):
        for m in cs.get("matches", []):
            _classify_declared_pattern(m, wildcards, exact)
    return {"exact": exact, "wildcards": wildcards}


def _is_declared_host(host: str, declared: dict) -> bool:
    """True neu host duoc coi la DA KHAI BAO theo declared tra ve tu
    _manifest_declared_hosts: khop exact, hoac khop wildcard (host == base hoac la
    subdomain cua base). <all_urls>/match-all KHONG lam host nao duoc coi la declared
    (xem _classify_declared_pattern)."""
    if host in declared["exact"]:
        return True
    return any(host == base or host.endswith("." + base) for base in declared["wildcards"])


def detect_undeclared_domains(events: dict) -> dict:
    """
    TIN HIEU DYNAMIC: domain do EXTENSION goi luc chay ma KHONG khai bao trong manifest.
    Provenance (GD3): chi tinh host do extension khoi tao --
      - from_sw:  network_requests origin=service_worker
      - from_cs:  request_provenance ext_initiated=True (content script, isolated world)
    BO host chi do TRANG khoi tao (page-initiated) -- do la traffic cua trang extension
    mo, khong phai hanh vi extension (ref: web content provenance, Arshad et al. RAID'16).
    Do luong: 73% traffic malware / 92% benign la page-initiated => nhieu.
    """
    manifest = events.get("manifest", {})
    declared = _manifest_declared_hosts(manifest)

    def _keep(host):
        return (_is_real_domain(host) and not _is_harness_host(host)
                and not _is_declared_host(host, declared)
                and not _is_known_infra_host(host))

    # Nguon 1: service worker (tu network_requests)
    from_sw = set()
    for r in events.get("network_requests", []):
        url = r.get("url", "")
        if url.startswith(_INTERNAL_SCHEMES):
            continue
        if r.get("origin") != "service_worker":
            continue
        host = _host_of(url)
        if _keep(host):
            from_sw.add(host)

    # Nguon 2: content script (tu provenance, ext_initiated=True)
    from_cs = set()
    for host, ext in (events.get("request_provenance", {}) or {}).items():
        if ext and _keep(host):
            from_cs.add(host)

    from_ext = from_sw | from_cs
    return {
        "undeclared_from_sw": sorted(from_sw),
        "undeclared_from_cs": sorted(from_cs),
        "undeclared_total": sorted(from_ext),
        "has_undeclared": bool(from_ext),
    }


def detect_unsolicited_tabs(events: dict) -> dict:
    """
    TIN HIEU DYNAMIC: tab do EXTENSION tu mo (khong phai harness).
    Loc bang PHASE: harness chi mo tab trong honeypot_pages/extension_pages.

    FIX #2 (id-robust, KHONG name-match): bo qua tab neu URL la trang NOI BO cua CHINH
    extension (`chrome-extension://<own-id>/...`, id lay tu _own_extension_ids — id THAT
    cua run nay, khong doan theo ten/domain). Day la onboarding chuan (options/setup page
    tu mo trong tab thay vi popup) - KHONG phai "dieu huong nguoi dung ra ngoai".

    KHONG discount tab toi domain BEN NGOAI (vd vendor.com/welcome) du "trong nhu" trang
    vendor chinh chu: ten/domain co the gia mao (xem docstring _own_extension_ids va muc
    LIMITATION o cuoi file) - malware cung mo tab toi domain ngoai luc install (vd
    julia-info.kiev.ua/install/<id> - xac nhan qua dataset that, xem eval/results/summary.csv).
    Tab toi domain ngoai LUON duoc giu nguyen tin hieu, bat ke domain do "giong" gi.
    """
    own_ids = _own_extension_ids(events)
    ext_tabs = []
    for tab in events.get("new_tabs", []):
        phase = tab.get("phase")
        url = tab.get("url", "")
        if phase in HARNESS_PHASES:      # tab do harness mo
            continue
        if url in ("", "about:blank"):   # tab rong, bo qua (nang cap sau: theo redirect)
            continue
        if any(url.startswith(f"chrome-extension://{oid}/") for oid in own_ids):
            continue  # trang noi bo cua CHINH extension (id that, khong doan)
        ext_tabs.append({"url": url, "phase": phase})
    return {
        "unsolicited_tabs": ext_tabs,
        "count": len(ext_tabs),
        "has_unsolicited": len(ext_tabs) > 0,
    }


def _welcome_tab_external_hosts(events: dict) -> set:
    """
    TIER-2 discount cho script_injection: trang do CHINH EXTENSION tu mo lam tab
    welcome/onboarding (new_tabs, KHONG phai phase harness) toi mot domain BEN NGOAI
    that ra la TRANG CUA VENDOR (vd grammarly.com/extension-success tu tai GTM/Taboola/
    DoubleClick...) - script tren trang do la CUA TRANG, khong phai do extension chen.
    Phat hien qua verify FP: rakuten/grammarly/honey bi risk CRITICAL gan nhu hoan toan
    vi hang chuc script quang cao cua CHINH trang welcome rieng cua ho bi quy nham.

    CHI loai host nao CHAC CHAN la "trang vendor rieng, khong phai trang thu nghiem cua
    minh": phai la domain that (co dau '.'), KHONG phai harness (localhost/example.com/
    *.invalid), VA KHONG nam trong target_matched_hosts cua chinh mau (neu extension co
    content_scripts nham vao dung domain do vi mot ly do khac - vd rakuten.com vua la
    welcome-host vua la target_matched-host - thi KHONG loai, uu tien giu signal).
    Khong ro -> khong loai (tha giu signal that hon bo oan, dung nguyen tac cua task).
    """
    target_hosts = set(events.get("target_matched_hosts") or [])
    welcome_hosts = set()
    for tab in events.get("new_tabs", []):
        if tab.get("phase") in HARNESS_PHASES:
            continue  # harness tu mo tab nay, khong phai extension
        host = _host_of(tab.get("url", ""))
        if not _is_real_domain(host) or _is_harness_host(host):
            continue
        if host in target_hosts:
            continue  # dong thoi la trang target_matched cua chinh minh -> GIU, khong loai
        welcome_hosts.add(host)
    return welcome_hosts


def detect_script_injection(events: dict) -> dict:
    """
    TIN HIEU DYNAMIC: extension chen SCRIPT/IFRAME co src CROSS-ORIGIN vao trang.
    Heuristic: node co src tro toi domain KHAC voi trang dang xem => dang ngo.
    Node inline / same-origin => bo (khong phan biet duoc voi node cua chinh trang).
    Gioi han: khong bat duoc inline injection (can taint tracking nhu Arcanum).

    TIER-2 (xem _welcome_tab_external_hosts): bo qua node xuat hien tren trang welcome-
    tab-vendor ma CHINH EXTENSION tu mo - day la script CUA TRANG, khong phai extension
    chen. Neu extension inject script that tren mot trang khac (vd honeypot/target_matched
    hoac bat ky trang nao KHAC voi tab welcome), tin hieu van duoc giu nguyen ven.

    FIX #3 (id-robust, CHI theo PAGE, khong theo NODE): bo qua node neu page_host la CHINH
    trang noi bo cua extension (`chrome-extension://<own-id>/...`, id tu _own_extension_ids,
    id THAT lay tu service worker, khong doan theo ten/domain) - node xuat hien tren TRANG
    CUA CHINH NO (vd welcome.html/options.html tu tai script/iframe) khong phai hanh vi
    "chen vao trang nguoi dung dang xem".

    QUAN TRONG - CHI loai theo PAGE_HOST, KHONG loai theo NODE_HOST: ban dau du dinh loai
    ca node ma NODE_HOST (src) la id cua chinh extension (vd widget UI tu chen boi
    chinh extension) voi ly do "tai nguyen SELF". Do luong tren malware that phat hien day
    la SAI/khong an toan: nhieu mau credential-phishing that su CHEN CHINH payload dong goi
    cua no (vd chrome-extension://<own-id>/js/bridge.js) vao TRANG THU BA that (vd
    tiktok.com, notion.so) kem theo <form> gia dang nhap tro toi tiktok.com/auth,
    notion.so/auth — day CHINH LA ky thuat tan cong pho bien (dua payload qua
    web_accessible_resources), KHONG phai UI tu chen vo hai. Loai theo node_host lam
    recall tren cohort injector tut tu 0.97 xuong 0.58 (23/60 mau credential-phishing that
    bi mat tin hieu) - VI PHAM nguyen tac "recall loi khong duoc tut". Da REVERT phan nay,
    CHI giu lai loai theo PAGE_HOST (node xuat hien tren TRANG CUA CHINH NO) - truong hop
    nay khong co doi ung ac y tuong duong (mo trang noi bo cua chinh minh khong the "tan
    cong" ai khac), khac han voi chen script vao mot trang KHAC ma extension khong so huu.
    """
    welcome_hosts = _welcome_tab_external_hosts(events)
    own_ids = _own_extension_ids(events)
    injected = []
    for act in events.get("dom_activity", []):
        if act.get("type") != "node_injected":
            continue
        src = act.get("src", "")
        if not src or src == "(inline)":
            continue
        node_host = _host_of(src)
        if not node_host or _is_harness_host(node_host):
            continue
        page_host = _host_of(act.get("page_url", ""))
        if node_host == page_host:
            continue
        if page_host in own_ids:
            continue  # FIX #3: node xuat hien tren mot trang NOI BO cua chinh extension
        if page_host in welcome_hosts:
            continue  # Tier-2: script cua chinh trang welcome-tab-vendor, khong phai extension chen
        injected.append({"tag": act.get("tag"), "src": src, "host": node_host})
    return {
        "injected_nodes": injected,
        "count": len(injected),
        "has_injection": len(injected) > 0,
    }


def detect_local_harvest(events: dict) -> dict:
    """
    TIN HIEU DYNAMIC: honeypot bi cat vao storage cua extension (LevelDB).
    = "da thu thap du chua kip gui" (MITRE T1074.001 Local Data Staging).
    Bo tro cho credential_exfil (T1041, da gui ra) - hai giai doan kill-chain khac nhau.
    Storage doc theo ext_id => khong lan harness, khong can loc.
    """
    storage = events.get("extension_storage", {})
    hits = storage.get("honeypot_hits", [])
    markers = sorted({m for hit in hits for m in hit.get("markers", [])})
    return {
        "harvested_markers": markers,
        "hit_count": len(hits),
        "has_harvest": len(hits) > 0,
    }


def detect_beaconing(events: dict) -> dict:
    """
    TIN HIEU DYNAMIC: nhip request DEU DAN toi cung mot host (C2 beaconing).
    Khac 5 tin hieu kia o CHAT: day la temporal pattern, phai do bang metric
    (coefficient of variation) chu khong boolean/count don thuan.

    Do do: gom request CO timestamp 't' theo HOST (khong theo path - exfil hay ma
    hoa data vao path nen path bien thien, host on dinh). Tinh interval giua cac
    request lien tiep => cv = pstdev/mean. Beacon neu cv <= BEACON_CV_MAX.

    Dung 't' TUONG DOI (hieu giua 2 request) => mien nhiem voi warm-up jitter va
    do KHONG neo vao _t0.

    Which requests are grouped depends on the trace's sandbox profile:
      - corpus / no profile (legacy, the paper's numbers): PAGE + SW, i.e. every request,
        whoever started it.
      - v2: only requests the EXTENSION started, with exactly the provenance rule of
        detect_undeclared_domains: origin == "service_worker", or request_provenance[host]
        is True (content script). Reason: a page the extension merely opens can beacon on its
        own -- e.g. hiiildgldbpfbegcfgemoliikibfhaeh's welcome tab embeds an autoplaying,
        looping YouTube video whose player calls *.googlevideo.com every ~7 s, which fired
        beaconing although the extension sent none of it. On the corpus this rule would
        change 6 scores (none crosses 40) and move AUC by 0.001
        (eval/sensitivity/beaconing_provenance.md), so it is applied to v2 traces only and
        the corpus keeps the legacy behaviour.

    Cross-ref undeclared: gan host_undeclared cho moi beacon. Trong so leo thang
    theo co qua _dynamic_score, KHONG double-count o day.
    spans_phases: tinh & report (nen cho Ex-Ray L0 sau), chua dua vao trong so.
    """
    undeclared_hosts = set(detect_undeclared_domains(events)["undeclared_total"])
    extension_only = _is_v2_trace(events)
    provenance = events.get("request_provenance", {}) or {}

    by_host = {}
    for r in events.get("network_requests", []):
        url = r.get("url", "")
        if url.startswith(_INTERNAL_SCHEMES):
            continue
        t = r.get("t")
        host = r.get("host") or _host_of(url)
        if t is None or not _is_real_domain(host) or _is_harness_host(host):
            continue
        if extension_only and not (r.get("origin") == "service_worker" or provenance.get(host)):
            continue  # v2: page-initiated request (see docstring)
        by_host.setdefault(host, []).append(
            {"t": t, "phase": r.get("phase"), "origin": r.get("origin")})

    beacons = []
    for host, reqs in by_host.items():
        if len(reqs) < MIN_BEACON_REQUESTS:      # chua du mau => khong phan quyet
            continue
        ts = sorted(x["t"] for x in reqs)
        intervals = [round(ts[i + 1] - ts[i], 3) for i in range(len(ts) - 1)]
        mean = statistics.fmean(intervals)
        if mean < MIN_PERIOD_S:                  # tight loop, khong phai beacon
            continue
        cv = round(statistics.pstdev(intervals) / mean, 3) if mean > 0 else 0.0
        if cv > BEACON_CV_MAX:                    # khong du deu
            continue
        phases = sorted({x["phase"] for x in reqs if x["phase"]})
        origins = sorted({x["origin"] for x in reqs if x["origin"]})
        beacons.append({
            "host": host,
            "count": len(reqs),
            "interval_mean_s": round(mean, 3),
            "cv": cv,
            "jitter_pct": round(cv * 100, 1),
            "host_undeclared": host in undeclared_hosts,
            "spans_phases": len(phases),
            "phases": phases,
            "origins": origins,
        })

    # undeclared beacon len dau (dang ngo nhat), roi den do deu tang dan.
    beacons.sort(key=lambda b: (not b["host_undeclared"], b["cv"]))
    return {
        "beacons": beacons,
        "count": len(beacons),
        "has_beaconing": len(beacons) > 0,
        "has_undeclared_beacon": any(b["host_undeclared"] for b in beacons),
    }


# ---- affiliate_hijack (v2 traces only) ----
# Fixed lists, compared case-insensitively. Frozen: changing them changes the detector.
# Each parameter is kept only with an official network source (checked 2026-10-02); ones
# without a public official source were dropped: ascsubtag (Amazon), aff_short_key /
# aff_platform / aff_trace_key (AliExpress Portals help is behind a login), sscid (the
# ShareASale help article now redirects to the Awin home page).
AFFILIATE_PARAMS = {
    # Amazon Associates: https://affiliate-program.amazon.com/help/node/topic/GP38PJ6EUR6PFBEC
    "tag",
    # eBay Partner Network: https://developer.ebay.com/api-docs/buy/static/ref-epn-link.html
    "campid", "mkcid", "mkrid",
    # Rakuten Advertising (checked by hand by the author: the page, updated 2026-09-09, shows
    # ranMID, e.g. ...?utm_content=sytedemo&ranMID=13275, and click.linksynergy.com;
    # ranEAID / ranSiteID dropped -- not confirmed on an official page read directly):
    # https://pubhelp.rakutenadvertising.com/hc/en-us/articles/6890984802189-Tracking-Links-and-Landing-Page-URLs
    "ranmid",
    # Awin: https://help.awin.com/developers/docs/parameter-guidance
    "awc",
    # CJ Affiliate: https://docs.cj.com/docs/click-events
    "cjevent",
    # Impact: https://help.impact.com/brand/what-would-you-like-to-learn-about/platform-features/tracking/set-up-tracking/determine-your-programs-itp-compliance
    "irclickid",
}
AFFILIATE_REDIRECT_DOMAINS = (
    "s.click.aliexpress.com", "amzn.to", "rover.ebay.com", "click.linksynergy.com",
    "awin1.com", "shareasale.com", "anrdoezrs.net", "dpbolvw.net", "jdoqocy.com",
    "kqzyfj.com", "tkqlhce.com",
)


def _affiliate_detector_enabled(events: dict) -> bool:
    """Only for traces of the v2 sandbox profile (they carry the target-page probe and the
    sensors this detector was validated on). Corpus traces / traces without a profile:
    detector off, so the corpus scores are unchanged."""
    return _is_v2_trace(events)


def _query_items(url: str) -> list:
    try:
        return [(k.lower(), v) for k, v in parse_qsl(urlparse(url).query, keep_blank_values=True)]
    except Exception:
        return []


def detect_affiliate_hijack(events: dict) -> dict:
    """
    TIN HIEU DYNAMIC (v2 only): the extension changed a URL of a shopping page the sandbox
    served so that it earns affiliate commission.

    Definition (frozen; also in README):
    Fires when a URL to a shopping page the sandbox served (host in target_matched_visited /
    target_matched_hosts) is changed from the original in one of three ways:
      a) a parameter from AFFILIATE_PARAMS is added: it is in the observed URL but not in
         the URL the sandbox served for the same host + path;
      b) the VALUE of a parameter from AFFILIATE_PARAMS that the served URL already had is
         replaced (Chrome Web Store affiliate ads policy update 2025: extensions may not
         replace existing affiliate codes / attribution,
         https://developer.chrome.com/blog/cws-policy-update-affiliate-ads-2025);
      c) the URL is rewritten to / navigates through a host in AFFILIATE_REDIRECT_DOMAINS
         (or a subdomain of one) that the served page did not link to itself.
    Observed URLs: link hrefs on the test page after the extension ran and the URLs reached
    by following them (events["target_page_probe"]: hrefs / clicks), same-tab navigations
    and new tabs (events["navigations"], events["new_tabs"]), and network requests.
    Original URLs: target_page_probe[].hrefs_served (links exactly as served) plus the page
    URL https://<host>/ itself.
    Does not fire for a parameter kept with its original value, for utm_* or any parameter
    outside AFFILIATE_PARAMS.
    """
    out = {"enabled": _affiliate_detector_enabled(events), "hits": [], "count": 0,
           "has_affiliate_hijack": False}
    if not out["enabled"]:
        return out

    targets = set(events.get("target_matched_visited") or events.get("target_matched_hosts") or [])

    def on_target(host):
        return any(host == t or host.endswith("." + t) for t in targets)

    def is_redirect(host):
        return any(host == d or host.endswith("." + d) for d in AFFILIATE_REDIRECT_DOMAINS)

    served_values, served_urls = {}, set()   # (host, path) -> {param: {values}}
    probe = events.get("target_page_probe") or []
    originals = [f"https://{t}/" for t in targets]
    originals += [u for p in probe for u in (p.get("hrefs_served") or [])]
    for u in originals:
        served_urls.add(u)
        pu = urlparse(u)
        vals = served_values.setdefault(((pu.hostname or "").lower(), pu.path or "/"), {})
        for k, v in _query_items(u):
            vals.setdefault(k, set()).add(v)

    observed = []
    for p in probe:
        observed += [("dom", u) for u in p.get("hrefs") or []]
        observed += [("click", c.get("url_after_click", "")) for c in p.get("clicks") or []]
        if p.get("url_after_click"):
            observed.append(("click", p["url_after_click"]))
    observed += [("navigation", n.get("url", "")) for n in events.get("navigations") or []]
    observed += [("navigation", t.get("url", "")) for t in events.get("new_tabs") or []]
    observed += [("network", r.get("url", "")) for r in events.get("network_requests") or []]

    hits = {}
    for source, url in observed:
        if not url or url in served_urls:
            continue
        pu = urlparse(url)
        host = (pu.hostname or "").lower()
        if is_redirect(host):
            kind, params = "redirect_domain", []
        elif on_target(host):
            orig = served_values.get((host, pu.path or "/"), {})
            aff = [(k, v) for k, v in _query_items(url) if k in AFFILIATE_PARAMS]
            added = sorted({k for k, _ in aff if k not in orig})
            replaced = sorted({k for k, v in aff if k in orig and v not in orig[k]})
            if not (added or replaced):
                continue
            kind = "param_added" if added else "param_replaced"
            params = added + [k for k in replaced if k not in added]
        else:
            continue
        h = hits.setdefault(url[:300], {"url": url[:300], "kind": kind, "params": params,
                                         "sources": []})
        if source not in h["sources"]:
            h["sources"].append(source)

    out["hits"] = list(hits.values())[:20]
    out["count"] = len(hits)
    out["has_affiliate_hijack"] = bool(hits)
    return out


# ---- A2: MITRE ATT&CK mapping ----
# Industry-standard labels on OBSERVED signals only. Only techniques seen at run time are
# mapped; the static heuristics (overprivileged, has_suspicious_host, broad_injection,
# causes_page_hang) are deliberately absent -- they are risk attributes, not adversary
# techniques, so they are not forced onto one.
# severity = the technique's inherent severity if confirmed; a different axis from the
# scoring weight (which accounts for false positives). The two axes are independent.
SIGNAL_MITRE = {
    "credential_exfil": {
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration", "severity": "CRITICAL", "layer": "dynamic"},
    "local_harvest": {
        "technique_id": "T1074.001",
        "technique_name": "Local Data Staging",
        "tactic": "Collection", "severity": "HIGH", "layer": "dynamic"},
    "script_injection": {
        "technique_id": "T1059.007",
        "technique_name": "Command and Scripting Interpreter: JavaScript",
        "tactic": "Execution", "severity": "HIGH", "layer": "dynamic"},
    "beaconing": {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control", "severity": "MEDIUM", "layer": "dynamic"},
    "undeclared_domain_contact": {
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic": "Command and Control", "severity": "MEDIUM", "layer": "dynamic"},
    # Honestly unmapped: ATT&CK Enterprise has no technique for browser tab abuse
    # (ads / redirects). The finding is still emitted so the report shows the gap (a thesis
    # point) instead of hiding it or forcing a near-miss technique.
    "unsolicited_tab": {
        "technique_id": None,
        "technique_name": None,
        "tactic": "Impact", "severity": "LOW", "layer": "dynamic",
        "note": "Browser tab abuse: no matching ATT&CK Enterprise technique"},
    # No technique in this table fits: T1041/T1071/T1071.001 are about data leaving or C2
    # traffic, T1059.007 about running injected JS, T1074.001 about staging collected data;
    # affiliate hijacking is commission fraud by rewriting the user's shopping links. Left
    # unmapped rather than forced onto a near miss (same policy as unsolicited_tab).
    "affiliate_hijack": {
        "technique_id": None,
        "technique_name": None,
        "tactic": None, "severity": "MEDIUM", "layer": "dynamic",
        "note": "Affiliate link hijacking: no matching technique in the ATT&CK table used here"},
}

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def build_findings(report: dict) -> list:
    """
    MITRE labels on the OBSERVED signals that fired. Additive -- does NOT feed the score.
    Emitted only for indicators in SIGNAL_MITRE, sorted by severity (highest first).
    """
    ind = report.get("indicators", {})
    findings = [{"signal": sig, **meta}
                for sig, meta in SIGNAL_MITRE.items() if ind.get(sig)]
    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 9))
    return findings


def build_behavioral_report(events: dict) -> dict:
    manifest = events.get("manifest", {})
    requests = events.get("network_requests", [])

    ext_domains = set()
    for r in requests:
        h = _host_of(r.get("url", ""))
        if h and h not in ("localhost", "127.0.0.1"):
            ext_domains.add(h)

    perms = set(manifest.get("permissions", []))
    host_perms = manifest.get("host_permissions", [])
    dangerous_perms = sorted(perms & DANGEROUS_PERMISSIONS)
    if "<all_urls>" in host_perms:
        dangerous_perms.append("<all_urls>")

    broad_scope = False
    for cs in manifest.get("content_scripts", []):
        if any(m in BROAD_MATCH_PATTERNS for m in cs.get("matches", [])):
            broad_scope = True
            break

    suspicious_hosts = _extract_suspicious_hosts(manifest)
    undeclared = detect_undeclared_domains(events)
    unsolicited = detect_unsolicited_tabs(events)
    injection = detect_script_injection(events)
    harvest = detect_local_harvest(events)
    beaconing = detect_beaconing(events)
    affiliate = detect_affiliate_hijack(events)

    report = {
        "static": {
            "manifest_version": manifest.get("manifest_version"),
            "declared_permissions": sorted(perms),
            "dangerous_permissions": dangerous_perms,
            "dangerous_permission_count": len(dangerous_perms),
            "host_permission_count": len(host_perms),
            "broad_content_script_scope": broad_scope,
            "suspicious_hosts": suspicious_hosts,
        },
        "network": {
            "total_requests": len(requests),
            "external_domains": sorted(ext_domains),
            "external_domain_count": len(ext_domains),
        },
        "runtime": {
            "pages_visited": len(events.get("pages_visited", [])),
            "page_hang_count": events.get("page_hang_count", 0),
            "honeypot_exfil": events.get("honeypot_exfil", False),
            "console_log_count": len(events.get("console_logs", [])),
            "error_count": len(events.get("errors", [])),
        },
        "dynamic": {
            "undeclared_domains": undeclared,
            "unsolicited_tabs": unsolicited,
            "script_injection": injection,
            "local_harvest": harvest,
            "beaconing": beaconing,
            "affiliate_hijack": affiliate,
        },
        "indicators": {
            "credential_exfil": events.get("honeypot_exfil", False),
            "overprivileged": len(dangerous_perms) >= 4,
            "has_suspicious_host": len(suspicious_hosts) > 0,
            "broad_injection": broad_scope,
            "causes_page_hang": events.get("page_hang_count", 0) > 0,
            "undeclared_domain_contact": undeclared["has_undeclared"],
            "unsolicited_tab": unsolicited["has_unsolicited"],
            "script_injection": injection["has_injection"],
            "local_harvest": harvest["has_harvest"],
            "beaconing": beaconing["has_beaconing"],
            "affiliate_hijack": affiliate["has_affiliate_hijack"],
        },
    }
    report["findings"] = build_findings(report)
    return report


# Trong so corroboration khi ket hop static & dynamic.
# Chon trong khoang defensible [0.2, 0.4]: du de thuong "ca hai truc cung xau"
# nhung < 0.5 nen khong lan at truc chinh. Tham so tunable, kiem o chuong thuc nghiem.
CORROBORATION_COEF = 0.3

# Static la PRIOR yeu: capability (quyen rong) KHAC hanh vi doc hai. Cong cu lanh
# (password manager, ad blocker) cung xin quyen rong => static MOT MINH khong duoc
# tu day len MEDIUM+. Chi khi dynamic corroborate (quan sat duoc hanh vi thuc) static
# moi phat huy day du. Phat hien tu FP benign: Privacy Badger/Vimium/SingleFile co
# static cao nhung dynamic=0 => bi flag oan chi vi xin quyen rong.
STATIC_ALONE_CAP = 35       # tran cho static khi dynamic im (giu o muc LOW, khong flag)
DYNAMIC_PRESENT_MIN = 15    # nguong coi dynamic "co hanh vi quan sat duoc"

# Nguong muc do, neo theo dai CVSS v3 (x10 sang thang 100).
LEVEL_THRESHOLDS = [(90, "CRITICAL"), (70, "HIGH"), (40, "MEDIUM"), (15, "LOW")]


def _static_score(report: dict) -> int:
    """Diem chi tu tin hieu doc MANIFEST."""
    score = 0
    ind = report["indicators"]
    static = report["static"]
    if ind["has_suspicious_host"]:
        score += 25 + min(len(static["suspicious_hosts"]) * 5, 15)
    if ind["overprivileged"]:
        score += 20
    score += min(static["dangerous_permission_count"] * 3, 15)
    if ind["broad_injection"]:
        score += 15
    return min(score, 100)


def _dynamic_score(report: dict) -> int:
    """Diem chi tu tin hieu QUAN SAT LUC CHAY."""
    score = 0
    ind = report["indicators"]
    if ind["credential_exfil"]:
        score += 80
    if ind["causes_page_hang"]:
        score += 10

    dyn = report.get("dynamic", {}).get("undeclared_domains", {})
    sw_hosts = dyn.get("undeclared_from_sw", [])
    cs_hosts = dyn.get("undeclared_from_cs", [])
    if sw_hosts or cs_hosts:
        base = (DYNAMIC_WEIGHTS["undeclared_domain_sw"] if sw_hosts
                else DYNAMIC_WEIGHTS["undeclared_domain_page"])
        extra = (len(sw_hosts) + len(cs_hosts) - 1) * DYNAMIC_WEIGHTS["undeclared_per_extra"]
        score += min(base + max(0, extra), DYNAMIC_WEIGHTS["undeclared_cap"])

    if ind.get("unsolicited_tab"):
        score += DYNAMIC_WEIGHTS["unsolicited_tab"]

    if ind.get("script_injection"):
        score += DYNAMIC_WEIGHTS["script_injection"]

    if ind.get("local_harvest"):
        score += DYNAMIC_WEIGHTS["local_harvest"]

    # Beaconing: base yeu; leo thang khi nhip toi host KHONG khai bao (nghi C2).
    # Phan "host la" da duoc undeclared_domain cham rieng => o day chi cham phan NHIP.
    beac = report.get("dynamic", {}).get("beaconing", {})
    if beac.get("has_beaconing"):
        b = DYNAMIC_WEIGHTS["beaconing_base"]
        if beac.get("has_undeclared_beacon"):
            b += DYNAMIC_WEIGHTS["beaconing_undeclared_bonus"]
        score += b

    if ind.get("affiliate_hijack"):
        score += DYNAMIC_WEIGHTS["affiliate_hijack"]

    return min(score, 100)


def _level_of(score: int) -> str:
    for threshold, name in LEVEL_THRESHOLDS:
        if score >= threshold:
            return name
    return "MINIMAL"


def compute_risk_score(report: dict) -> tuple:
    """
    Tra ve (risk_score, level, breakdown).
    static va dynamic tinh RIENG (moi cai tu cat tran 100) roi ket hop:
      risk = max(s, d) + CORROBORATION_COEF * min(s, d)
    Bao cao GIU CA HAI so rieng => thay duoc dong gop cua dynamic (khong bi tran che).
    """
    s = _static_score(report)
    d = _dynamic_score(report)
    # Khi dynamic im (khong quan sat duoc hanh vi), chan static khong tu day len MEDIUM+.
    # Khi co dynamic corroborate, static phat huy day du.
    s_eff = min(s, STATIC_ALONE_CAP) if d < DYNAMIC_PRESENT_MIN else s
    risk = round(min(max(s_eff, d) + CORROBORATION_COEF * min(s_eff, d), 100))
    level = _level_of(risk)
    breakdown = {"static_score": s, "static_effective": s_eff,
                 "dynamic_score": d, "corroboration_coef": CORROBORATION_COEF}
    return risk, level, breakdown