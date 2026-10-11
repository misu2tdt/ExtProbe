# v3 dev audit: label check and missed malware

Criteria and sample were committed before any sample was reviewed (`AUDIT_CRITERIA.md`,
`sample.csv`). This file reports what was found. `sandbox_v3/`, the image, `score_v3.py` and the
labels are unchanged. The proposed labels live only in `audit.csv`.

Files:
- `audit.csv`: one row per reviewed sample, with the proposed label, FN group, confidence, code
  evidence (`file:line` + snippet), trace evidence and a note.
- `summary.md`: counts, Wilson intervals and extrapolation (`summarize.py`).
- `spotcheck.md`: 10 rows drawn with seed 7, for a manual check.
- `select.py`, `evidence.py`: sample selection, and evidence sheets. Packages were unpacked
  outside the repository.

Method: for every sample, the manifest, the v3 trace (extension-initiated requests with their
bodies and responses, tabs and redirect chains, `setUninstallURL`, network errors, created nodes,
API hooks) and the package code were read. The code was searched for capabilities (history,
cookies, remote code, tab control, DNR / search overrides, affiliate parameters, outbound
calls) and the relevant functions were then read. ExtProbe scores were not used as evidence.
Confidence is `low` when a large bundle (> 1 MB) could only be checked by capability search.

## 1. True positives (41)

| proposed label | n | what the detectors fired on |
|---|---|---|
| malicious-confirmed | **11** | 7 affiliate injection (`affiliate_hijack`, on the real link rewriting: 10Xprofit `tag=`, AliExpress `s.click` deep links), 3 history upload (`history_exfil`, on the real upload: Giant Coupons, an Auto-Refresh copy, a "SwitchyOmega" copy), 1 Urban VPN (data-collection framework in the code; the detectors fired only on its tab, hosts and API hooks, **not** on the collection, which did not run) |
| grey/PUP | **22** | 15 F001 AI-tool template network (`script_injection` on the vendor paywall iframe on the declared site, plus welcome tab and vendor host); 2 cashback (merchant URLs only); 3 URL-reputation / site-rank lookups (Avast, AVG, Trellian; the lookup is the product); Webcam Effects (strips CSP everywhere, no theft); a LinkedIn lead scraper |
| benign-looking | **8** | 4 OEM rebrands of one AI translator, Vidnoz recorder, the official Trust Wallet 2.77, Reader Mode (`local_harvest` = its own article cache), Browsec VPN |

So **10 of 41 TP fire on the malicious behaviour itself**. One more is a correct alert for
other reasons: Urban VPN is malicious, but the detectors fired on its tab, hosts and hooks. The
other 30 are malware-labelled samples whose code shows nothing harmful under the criteria;
the detectors fired on behaviour that really happened but is by design.

## 2. False negatives (40 of 237)

| group | n | samples |
|---|---|---|
| **A, silent** | 8 | 4 F000 with `loadInfo()`: the C2 picks a URL to open in a tab, and replied `{"success":true,"infoURL":""}` in the trace. Urban VPN `almalg` and Urban Ad Blocker `feflcg`: page-collection code present, upload gated by onboarding consent or remote config. SHEIN Search By Image: affiliate rewriting only for SHEIN product URLs containing `-p-`, absent from the harness product pages. Fake "Adobe Express": full-screen remote overlay only 60 s after install. |
| **B, seen but scored low** | 1 | Fake "HP Print Service Plugin" (`jnkmep`): the trace holds the remote config (A3 response body) of a "Verify you are human / Click here to download" banner pointing to a `.shop` domain. The banner is a `div` added with `insertAdjacentHTML`, so `script_injection` (SCRIPT / IFRAME) cannot see it; only `undeclared` (light) and `beaconing` fired. |
| **C, label probably wrong** | 31 | 16 benign-looking (downloaders for VK / TikTok / images, uptime checker, link-out "shell" apps whose welcome domains no longer resolve, Reddit summariser, password manager, Flappy Bird popup…); 15 grey/PUP (10 F000 games / apps of the `cloudapi.stream` network with paid top-ups and install / uninstall tracking only, 2 search-engine overrides that disclose the engine, 2 new-tab replacements, a self-declared keystroke recorder that stores locally) |
| D, run problem | 0 | — |

Where the malicious code sits and why the run missed it (group A):

| sample(s) | code | trigger not met in the run |
|---|---|---|
| F000 ×4 | `scripts/background.js:386` (and similar) `if (result?.success && result?.infoURL) chrome.tabs.create(...)` | C2 alive but returned an empty `infoURL` |
| `almalg` | `ad-blocker/content.js:1` `SendInitMessage`: page `innerHTML` + frame URL to the SW | collection enabled by downloaded configuration / consent |
| `feflcg` | `service_worker/index.js:35888` `SensitiveDataFilter`; analytics `enabled` only if `iaPolicy` agreed (`:37117`) | consent page never accepted |
| `mpgaod` | `content.js:2-30` wraps SHEIN links with `tr.tdwarp.com/...?ulp=` when `href` contains `-p-` | product page URLs of the harness use `/dp/…` |
| `pcdgkg` | `js/premium.js:5` `DEFAULT_DELAY_SECONDS = 60`, banner text / link from `config.json` | no harness page stays open 60 s after install |

For B (`jnkmep`), the feature that would separate it is the **content of the extension-fetched
response**: a remote JSON naming popular sites, a "verify you are human" text and a download
link to an unrelated `.shop` domain, combined with non-SCRIPT DOM insertion. None of the
generic trace features separates it. An install tab, `setUninstallURL` or an undeclared host
are each common in benign extensions (45 %, 50 % and 42 % of the new benign set,
`eval/v3/explore/tables.md`), and "a response body with URLs" occurs in 25 % of new benign.

## 3. Synthesis (details in `summary.md`)

| | count | 95 % CI | extrapolated to the 237 FN |
|---|---|---|---|
| A | 8 / 40 (20.0 %) | 10.5–34.8 % | ≈ 47 (25–82) |
| B | 1 / 40 (2.5 %) | 0.4–12.9 % | ≈ 6 (1–31) |
| C | 31 / 40 (77.5 %) | 62.5–87.7 % | ≈ 184 (148–208) |
| D | 0 / 40 | 0–8.8 % | ≈ 0 (0–21) |

TP confirmed malicious by code: **11 / 41**.

**Realistic Tier-2 recall ceiling, with the labels as used today (278 positives):**
- **≈ 17 % (15–26 %)**: today's 41 TP plus the B estimate. Today's recall is 14.7 %.
- **≈ 25 % (19–37 %)**: also counting the A cases whose C2 check-in is visible (F000), which a
  rule on C2 check-in could flag although the payload never ran.

**With the audited labels** (only malicious-confirmed / -likely as positives): about 64
code-malicious samples among the 278 (11 TP + ≈ 53 FN, 29–89). v3 finds ≈ 17 % of them, and Tier 2
could reach ≈ 26 % with B. The rest (group A) needs the sandbox to trigger the payload: a
longer dwell (> 60 s), clicking the onboarding consent, site-specific product URLs, and a C2
that answers. Those are Tier-1 / harness changes, not scoring.

## 4. Conclusion

- **Scoring is not the limit.** At most ~6 (up to ~31) of the 237 FN show their malicious
  behaviour in the trace. The realistic Tier-2 recall ceiling on the current labels is about
  17 %, and 25 % in the lenient reading.
- **The labels are the main limit.** About three quarters of the FN, and three quarters of the
  TP, are not malicious by code under the pre-registered criteria. They are grey/PUP (template
  and spam networks, install / uninstall tracking, disclosed search / new-tab overrides,
  paywalls, cashback) or ordinary tools. Store takedowns for policy reasons (spam, repetitive
  content, impersonation, deceptive install flows) appear to explain them. Recall measured
  against "removed from the store" is therefore not recall against malicious behaviour.
- **The payloads that were missed are mostly conditional.** C2 replies, consent, timers and
  site-specific triggers. The harness can address these; the scoring cannot.

Caveats: one reviewer, with capability search plus targeted reading. Two rows are `low`
confidence (bundles > 1 MB). The FN sample contains 14 samples of one family (F000), so the
intervals, which assume independent rows, are optimistic. The proposed labels are not
applied anywhere; any relabelling needs its own procedure (LABELING_CRITERIA.md).
