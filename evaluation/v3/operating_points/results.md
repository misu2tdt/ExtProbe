# Operating points and performance (v2 and v3)

Recomputed from existing traces and scores only (`operating_points.py`): no sandbox run, no frozen file changed. Rates are `k/n = p% (Wilson 95 %)`; Wilson treats samples as independent, which the malware set is not (family F000 alone is 101 samples; see the cluster bootstrap below).

**The threshold 40 is the pre-registered one** (`FREEZE_v3.md`). The other thresholds are shown for reference only; nothing here changes the scoring or the threshold.

## Key figures at the pre-registered threshold 40

| | v2 | v3 |
|---|---|---|
| recall, dev malware (verified) | 187/283 = 66.1% (60.4%–71.3%) | 41/278 = 14.7% (11.1%–19.4%) |
| FPR, dev new benign | 127/248 = 51.2% (45.0%–57.4%) | 41/246 = 16.7% (12.5%–21.8%) |
| FPR, held-out test benign | 72/192 = 37.5% (31.0%–44.5%) | 17/192 = 8.9% (5.6%–13.7%) |

## 1a. Recall on the development malware

Positives: label verified `malicious` (the 313 malware minus the benign_mislabel / grey / unknown_verify of the label review) with a complete run in the profile; tiers from `eval/v3/labels/labels_tiers.csv`. n differs between v2 and v3 because the runs that failed differ.

| group | profile | ≥ 15 | ≥ 25 | ≥ 35 | ≥ 40 | ≥ 50 | ≥ 60 |
|---|---|---|---|---|---|---|---|
| all (n = 283) | v2 | 265/283 = 93.6% (90.2%–95.9%) | 224/283 = 79.2% (74.0%–83.5%) | 208/283 = 73.5% (68.1%–78.3%) | 187/283 = 66.1% (60.4%–71.3%) | 148/283 = 52.3% (46.5%–58.0%) | 79/283 = 27.9% (23.0%–33.4%) |
| all (n = 278) | v3 | 244/278 = 87.8% (83.4%–91.1%) | 80/278 = 28.8% (23.8%–34.4%) | 47/278 = 16.9% (13.0%–21.8%) | 41/278 = 14.7% (11.1%–19.4%) | 15/278 = 5.4% (3.3%–8.7%) | 9/278 = 3.2% (1.7%–6.0%) |
| T1 (n = 113) | v2 | 112/113 = 99.1% (95.2%–99.8%) | 97/113 = 85.8% (78.2%–91.1%) | 90/113 = 79.6% (71.3%–86.0%) | 79/113 = 69.9% (60.9%–77.6%) | 64/113 = 56.6% (47.4%–65.4%) | 34/113 = 30.1% (22.4%–39.1%) |
| T1 (n = 111) | v3 | 105/111 = 94.6% (88.7%–97.5%) | 26/111 = 23.4% (16.5%–32.1%) | 11/111 = 9.9% (5.6%–16.9%) | 9/111 = 8.1% (4.3%–14.7%) | 6/111 = 5.4% (2.5%–11.3%) | 5/111 = 4.5% (1.9%–10.1%) |
| T2 (n = 138) | v2 | 123/138 = 89.1% (82.8%–93.3%) | 99/138 = 71.7% (63.7%–78.6%) | 93/138 = 67.4% (59.2%–74.6%) | 86/138 = 62.3% (54.0%–70.0%) | 67/138 = 48.6% (40.4%–56.8%) | 33/138 = 23.9% (17.6%–31.7%) |
| T2 (n = 136) | v3 | 113/136 = 83.1% (75.9%–88.5%) | 38/136 = 27.9% (21.1%–36.0%) | 26/136 = 19.1% (13.4%–26.5%) | 24/136 = 17.6% (12.2%–24.9%) | 5/136 = 3.7% (1.6%–8.3%) | 1/136 = 0.7% (0.1%–4.0%) |
| T3 (n = 32) | v2 | 30/32 = 93.8% (79.9%–98.3%) | 28/32 = 87.5% (71.9%–95.0%) | 25/32 = 78.1% (61.2%–89.0%) | 22/32 = 68.8% (51.4%–82.0%) | 17/32 = 53.1% (36.4%–69.1%) | 12/32 = 37.5% (22.9%–54.7%) |
| T3 (n = 31) | v3 | 26/31 = 83.9% (67.4%–92.9%) | 16/31 = 51.6% (34.8%–68.0%) | 10/31 = 32.3% (18.6%–49.9%) | 8/31 = 25.8% (13.7%–43.2%) | 4/31 = 12.9% (5.1%–28.9%) | 3/31 = 9.7% (3.3%–24.9%) |
| all without F000 (n = 183) | v2 | 165/183 = 90.2% (85.0%–93.7%) | 135/183 = 73.8% (67.0%–79.6%) | 125/183 = 68.3% (61.2%–74.6%) | 109/183 = 59.6% (52.3%–66.4%) | 88/183 = 48.1% (41.0%–55.3%) | 42/183 = 23.0% (17.5%–29.6%) |
| all without F000 (n = 178) | v3 | 144/178 = 80.9% (74.5%–86.0%) | 68/178 = 38.2% (31.4%–45.5%) | 46/178 = 25.8% (20.0%–32.7%) | 41/178 = 23.0% (17.5%–29.7%) | 15/178 = 8.4% (5.2%–13.4%) | 9/178 = 5.1% (2.7%–9.3%) |
| T1 without F000 (n = 51) | v2 | 50/51 = 98.0% (89.7%–99.7%) | 44/51 = 86.3% (74.3%–93.2%) | 42/51 = 82.4% (69.7%–90.4%) | 34/51 = 66.7% (53.0%–78.0%) | 27/51 = 52.9% (39.5%–65.9%) | 15/51 = 29.4% (18.7%–43.0%) |
| T1 without F000 (n = 49) | v3 | 43/49 = 87.8% (75.8%–94.3%) | 15/49 = 30.6% (19.5%–44.5%) | 10/49 = 20.4% (11.5%–33.6%) | 9/49 = 18.4% (10.0%–31.4%) | 6/49 = 12.2% (5.7%–24.2%) | 5/49 = 10.2% (4.4%–21.8%) |

## 1b. False-positive rate

Development new benign: the 256 `benign_ext` extensions with the manifest label benign (grey excluded), complete runs. Test: the 192 benign extensions of the held-out set (8 grey excluded), run once on the frozen configuration.

| set | profile | ≥ 15 | ≥ 25 | ≥ 35 | ≥ 40 | ≥ 50 | ≥ 60 |
|---|---|---|---|---|---|---|---|
| dev new benign (n = 248) | v2 | 212/248 = 85.5% (80.6%–89.3%) | 188/248 = 75.8% (70.1%–80.7%) | 167/248 = 67.3% (61.3%–72.9%) | 127/248 = 51.2% (45.0%–57.4%) | 100/248 = 40.3% (34.4%–46.5%) | 74/248 = 29.8% (24.5%–35.8%) |
| dev new benign (n = 246) | v3 | 165/246 = 67.1% (61.0%–72.6%) | 84/246 = 34.1% (28.5%–40.3%) | 54/246 = 22.0% (17.2%–27.5%) | 41/246 = 16.7% (12.5%–21.8%) | 33/246 = 13.4% (9.7%–18.2%) | 23/246 = 9.3% (6.3%–13.6%) |
| test benign (n = 192) | v2 | 149/192 = 77.6% (71.2%–82.9%) | 120/192 = 62.5% (55.5%–69.0%) | 110/192 = 57.3% (50.2%–64.1%) | 72/192 = 37.5% (31.0%–44.5%) | 62/192 = 32.3% (26.1%–39.2%) | 39/192 = 20.3% (15.2%–26.6%) |
| test benign (n = 192) | v3 | 100/192 = 52.1% (45.0%–59.0%) | 46/192 = 24.0% (18.5%–30.5%) | 24/192 = 12.5% (8.5%–17.9%) | 17/192 = 8.9% (5.6%–13.7%) | 11/192 = 5.7% (3.2%–10.0%) | 9/192 = 4.7% (2.5%–8.7%) |

## 1c. v2 at the same test FPR as v3@40

v3 at 40 flags 17 of 192 test benign (8.9%). The smallest v2 threshold with a test FPR no higher than that is **81**. This is a threshold chosen on the test set to match v3, so it shows what v2 would need to give up to reach v3's false-positive rate; it is not a v2 operating point anyone fixed in advance.

| v2 threshold | test FPR | dev new benign FPR | recall all | recall T1 | recall T2 | recall T3 | recall without F000 |
|---|---|---|---|---|---|---|---|
| 79 | 20/192 = 10.4% (6.8%–15.5%) | 39/248 = 15.7% (11.7%–20.8%) | 15/283 = 5.3% (3.2%–8.6%) | 7/113 = 6.2% (3.0%–12.2%) | 3/138 = 2.2% (0.7%–6.2%) | 5/32 = 15.6% (6.9%–31.8%) | 15/183 = 8.2% (5.0%–13.1%) |
| 80 | 20/192 = 10.4% (6.8%–15.5%) | 37/248 = 14.9% (11.0%–19.9%) | 14/283 = 4.9% (3.0%–8.1%) | 7/113 = 6.2% (3.0%–12.2%) | 3/138 = 2.2% (0.7%–6.2%) | 4/32 = 12.5% (5.0%–28.1%) | 14/183 = 7.7% (4.6%–12.4%) |
| 81 **(matched)** | 16/192 = 8.3% (5.2%–13.1%) | 36/248 = 14.5% (10.7%–19.4%) | 13/283 = 4.6% (2.7%–7.7%) | 7/113 = 6.2% (3.0%–12.2%) | 2/138 = 1.4% (0.4%–5.1%) | 4/32 = 12.5% (5.0%–28.1%) | 13/183 = 7.1% (4.2%–11.8%) |
| 82 | 15/192 = 7.8% (4.8%–12.5%) | 35/248 = 14.1% (10.3%–19.0%) | 13/283 = 4.6% (2.7%–7.7%) | 7/113 = 6.2% (3.0%–12.2%) | 2/138 = 1.4% (0.4%–5.1%) | 4/32 = 12.5% (5.0%–28.1%) | 13/183 = 7.1% (4.2%–11.8%) |

At v2 threshold 81 the dev new benign FPR is 36/248 = 14.5% (10.7%–19.4%): the match holds on the test set only.

Bootstrap intervals (percentile, 10000 replicates, seed 20261010), recall on all verified malware:

| | recall | resampling samples | resampling families (cluster) | samples + test benign, threshold re-chosen |
|---|---|---|---|---|
| v2 at 81 (matched to v3@40) | 4.6% | 2.5%–7.4% | 1.7%–11.4% | 1.8%–9.9% (threshold 70–90) |
| v3 at 40 (pre-registered) | 14.7% | 10.8%–19.1% | 5.2%–30.1% | — |

The family-cluster interval is the honest one for the malware: the replicates draw whole families, so F000 (101 of 283 samples for v2) is either in or out. The last column adds the uncertainty of the 192 test benign extensions to the choice of the matched threshold.

## 2. The v3 false positives on the test set (17 of 192)

Extension names are replaced by FP-01…FP-17 (score order). Detectors are those of `score_v3.py` that fired; the cause is derived from the signals (host classes: first-party = a registrable domain of the extension's own tab or a token of its name; analytics SDK = well-known telemetry vendors).

| id | category | score (v2 / v3) | detectors | cause |
|---|---|---|---|---|
| FP-01 | productivity/workflow | 80 / 100 | history_exfil, undeclared_domain_contact, unsolicited_tab | visited URL of the harness pages sent by the service worker to host class: first-party domain; welcome-like extension-opened tab 0.333 s after install (1 domain) |
| FP-02 | productivity/developer | 81 / 100 | history_exfil, undeclared_domain_contact, unsolicited_tab, script_injection | visited URL + title of the harness pages sent by the service worker to host class: first-party domain; non-welcome extension-opened tab 0.158 s after install (1 domain); own UI script / iframe inserted into the page |
| FP-03 | lifestyle/travel | 100 / 100 | history_exfil, undeclared_domain_contact, unsolicited_tab, page_api_hooking, beaconing | visited URL of the harness pages sent by the service worker to host class: other third party; welcome-like extension-opened tab 0.307 s after install (1 domain); page fetch/xhr_open/xhr_send wrapped; periodic requests |
| FP-04 | productivity/education | 90 / 90 | history_exfil, undeclared_domain_contact | visited URL of the harness pages sent by the service worker to host class: first-party domain |
| FP-05 | productivity/education | 100 / 65 | undeclared_domain_contact, unsolicited_tab, script_injection, page_api_hooking | undeclared hosts: 2 first-party domain; welcome-like extension-opened tab 5.793 s after install (1 domain); own UI script / iframe inserted into the page; page fetch/xhr_open wrapped |
| FP-06 | productivity/communication | 66 / 65 | history_exfil, unsolicited_tab | visited URL of the harness pages sent by the content script to host class: first-party domain; non-welcome extension-opened tab 0.797 s after install (1 domain) |
| FP-07 | lifestyle/shopping | 62 / 65 | history_exfil, unsolicited_tab | visited URL of the harness pages sent by the content script to host class: first-party domain; welcome-like extension-opened tab 0.236 s after install (1 domain) |
| FP-08 | make_chrome_yours/privacy | 100 / 60 | undeclared_domain_contact, unsolicited_tab, page_api_hooking, causes_page_hang | undeclared hosts: 2 first-party domain; welcome-like extension-opened tab 0.306 s after install (1 domain); page fetch/xhr_open/xhr_send wrapped; page hang during the visit |
| FP-09 | productivity/workflow | 90 / 60 | undeclared_domain_contact, unsolicited_tab, page_api_hooking, beaconing | undeclared hosts: 2 third-party analytics / error SDK, 2 first-party domain; welcome-like extension-opened tab 6.527 s after install (1 domain); page xhr_open/xhr_send wrapped; periodic requests |
| FP-10 | productivity/communication | 78 / 50 | undeclared_domain_contact, unsolicited_tab, script_injection | undeclared hosts: 3 third-party analytics / error SDK; welcome-like extension-opened tab 8.693 s after install (1 domain); own UI script / iframe inserted into the page |
| FP-11 | lifestyle/social | 85 / 50 | undeclared_domain_contact, unsolicited_tab, script_injection | undeclared hosts: 2 first-party domain, 1 third-party analytics / error SDK, 1 CDN / static hosting; welcome-like extension-opened tab 0.454 s after install (1 domain); own UI script / iframe inserted into the page |
| FP-12 | make_chrome_yours/privacy | 98 / 45 | unsolicited_tab, script_injection, page_api_hooking | welcome-like extension-opened tab 1.821 s after install (1 domain); own UI script / iframe inserted into the page; page xhr_open/xhr_send wrapped |
| FP-13 | make_chrome_yours/privacy | 100 / 45 | undeclared_domain_contact, unsolicited_tab, script_injection | undeclared hosts: 1 CDN / static hosting; welcome-like extension-opened tab 1.03 s after install (1 domain); own UI script / iframe inserted into the page |
| FP-14 | productivity/communication | 60 / 45 | undeclared_domain_contact, unsolicited_tab, page_api_hooking | undeclared hosts: 1 third-party analytics / error SDK; non-welcome extension-opened tab 0.219 s after install (1 domain); page xhr_open/xhr_send wrapped |
| FP-15 | productivity/tools | 80 / 45 | undeclared_domain_contact, unsolicited_tab, page_api_hooking | undeclared hosts: 1 CDN / static hosting; non-welcome extension-opened tab 0.087 s after install (1 domain); page fetch/websocket/xhr_open/xhr_send wrapped |
| FP-16 | productivity/developer | 82 / 45 | undeclared_domain_contact, unsolicited_tab, beaconing | undeclared hosts: 4 other third party, 3 first-party domain; welcome-like extension-opened tab 0.209 s after install (2 domain); periodic requests |
| FP-17 | productivity/workflow | 74 / 40 | undeclared_domain_contact | persistent identifier (UUID in 2 phases) sent to host class: other third party |

Summary of the 17:

- visited URL / title sent to a backend (`history_exfil`, heavy): 6 (whether this is the extension's function or analytics is not decided here)
- persistent identifier (UUID seen in two phases) sent to an undeclared host (`undeclared_domain_contact`, heavy): 1
- only light signals adding up to ≥ 40 (extension-opened tab + undeclared hosts + own UI / page wrapper / periodic requests): 10

## 3. Performance

Run time = `duration_s` of `meta.json` (container wall time per extension, 2 workers in parallel, includes start-up and the 180 s timeout when hit). Trace size = `events.json`; the output folder adds `capture.pcap` and the screenshots. Counts are run statuses of the traces on disk.

| set | n | complete | partial | failed | time median / p90 / max (s) | events.json median / p90 / max | output folder median |
|---|---|---|---|---|---|---|---|
| dev, v3 image: benign | 30 | 30 | 0 | 0 | 48.2 / 60.2 / 70.7 | 253 kB / 3.1 MB / 6.8 MB | 2.3 MB |
| dev, v3 image: benign_ext | 256 | 254 | 2 | 0 | 48.5 / 59.9 / 88.1 | 206 kB / 1.0 MB / 20.0 MB | 1.7 MB |
| dev, v3 image: cws_benign_crx | 11 | 11 | 0 | 0 | 49.4 / 54.4 / 56.5 | 116 kB / 848 kB / 999 kB | 665 kB |
| dev, v3 image: malware | 313 | 306 | 0 | 7 | 40.1 / 58.6 / 66.3 | 234 kB / 575 kB / 2.0 MB | 1.9 MB |
| dev, v2 image (expanded run): benign | 30 | 30 | 0 | 0 | 48.5 / 59.1 / 71.1 | 62 kB / 277 kB / 734 kB | 1.2 MB |
| dev, v2 image (expanded run): benign_ext | 256 | 256 | 0 | 0 | 47.9 / 59 / 68.5 | 43 kB / 210 kB / 1.9 MB | 1000 kB |
| dev, v2 image (expanded run): cws_benign_crx | 11 | 11 | 0 | 0 | 47.4 / 49.9 / 56.5 | 28 kB / 91 kB / 174 kB | 452 kB |
| dev, v2 image (expanded run): malware | 313 | 312 | 0 | 1 | 40.5 / 58.7 / 101.7 | 38 kB / 148 kB / 674 kB | 797 kB |
| test benign, v3 | 200 | 200 | 0 | 0 | 48.9 / 60.2 / 72.8 | 98 kB / 700 kB / 4.9 MB | 919 kB |
| test benign, v2 | 200 | 200 | 0 | 0 | 48.8 / 58.9 / 64.3 | 28 kB / 162 kB / 782 kB | 524 kB |
| MADWeb V3 malware test, v3 | 517 | 415 | 0 | 102 | 24.8 / 40.7 / 59.2 | 21 kB / 42 kB / 21.1 MB | 384 kB |
| MADWeb V3 malware test, v2 | 517 | 415 | 0 | 102 | 24.8 / 101.5 / 102 | 7 kB / 13 kB / 15.0 MB | 326 kB |
