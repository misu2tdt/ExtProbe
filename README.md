# ExtProbe

**ExtProbe: pre-installation behavior analysis of Chrome extensions with attributable runtime evidence.**

## What it does

- Runs a Manifest V3 extension in an instrumented, containerized Chrome and records what it actually does: network requests, DOM changes, opened tabs, API use.
- Attributes each event to the extension component that caused it (service worker, content script, extension page), so a report can say *who* did *what*, *where* and *how often*.
- Produces an explainable report (`report.html`, `report.json`) and a risk score from 0 to 100. Every point of the score comes from a named detector with a fixed weight.
- Optional probe mode (`--probe`) opens the extension's own pages and safely exercises their controls to elicit behavior that waits for a user action.

**The score prioritizes review; it is not a malware verdict.**

## Requirements

| | |
|---|---|
| Docker | Docker Engine or Docker Desktop. The sandbox runs inside a container with 3 GB of memory and a 512-process limit. |
| Python | 3.11 or newer. The CLI, scoring and report use only the standard library. |
| Disk / RAM | Each image is about 2.4 GB (v2, v3 and v3.1-probe share layers, so all three need less than 3 × 2.4 GB). One run is limited to 3 GB of memory, so Docker needs at least that much available. |
| OS tried | Windows 11 with Docker Desktop (Linux containers). The tests and `verify-freeze` also run on Ubuntu in CI; Docker runs on Linux and macOS have not been tried by the authors. |

## Quickstart (5 minutes)

```bash
git clone <REPO_URL> extprobe && cd extprobe

# 1. install the CLI (editable: it reads scoring/, report/ and sandbox/ from this checkout)
pip install -e .

# 2. get the sandbox image
<IMAGE_PULL_COMMAND>                  # a prebuilt image will be published later; until then, build it:
docker build -f docker/Dockerfile.base -t extprobe-sandbox:v2 sandbox/base
docker build -f docker/Dockerfile.v3   -t extprobe-sandbox:v3 sandbox/v3
#   probe mode also needs: docker build -f docker/Dockerfile.probe -t extprobe-sandbox:v3.1-probe sandbox/probe
#   (or all three: powershell -File docker/build.ps1)

# 3. analyze the demo extension
extprobe analyze examples/demo --out out/

# 4. open out/report.html in a browser
```

Terminal output:

```text
[extprobe] running extprobe-sandbox:v3 on demo ...
score:     100 / 100
level:     Flagged for review
detectors: credential_exfil, local_harvest, unsolicited_tab
report:    /home/you/extprobe/out/report.html
           /home/you/extprobe/out/report.json
The score prioritizes review; it is not a malware verdict.
```

`extprobe analyze` takes a `.crx` file or an unpacked extension directory (with `manifest.json`). It checks that Docker and the image are present and that the image id matches the one recorded in `docs/v3/IMAGE.md`. Local ids differ between builds; if your own build is fine, pass `--skip-image-check`.
Other commands: `extprobe verify-freeze`, `extprobe score-v3 --traces DIR`, `extprobe score-v31 --traces DIR`.

## Reading the report

**Level.** The score maps to one of three levels. The wording is deliberate: it says where to look, not what the extension is.

| score | level |
|---|---|
| 40 or more | Flagged for review |
| 15 to 39 | Review suggested |
| below 15 | No notable behavior observed |

**What the extension did.** One sentence per detector that fired: which component acted, what it did, to which destination, how many times. Example: *"The service worker sent a honeypot password to canary-c2.invalid (10 requests, plain text)."*

**Signals.** The detectors that fired and their weights; the others are listed in one line ("Not observed: …"). The weights add up to the score, capped at 100.

**Evidence.** For each detector that fired, the records behind the sentence. Repeated records are merged (×N, first and last time, phase). Data sent is cut to 120 characters; the script that started a request is shown when the trace has it (file, not line).

**Diagnostics** (collapsed). Sensor counts and run status. Use them to see whether the run itself worked (for example whether the service worker was hooked).

**Manifest risk** (last). A static score from the manifest, shown for information and not part of the score.

## Probe mode (`--probe`)

```bash
extprobe analyze path/to/extension --probe --out out/
```

Some behavior only appears after a user clicks something. The probe opens the pages the manifest declares (popup, options), lists their visible controls, and clicks them in priority order, filling forms with fake `PROBE` values: at most 15 clicks, 3 levels deep, about 30 seconds. It uses the image `extprobe-sandbox:v3.1-probe` and is scored with `score_v31`, which is `score_v3` applied to the run with the effects of the clicks themselves removed.

**Proxy safety.** An extension can ask Chrome to route traffic through a proxy. In probe mode that never takes effect: a managed Chrome policy (`ProxyMode=direct`, baked into the image) makes the setting uncontrollable, `chrome.proxy.settings` calls are recorded and neutralized in every extension context, and a monitor checks the effective configuration every 2 seconds. The report shows what the extension tried.

**Limits.** The probe clicks only controls that have a visible label in English. Controls without a label or with a non-English label are skipped and counted. It cannot log in, so behavior behind a sign-in is not reached.

## Safety

- Everything runs in a disposable container (`docker run --rm`, throwaway browser profile, dropped capabilities).
- **Analyze only extensions you are allowed to analyze.** Never open a suspicious `.crx` outside the sandbox and never sign in with real credentials while testing.
- The evaluation used real malicious extensions. They are not part of this repository.
- **Honeypot decoys are fake values.** The sandbox plants fake credentials so that an extension that reads and sends them is caught: environment variables such as `OPENAI_API_KEY=sk-HONEYPOT-...`, `GITHUB_TOKEN=ghp_HONEYPOT...`, `AWS_ACCESS_KEY_ID=AKIAHONEYPOT...`, a fake `~/.ssh/id_rsa` and `~/.aws/credentials` inside the container image (`docker/Dockerfile.base`, `sandbox/base/honeypot.py`), and fake pages (`sandbox/base/honey_pages/`). Every value contains the word `HONEYPOT` and works nowhere. They look like secrets on purpose, so secret scanners (for example GitHub secret scanning) may flag them: they are canaries, not leaked keys.
- See `docs/TROUBLESHOOTING.md`, in particular for Windows antivirus.

## Repository layout

```text
extprobe/        the CLI (analyze, verify-freeze, score-v3, score-v31)
sandbox/         container code: base (core), v3 (sensors and profile), probe (--probe)
docker/          Dockerfiles and build.ps1
scoring/         risk.py, v3/score_v3.py, probe/score_v31.py (the score)
report/          report_v3.py (HTML report)
examples/        canary/ (frozen verification sample), demo/ (sample for users)
tests/           unit tests (no Docker needed)
docs/            design, scoring rules, freeze, image records, troubleshooting
evaluation/      manifests, criteria, results and scripts behind the paper
PROVENANCE/      frozen-file list and criteria history; PROVENANCE.md explains them
```

## Reproducing the paper

See [REPRODUCE.md](REPRODUCE.md). The quick checks need no Docker: `python -m pytest -q`, `extprobe verify-freeze`, `python evaluation/v2/check_paper_numbers.py --precomputed`.

## Limitations

- A run is short (tens of seconds of extension activity). Behavior that needs more time, such as a delayed payload, may not appear.
- Behavior behind a login, a specific website, a purchase or other real interaction can stay hidden. The probe only clicks English-labeled controls on the extension's own pages.
- The score is a prioritization aid. In the evaluation it flags some benign extensions and misses some harmful ones (see `evaluation/v3/operating_points/results.md`); a human reads the evidence.
- Local Docker image ids are not reproducible between builds; `PROVENANCE.md` records the ids used for the evaluations.

## Citation, license, contact

Cite this software with [CITATION.cff](CITATION.cff) (GitHub's "Cite this repository"), or:

```bibtex
@inproceedings{extprobe,
  title     = {<PAPER_TITLE>},
  author    = {Tran, Duong Tien and Tran, Truong Tuan Phat and Vu, Duc Ly},
  booktitle = {Proc. IEEE International Conference on Software Analysis, Evolution and Reengineering (SANER), Tool Demonstrations},
  year      = {2027},
  note      = {Software: <REPO_URL>}
}
```

Licensed under the MIT License ([LICENSE](LICENSE)). Contact: <CONTACT_EMAIL>.
