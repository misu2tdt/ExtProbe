# Detector-test fixtures

Real sandbox traces (events.json) used by `tests/detectors/run.py --matrix` for the
canary and provenance columns of `../matrix.md`. Both come from extensions written for
this project (no third-party samples); every host they contact is a test host
(`*.invalid` / `*.bench`), never the real Internet.

| file | produced by | extension |
|---|---|---|
| canary_corpus.json | `sandbox/smoke_test.py` (sensor smoke test, 13/13 sensor checks + lifecycle timeout check PASS); copy of `/tmp/smoke_out/events.json` | `sandbox/canary/` |
| provenance_corpus.json | `eval/provenance_benchmark/run_benchmark.py --timeout 180` (9 requests, 4 provenance hosts); `score.py` on it: TP 4 / FP 0 / FN 0 / TN 1, results identical to the committed `results.csv` / `summary.json` | `eval/provenance_benchmark/extension/` |

Provenance (both files):

- date: 2026-10-01
- repo commit: f335ca0 (saner-prep)
- image: `extanalyze-sandbox:corpus`, id
  `sha256:ff794544d040dabcca70e372597d6c670ef46f08e464dfd2a6d05633f5d705ab`
  (sandbox/Dockerfile, digest-pinned base `mcr.microsoft.com/playwright/python:v1.40.0-jammy`)
- browser: Playwright 1.40.0 / Chromium 120.0.6099.28, profile `corpus`, Chromium sandbox off

SHA-256:

```
f0f1d50903a231568006b1f8d4e6111b27081a09da7f72feeff0a10fc9c4f155  canary_corpus.json
9f22f6bcc29440ba1885c23157bd3fcc761ee0e49da31708204fb0b43c6888b6  provenance_corpus.json
```

Regenerate:

```
# canary
docker run --rm --shm-size=2g --entrypoint sh -v "<dir>:/out" extanalyze-sandbox:corpus \
  -c "python3 /sandbox/smoke_test.py; cp /tmp/smoke_out/events.json /out/events.json"
# provenance
docker run --rm --shm-size=2g --entrypoint bash -v "<repo>/eval/provenance_benchmark:/bench:ro" \
  -v "<dir>:/out" extanalyze-sandbox:corpus -c "cd /sandbox && xvfb-run -a \
  --server-args='-screen 0 1280x720x24' python3 /bench/run_benchmark.py --output /out --timeout 180"
```

Timestamps and request ids differ between runs; the detector verdicts should not.

> Note: `sandbox/smoke_test.py`, `sandbox/canary/`, `eval/...` and the `/tmp/smoke_out/...` paths named here refer to the development environment. They are not included in this release; the canary extension is `examples/canary/` (see the path map in `PROVENANCE.md`).
