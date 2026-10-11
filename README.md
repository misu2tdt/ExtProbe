# ExtProbe (public release - work in progress)

**Temporary README.** The full README and the CLI are written in the next step. This repository is the public release of ExtProbe
profile v3 and its user-action probe (`--probe`, image `extprobe-sandbox:v3.1-probe`): sandbox code, scoring, tests, the evaluation
records and their provenance.

Layout: `sandbox/` (container code: `base` = v2 core, `v3`, `probe`), `scoring/` (`risk.py`, `v3/score_v3.py`, `probe/score_v31.py`),
`report/`, `docker/` (Dockerfiles, build script), `examples/canary/`, `tests/`, `docs/`, `evaluation/` (manifests, criteria, results, records).
`PROVENANCE.md` lists when each criterion was fixed relative to each run and the image digests.

Quick checks (no Docker needed):

```bash
pip install -r requirements-dev.txt
python -m pytest -q
python -m extprobe verify-freeze                          # frozen files unchanged (sha256)
python evaluation/v2/check_paper_numbers.py --precomputed # paper numbers from the precomputed files
```

## Honeypot decoys (not real secrets)

The sandbox plants fake credentials so that an extension that reads and sends them is caught: environment variables such as
`OPENAI_API_KEY=sk-HONEYPOT-...`, `GITHUB_TOKEN=ghp_HONEYPOT...`, `AWS_ACCESS_KEY_ID=AKIAHONEYPOT...`, a fake `~/.ssh/id_rsa` and
`~/.aws/credentials` inside the container image (`docker/Dockerfile.base`, `sandbox/base/honeypot.py`), and fake pages
(`sandbox/base/honey_pages/`). Every value contains the word `HONEYPOT` and works nowhere. They look like secrets on purpose, so
secret scanners (for example GitHub secret scanning) may flag them: they are canaries, not leaked keys.

## Safety

The evaluation used real malicious extensions. Samples are not part of this repository. Run extensions only inside the sandbox container.

## Provenance and authorship

Per-extension data of the in-the-wild set A is not published (aggregate description and a SHA-256 of the id list are in
`evaluation/v3/in_the_wild/set_A_summary.md`; available on request).
