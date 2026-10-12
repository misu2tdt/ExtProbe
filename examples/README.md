# examples/

- `canary/` is the verification sample. It is frozen (listed in `PROVENANCE/frozen_files.tsv`; `python -m extprobe verify-freeze` checks it), and the
  evaluation results refer to it. Do not edit it.
- `demo/` is the sample for users who want to see ExtProbe work. It is a copy of `canary/` with only the `name` in `manifest.json` changed
  ("ExtProbe Demo Extension"), so it triggers the same detectors and gets the same score. Edit or extend it freely.

Try it (needs Docker and the `extprobe-sandbox:v3` image, see `docker/README.md`):

```bash
python -m extprobe analyze examples/demo --out demo-out     # report: demo-out/report.html, demo-out/report.json
```

Both extensions are test fixtures that behave badly on purpose, towards `.invalid` hosts only. Run them only through the sandbox.
