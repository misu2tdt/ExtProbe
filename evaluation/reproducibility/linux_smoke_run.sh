#!/usr/bin/env bash
# Linux smoke re-run: analyze the canary and the packages of a "bundle" with `extprobe analyze`, then write results.csv.
# Run it from the repository root, after `python docker/build.py` (image extprobe-local:v3):
#
#   bash evaluation/reproducibility/linux_smoke_run.sh [BUNDLE_DIR]          # default BUNDLE_DIR: linux_smoke_bundle
#
# BUNDLE_DIR holds expected.csv (the labels to run) and samples/<label>.crx. The packages are not part of this repository; the canary needs
# no file (examples/canary). See evaluation/reproducibility.md.
#
# Environment (all optional):
#   OUT=extprobe-out/linux_smoke   output folder: <OUT>/<label>/ (report, traces), <OUT>/<label>.log, <OUT>/results.csv.
#                                  Keep it inside the repository: with docker-in-docker (Codespaces) the container cannot see /tmp.
#   IMAGE=extprobe-local:v3        image to run          PYTHON=python        interpreter of the extprobe install
#   LABELS="U1 canary"             run only these labels (default: every label of expected.csv)
# results.csv: label,score,level,detectors,exit_code,seconds. A failed run has an empty score; the loop continues.

BUNDLE="${1:-linux_smoke_bundle}"
PY="${PYTHON:-python}"
OUT="${OUT:-extprobe-out/linux_smoke}"
IMAGE="${IMAGE:-extprobe-local:v3}"

if [ ! -f examples/canary/manifest.json ]; then
  echo "run this from the repository root (examples/canary not found)"
  exit 2
fi
if [ ! -f "$BUNDLE/expected.csv" ]; then
  echo "$BUNDLE/expected.csv not found: pass the bundle folder as the first argument"
  exit 2
fi
mkdir -p "$OUT"
LABELS="${LABELS:-$(tail -n +2 "$BUNDLE/expected.csv" | cut -d, -f1 | tr '\n' ' ')}"
echo "label,score,level,detectors,exit_code,seconds" > "$OUT/results.csv"

for label in $LABELS; do
  if [ "$label" = "canary" ]; then target="examples/canary"; else target="$BUNDLE/samples/$label.crx"; fi
  rm -rf "$OUT/$label"
  start=$(date +%s)
  "$PY" -m extprobe analyze "$target" --image "$IMAGE" --out "$OUT/$label" > "$OUT/$label.log" 2>&1
  code=$?
  secs=$(( $(date +%s) - start ))
  "$PY" - "$label" "$OUT/$label/report.json" "$code" "$secs" >> "$OUT/results.csv" <<'PYEOF'
import csv, json, sys
label, path, code, secs = sys.argv[1:5]
score = level = det = ""
try:
    r = json.load(open(path, encoding="utf-8"))
    score, level, det = r["score"], r["label"], ";".join(r["detectors_fired"])
except Exception:
    pass
csv.writer(sys.stdout, lineterminator="\n").writerow([label, score, level, det, code, secs])
PYEOF
  echo "== $label: exit $code, ${secs}s, $(grep -E '^score:' "$OUT/$label.log" 2>/dev/null || echo "no score (see $OUT/$label.log)")"
done

echo
echo "results: $OUT/results.csv"
echo "compare: python evaluation/reproducibility/linux_smoke_compare.py $BUNDLE/expected.csv $OUT/results.csv"
