#!/bin/bash
set -e
cd /sandbox
xvfb-run -a --server-args="-screen 0 1280x720x24" \
    python3 /bench/run_benchmark.py --output /bench/output --timeout 180
