#!/bin/bash
set -e

CRX_PATH=${1:-/work/extension.crx}
OUTPUT_DIR=${2:-/work/output}
TIMEOUT=${3:-240}
# PHAI khop config.py:PROFILE_DIR (sensors/storage.py doc chrome.storage tu day).
PROFILE_DIR="/tmp/chrome-profile"

echo "[Sandbox] === Starting analysis (profile v3.1-probe) ==="
echo "[Sandbox] CRX: $CRX_PATH"
echo "[Sandbox] Output: $OUTPUT_DIR"
echo "[Sandbox] Timeout: ${TIMEOUT}s"

mkdir -p "$OUTPUT_DIR"
# Don output cu (tranh nham lan file tu lan chay truoc)
rm -rf "$OUTPUT_DIR"/* 2>/dev/null || true

# Don profile Chromium cu (BAT BUOC): sensors/storage.py doc chrome.storage tu
# PROFILE_DIR SAU khi browser dong. Neu container bi tai su dung cho >1 lan chay
# (vd debug thu cong, khong phai --rm production path), khong xoa se khien cam
# bien storage doc nham du lieu cua MAU TRUOC => ket luan sai.
rm -rf "${PROFILE_DIR:?}"/* 2>/dev/null || true

# Serve honey pages qua HTTP server local (port 8888)
python3 -m http.server 8888 --directory /sandbox/honey_pages > /dev/null 2>&1 &
HTTP_PID=$!
echo "[Sandbox] Honey page server started (PID=$HTTP_PID)"
sleep 1

# Bat dau tcpdump (chay nen)
tcpdump -i any -w "$OUTPUT_DIR/capture.pcap" -U > /dev/null 2>&1 &
TCPDUMP_PID=$!
echo "[Sandbox] tcpdump started (PID=$TCPDUMP_PID)"
sleep 1

# v3.1-probe: the managed Chrome policy (ProxyMode=direct) must be in place before Chrome starts.
POLICY=/etc/opt/chrome_for_testing/policies/managed/extprobe_proxy.json
if [ -f "$POLICY" ]; then
    echo "[Sandbox] proxy policy: $(tr -d ' \n' < "$POLICY")"
else
    echo "[Sandbox] proxy policy MISSING"
fi

# Xvfb + Python + Chromium chay bang user thuong (mac dinh pwuser, khong capability);
# chi tcpdump va http server o tren chay root. SANDBOX_USER=root de tat.
RUN_AS="${SANDBOX_USER:-pwuser}"
DROP=""
if [ "$(id -u)" = "0" ] && [ "$RUN_AS" != "root" ] && id "$RUN_AS" >/dev/null 2>&1; then
    chmod 0777 "$OUTPUT_DIR"
    [ -d "$OUTPUT_DIR/extension_unpacked" ] && chmod 1777 "$OUTPUT_DIR/extension_unpacked"
    DROP="setpriv --reuid=$RUN_AS --regid=$RUN_AS --init-groups --inh-caps=-all env HOME=/home/$RUN_AS"
    echo "[Sandbox] Analysis runs as $RUN_AS"
fi

# Chay phan tich trong Xvfb (man hinh ao). timeout = luoi an toan cuoi cung.
set +e
$DROP xvfb-run -a --server-args="-screen 0 1280x720x24" \
    timeout "$TIMEOUT" python3 /sandbox/v31/analyze_v31.py \
        --crx "$CRX_PATH" \
        --output "$OUTPUT_DIR" \
        --timeout "$TIMEOUT"
ANALYZE_EXIT=$?
set -e

echo "[Sandbox] Analysis exit code: $ANALYZE_EXIT"

# Dung tcpdump bang SIGINT roi wait => pcap flush day du (tranh cat giua buffer)
kill -INT $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true
kill $HTTP_PID 2>/dev/null || true

echo "[Sandbox] === Done ==="
ls -la "$OUTPUT_DIR"