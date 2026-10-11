"""Unit tests for the honeypot marker matcher (sandbox/honeypot.py find_honeypot_any):
verbatim markers and one decoding layer (url / base64 / hex) in a request surface.

Run: python tests/sensors/test_honeypot_encoding.py   or   pytest tests/sensors
"""
import base64
import json
import sys
from pathlib import Path
from urllib.parse import quote

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "sandbox"))
from honeypot import find_honeypot_any  # noqa: E402

SECRET = "pass=HONEYPOT-PASSWORD-XYZ789&otp=HONEYPOT-OTP-1234"


def enc(kind):
    if kind == "url":
        return quote(SECRET, safe="")
    if kind == "base64":
        return base64.b64encode(SECRET.encode()).decode()
    if kind == "hex":
        return SECRET.encode().hex()
    return SECRET


def test_plain():
    assert find_honeypot_any("https://x.bench.test/c?" + SECRET)[1] == "plain"


def test_url_encoded():
    # Fully percent-encoded (every byte as %XX), so no marker is visible verbatim.
    full = "".join("%%%02X" % b for b in SECRET.encode())
    hits, encoding = find_honeypot_any("https://x.bench.test/c?d=" + full)
    assert encoding == "url" and "HONEYPOT-PASSWORD" in hits


def test_base64_in_body():
    hits, encoding = find_honeypot_any("https://x.bench.test/c " + json.dumps({"d": enc("base64")}))
    assert encoding == "base64" and "HONEYPOT-OTP" in hits


def test_hex_in_header():
    hits, encoding = find_honeypot_any('https://x.bench.test/c {"x-data": "%s"}' % enc("hex"))
    assert encoding == "hex" and "HONEYPOT" in hits


def test_negative_benign_payloads():
    benign = ["https://x.bench.test/c?q=hello%20world",
              json.dumps({"token": base64.b64encode(b"session-0123456789abcdef").decode()}),
              "deadbeefcafebabe0123456789abcdef"]
    for s in benign:
        assert find_honeypot_any(s) == ([], None), s


def test_detector_case_matches_sensor():
    """flag_exfil_base64.json must be what the sensor would record for its request."""
    case = json.loads((REPO / "tests/detectors/cases/flag_exfil_base64.json").read_text(encoding="utf-8"))
    r = case["events"]["network_requests"][0]
    hits, encoding = find_honeypot_any(r["url"] + " " + r["post_data"])
    assert encoding == case["events"]["honeypot_exfil_encoding"] == "base64"
    assert sorted(hits) == sorted(r["honeypot_markers"])


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} PASS")
    sys.exit(1 if failed else 0)
