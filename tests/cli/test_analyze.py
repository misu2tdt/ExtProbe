"""Tests of `extprobe analyze`: arguments, missing Docker / image, level text, input packing, report wording. No Docker needed."""
import json
import struct
import subprocess
import zipfile
from pathlib import Path

import pytest

from extprobe import analyze as A
from extprobe.__main__ import main as cli_main

ROOT = Path(__file__).resolve().parents[2]


def _proc(code=0, out="", err=""):
    return subprocess.CompletedProcess([], code, out, err)


# ---- arguments ----
def test_parse_defaults_and_flags():
    a = A.parse(["x.crx"])
    assert (a.target, a.probe, a.out, a.timeout, a.skip_image_check) == ("x.crx", False, "extprobe-out", None, False)
    a = A.parse(["d", "--probe", "--out", "o", "--timeout", "5", "--skip-image-check"])
    assert (a.probe, a.out, a.timeout, a.skip_image_check) == (True, "o", 5, True)


def test_target_is_required():
    with pytest.raises(SystemExit) as e:
        A.parse([])
    assert e.value.code == 2


def test_cli_dispatches_analyze_and_help_lists_it(capsys):
    assert cli_main(["--help"]) == 0
    assert "analyze TARGET" in capsys.readouterr().out


# ---- level text ----
@pytest.mark.parametrize("score,label", [
    (0, "No notable behavior observed"), (14, "No notable behavior observed"),
    (15, "Review suggested"), (39, "Review suggested"),
    (40, "Flagged for review"), (100, "Flagged for review")])
def test_label_mapping(score, label):
    assert A.label_of(score) == label


def test_threshold_matches_scoring():
    import score_v3 as S
    assert S.FLAG_THRESHOLD == 40 and A.label_of(S.FLAG_THRESHOLD) == "Flagged for review"


# ---- Docker missing / image missing ----
def test_docker_not_installed(monkeypatch, capsys):
    def boom(*a, **k):
        raise FileNotFoundError
    monkeypatch.setattr(subprocess, "run", boom)
    assert A.main(["examples/canary"]) == A.EXIT_ENV
    assert "Docker was not found" in capsys.readouterr().err


def test_docker_daemon_down(monkeypatch, capsys):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _proc(1, err="Cannot connect to the Docker daemon"))
    assert A.main(["examples/canary"]) == A.EXIT_ENV
    assert "daemon" in capsys.readouterr().err


def test_image_missing_gives_one_line_hint(monkeypatch, capsys):
    def fake(cmd, **k):
        return _proc(0, "27.0") if cmd[1] == "version" else _proc(1, err="No such image")
    monkeypatch.setattr(subprocess, "run", fake)
    assert A.main(["examples/canary"]) == A.EXIT_ENV
    err = capsys.readouterr().err.strip()
    assert len(err.splitlines()) == 1 and "Traceback" not in err
    assert "extprobe-sandbox:v3 is not present" in err and "python docker/build.py" in err and "--image extprobe-local:v3" in err
    assert A.main(["examples/canary", "--probe"]) == A.EXIT_ENV
    assert "extprobe-local:v3.1-probe" in capsys.readouterr().err


def test_docker_hints_are_one_line(monkeypatch, capsys):
    def boom(*a, **k):
        raise FileNotFoundError
    monkeypatch.setattr(subprocess, "run", boom)
    assert A.main(["examples/canary"]) == A.EXIT_ENV
    err = capsys.readouterr().err.strip()
    assert len(err.splitlines()) == 1 and "Docker was not found" in err
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _proc(1, err="Cannot connect to the Docker daemon\nsecond line"))
    assert A.main(["examples/canary"]) == A.EXIT_ENV
    err = capsys.readouterr().err.strip()
    assert len(err.splitlines()) == 1 and "daemon is not running" in err


def test_not_editable_install_gives_one_line(monkeypatch, tmp_path):
    from extprobe import paths
    monkeypatch.setattr(paths, "ROOT", tmp_path)            # a folder without scoring/ = a non-editable install
    with pytest.raises(SystemExit) as e:
        paths.setup()
    msg = str(e.value)
    assert "\n" not in msg and "pip install -e ." in msg


def test_image_id_mismatch_and_skip(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda cmd, **k: _proc(0, "sha256:" + "0" * 64))
    with pytest.raises(A.AnalyzeError) as e:
        A.check_image(A.IMAGE_V3)
    assert "records sha256:0e4016d1" in str(e.value) and "--skip-image-check" in str(e.value)
    assert A.check_image(A.IMAGE_V3, skip_digest=True) == "sha256:" + "0" * 64


def test_recorded_ids_found():
    assert A.recorded_image_id(A.IMAGE_V3).startswith("sha256:0e4016d1")
    assert A.recorded_image_id(A.IMAGE_PROBE).startswith("sha256:67d0ebe6")


# ---- input packing ----
def test_pack_directory_roundtrip(tmp_path):
    from crx import extract_crx
    crx = A.pack_input(ROOT / "examples" / "canary", tmp_path / "e.crx")
    assert crx.read_bytes()[:4] == b"Cr24"
    assert extract_crx(str(crx), tmp_path / "x")["manifest_version"] == 3
    assert zipfile.is_zipfile(crx)       # score_v3.package_text reads it as a zip


def test_pack_rejects_bad_input(tmp_path):
    (tmp_path / "empty").mkdir()
    bad = tmp_path / "x.crx"
    bad.write_bytes(b"PK\x03\x04")
    for target in (tmp_path / "empty", bad, tmp_path / "nope"):
        with pytest.raises(A.AnalyzeError) as e:
            A.pack_input(target, tmp_path / "o.crx")
        assert e.value.code == A.EXIT_USAGE


def test_pack_crx_is_copied(tmp_path):
    src = tmp_path / "a.crx"
    src.write_bytes(b"Cr24" + struct.pack("<II", 3, 0) + b"PK")
    assert A.pack_input(src, tmp_path / "b.crx").read_bytes() == src.read_bytes()


# ---- report wording ----
def _result(score):
    import score_v3 as S
    ev = {"manifest": {"name": "t", "permissions": [], "host_permissions": []}, "startup": {"profile": "v3"},
          "network_requests": [], "page_request_initiators": [], "dom_activity": [], "page_api_hooks": [],
          "tabs_v3": [], "new_tabs": [], "extension_storage": {}, "page_hang_count": 0}
    res = S.score_trace(ev)
    res["score"] = score
    return ev, res


@pytest.mark.parametrize("score", [0, 20, 100])
def test_reports_use_only_the_three_labels(score):
    ev, res = _result(score)
    html = A.build_html("sample", ev, res, False)
    js = json.dumps(A.build_json("sample", "0" * 64, A.IMAGE_V3, "sha256:x", False, res, {}, "t"))
    for text in (html, js):
        low = text.lower()
        for bad in ("malicious", "malware detected", "safe", "critical", '"level"'):
            assert bad not in low, bad
        assert "it is not a malware verdict" in low
    assert A.label_of(score) in html and json.loads(js)["label"] == A.label_of(score)


# ---- analyst report: sentences, merged evidence, no internal codes ----
INTERNAL = (r"\bT[12]-\d", r"\bA[24]\b", "v3 sensors")


def _exfil_trace(n=3, **kw):
    import score_v3 as S
    ev = {"manifest": {"name": "t", "permissions": [], "host_permissions": [], "content_scripts": []}, "startup": {"profile": "v3"},
          "install_ts": 1000.0, "service_workers": [{"url": "chrome-extension://" + "a" * 32 + "/sw.js"}],
          "network_requests": [{"origin": "service_worker", "source": "cdp_sw", "resource_type": "Fetch", "url": "https://c2.example-evil.net/collect",
                                "method": "POST", "post_data": '{"cred":"HONEYPOT-PASSWORD","pad":"' + "x" * 300 + '"}',
                                "ts": 1000.0 + 1000 * i, "phase_ts": "load"} for i in range(n)],
          "page_request_initiators": [], "dom_activity": [], "page_api_hooks": [], "tabs_v3": [], "new_tabs": [],
          "extension_storage": {}, "page_hang_count": 0}
    ev.update(kw)
    return ev, S.score_trace(ev)


def test_sentence_counts_merge_and_excerpt_limit():
    import report.report_v3 as R
    ev, res = _exfil_trace(3)
    assert res["signals"]["credential_exfil"]["fired"]
    (k, sentence, rows), = [x for x in R.what_it_did(ev, res) if x[0] == "credential_exfil"]
    assert sentence == ("The service worker sent a honeypot password to c2.example-evil.net (3 requests, plain text).")
    assert len(rows) == 1 and rows[0]["Count"] == "×3"                     # three identical requests -> one line
    assert rows[0]["First–last"] == "+0.0 to +2.0 s"
    assert rows[0]["From"] == "sw.js" and rows[0]["Phase"] == "load"
    assert len(rows[0]["Data (max 120 chars)"]) <= 120


def test_signals_lists_only_fired_and_not_observed():
    import re
    import report.report_v3 as R
    ev, res = _exfil_trace(2)
    html = R.analyst_sections(ev, res)
    assert "Credential exfiltration" in html and "+80" in html
    assert re.search(r"Not observed: [^<]*Beaconing", html)
    assert not re.search(r"Not observed: [^<]*Credential exfiltration", html)
    assert "<details><summary>Diagnostics</summary>" in html            # collapsed (no 'open')
    assert html.index("Evidence") < html.index("Diagnostics") < html.index("Manifest risk (shown for information, not scored)")


def test_no_internal_codes_in_report():
    import re
    import report.report_v3 as R
    ev, res = _exfil_trace(2)
    page = R.headline(res) + R.analyst_sections(ev, res) + R.sample_html("s", ev, res)
    for pat in INTERNAL:
        assert not re.search(pat, page), pat


def test_clean_trace_says_nothing_notable():
    import report.report_v3 as R
    ev, res = _exfil_trace(0)
    assert res["score"] == 0 and "No notable behavior was observed" in R.analyst_sections(ev, res)
