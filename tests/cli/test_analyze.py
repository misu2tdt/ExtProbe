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


def test_image_missing_prints_build_commands(monkeypatch, capsys):
    def fake(cmd, **k):
        return _proc(0, "27.0") if cmd[1] == "version" else _proc(1, err="No such image")
    monkeypatch.setattr(subprocess, "run", fake)
    assert A.main(["examples/canary"]) == A.EXIT_ENV
    err = capsys.readouterr().err
    assert "extprobe-sandbox:v3 is not present" in err and "docker build -f docker/Dockerfile.v3" in err
    assert A.main(["examples/canary", "--probe"]) == A.EXIT_ENV
    assert "docker build -f docker/Dockerfile.probe" in capsys.readouterr().err


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
