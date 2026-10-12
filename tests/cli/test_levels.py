"""score-v3 / score-v31 print the three report levels (legacy severity in parentheses); the scoring scripts are unchanged."""
import json

import pytest

from extprobe import levels
from extprobe.__main__ import main as cli_main
from extprobe.analyze import label_of as report_label


def _trace(n_requests):
    return {"manifest": {"name": "t", "permissions": [], "host_permissions": [], "content_scripts": []}, "startup": {"profile": "v3"},
            "install_ts": 1000.0, "service_workers": [{"url": "chrome-extension://" + "a" * 32 + "/sw.js"}],
            "network_requests": [{"origin": "service_worker", "source": "cdp_sw", "resource_type": "Fetch", "url": "https://c2.example-evil.net/x",
                                  "method": "POST", "post_data": '{"cred":"HONEYPOT-PASSWORD"}', "ts": 1000.0 + 1000 * i, "phase_ts": "load"}
                                 for i in range(n_requests)],
            "page_request_initiators": [], "dom_activity": [], "page_api_hooks": [], "tabs_v3": [], "new_tabs": [],
            "extension_storage": {}, "page_hang_count": 0}


def _write(tmp_path, name, ev):
    d = tmp_path / name / "output"
    d.mkdir(parents=True)
    (d / "events.json").write_text(json.dumps(ev), encoding="utf-8")


@pytest.mark.parametrize("score,legacy,label", [
    (100, "CRITICAL", "Flagged for review"), (70, "HIGH", "Flagged for review"), (40, "MEDIUM", "Flagged for review"),
    (39, "LOW", "Review suggested"), (15, "LOW", "Review suggested"), (14, "MINIMAL", "No notable behavior observed"),
    (0, "MINIMAL", "No notable behavior observed")])
def test_relabel_v3_line(score, legacy, label):
    out = levels.relabel_v3_line(f"{'sample':34s} {score:3d} {legacy:8s} credential_exfil,local_harvest")
    assert f"{score:3d} {label} (legacy: {legacy}) credential_exfil,local_harvest" in out
    assert out.startswith("sample")


def test_relabel_leaves_other_lines_alone():
    assert levels.relabel_v3_line("some other output") == "some other output"
    assert levels.relabel_v31_line("some other output") == "some other output"


def test_relabel_v31_line_appends_level_of_v31_score():
    line = "run: v3 20 -> v3.1 45 | yield True | login_gate False | proxy False"
    assert levels.relabel_v31_line(line).endswith("| level: Flagged for review")


def test_levels_agree_with_report():
    for s in range(0, 101):
        assert levels.label_of(s) == report_label(s)


def test_cli_score_v3_prints_report_levels(tmp_path, capsys):
    _write(tmp_path, "hit", _trace(3))
    _write(tmp_path, "clean", _trace(0))
    assert cli_main(["score-v3", "--traces", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    hit = next(l for l in out.splitlines() if l.startswith("hit"))
    clean = next(l for l in out.splitlines() if l.startswith("clean"))
    assert "Flagged for review (legacy: CRITICAL)" in hit and "credential_exfil" in hit
    assert "No notable behavior observed (legacy: MINIMAL)" in clean


def test_cli_score_v31_prints_level(tmp_path, capsys):
    _write(tmp_path, "hit", _trace(3))
    assert cli_main(["score-v31", "--traces", str(tmp_path)]) == 0
    assert "| level: Flagged for review" in capsys.readouterr().out
