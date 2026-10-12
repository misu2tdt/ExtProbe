"""docker/build.py (new tags, frozen FROM lines rewritten) and `extprobe analyze --image`. No Docker needed."""
import importlib.util
import subprocess
from pathlib import Path

import pytest

from extprobe import analyze as A

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("docker_build", ROOT / "docker" / "build.py")
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)


def _from_lines(text):
    return [l for l in text.splitlines() if l.startswith("FROM ")]


def test_base_dockerfile_is_unchanged():
    p = ROOT / "docker" / "Dockerfile.base"
    assert B.patched_dockerfile(p, None) == p.read_bytes().decode("utf-8").replace("\r\n", "\n")


def test_from_lines_point_to_the_new_tags():
    assert _from_lines(B.patched_dockerfile(ROOT / "docker" / "Dockerfile.v3", "mine:base")) == ["FROM mine:base"]
    assert _from_lines(B.patched_dockerfile(ROOT / "docker" / "Dockerfile.probe", "mine:v3")) == ["FROM mine:v3"]
    for f in ("Dockerfile.v3", "Dockerfile.probe"):
        assert "extprobe-sandbox" not in "\n".join(l for l in B.patched_dockerfile(ROOT / "docker" / f, "x:y").splitlines() if l.startswith("FROM"))


def test_steps_chain_and_never_use_frozen_repo():
    assert [s[0] for s in B.STEPS] == ["base", "v3", "v3.1-probe"]
    assert [s[3] for s in B.STEPS] == [None, "base", "v3"]


def test_refuses_the_frozen_repository_name():
    with pytest.raises(SystemExit) as e:
        B.main(["--prefix", "extprobe-sandbox"])
    assert "frozen" in str(e.value)


def test_analyze_image_option_parses():
    a = A.parse(["x", "--image", "extprobe-local:v3"])
    assert a.image == "extprobe-local:v3" and A.parse(["x"]).image is None


def test_custom_image_skips_the_id_check_and_is_announced(monkeypatch, capsys, tmp_path):
    def fake(cmd, **k):
        if cmd[1] == "version":
            return subprocess.CompletedProcess(cmd, 0, "27.0", "")
        if cmd[1:3] == ["image", "inspect"]:
            return subprocess.CompletedProcess(cmd, 0, "sha256:" + "1" * 64, "")
        raise RuntimeError("stop after the image check")          # run_container must not be reached with a wrong id check
    monkeypatch.setattr(subprocess, "run", fake)
    with pytest.raises(RuntimeError):
        A.run(A.parse([str(ROOT / "examples" / "canary"), "--image", "mine:v3", "--out", str(tmp_path)]))
    assert "custom image mine:v3" in capsys.readouterr().out


def test_missing_custom_image_points_to_build_py(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda cmd, **k: subprocess.CompletedProcess(cmd, 0 if cmd[1] == "version" else 1, "27.0", "No such image"))
    with pytest.raises(A.AnalyzeError) as e:
        A.check_image("mine:v3")
    assert "docker/build.py" in str(e.value) and "--image" in str(e.value)


# ---- --platform / DOCKER_DEFAULT_PLATFORM (Apple Silicon: linux/amd64) ----
def _capture_run(monkeypatch):
    calls = []

    def fake(cmd, **k):
        calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0, "", "")
    monkeypatch.setattr(subprocess, "run", fake)
    return calls


def test_run_container_passes_platform(monkeypatch, tmp_path):
    crx = tmp_path / "e.crx"
    crx.write_bytes(b"Cr24")
    calls = _capture_run(monkeypatch)
    A.run_container("mine:v3", crx, tmp_path / "r1", 10, "linux/amd64")
    cmd = calls[-1]
    assert cmd[:5] == ["docker", "run", "--rm", "--platform", "linux/amd64"] and "mine:v3" in cmd
    A.run_container("mine:v3", crx, tmp_path / "r2", 10)
    assert "--platform" not in calls[-1]


@pytest.mark.parametrize("flag,env,expect", [(["--platform", "linux/arm64"], "linux/amd64", "linux/arm64"), ([], "linux/amd64", "linux/amd64"), ([], None, None)])
def test_analyze_platform_flag_then_env(monkeypatch, tmp_path, flag, env, expect):
    seen = {}
    monkeypatch.delenv("DOCKER_DEFAULT_PLATFORM", raising=False)
    if env:
        monkeypatch.setenv("DOCKER_DEFAULT_PLATFORM", env)
    monkeypatch.setattr(A, "check_docker", lambda: None)
    monkeypatch.setattr(A, "check_image", lambda image, skip=False: "sha256:" + "2" * 64)

    def stop(image, crx, run_dir, timeout, platform=None):
        seen["platform"] = platform
        raise RuntimeError("stop")
    monkeypatch.setattr(A, "run_container", stop)
    with pytest.raises(RuntimeError):
        A.run(A.parse([str(ROOT / "examples" / "canary"), "--image", "mine:v3", "--out", str(tmp_path), *flag]))
    assert seen["platform"] == expect


@pytest.mark.parametrize("args,env,expect", [(["--platform", "linux/amd64"], None, True), ([], "linux/amd64", True), ([], None, False)])
def test_build_py_platform(monkeypatch, args, env, expect):
    monkeypatch.delenv("DOCKER_DEFAULT_PLATFORM", raising=False)
    if env:
        monkeypatch.setenv("DOCKER_DEFAULT_PLATFORM", env)
    builds = []

    def fake(*a, **k):
        if a and a[0] == "build":
            builds.append(list(a))
        return subprocess.CompletedProcess(a, 0, "27.0\n", "")
    monkeypatch.setattr(B, "docker", fake)
    # B.main re-parses the environment default each call
    assert B.main(args) == 0
    assert len(builds) == 3
    for cmd in builds:
        assert (["--platform", "linux/amd64"] == cmd[cmd.index("--platform"):cmd.index("--platform") + 2]) if expect else "--platform" not in cmd


# ---- Linux: capabilities, Playwright's seccomp profile, failure log ----
def _docker_run_cmd(monkeypatch, tmp_path):
    crx = tmp_path / "e.crx"
    crx.write_bytes(b"Cr24")
    calls = _capture_run(monkeypatch)
    A.run_container("mine:v3", crx, tmp_path / "run", 10)
    return calls[-1]


def _pairs(cmd, flag):
    return [cmd[i + 1] for i, x in enumerate(cmd) if x == flag]


def test_run_container_linux_caps_and_seccomp(monkeypatch, tmp_path):
    cmd = _docker_run_cmd(monkeypatch, tmp_path)
    caps = _pairs(cmd, "--cap-add")
    assert {"FOWNER", "SYS_CHROOT"} <= set(caps)                           # Linux hosts (Codespaces)
    assert {"NET_RAW", "CHOWN", "SETUID", "SETGID", "KILL"} <= set(caps)    # the evaluation configuration is kept
    assert _pairs(cmd, "--cap-drop") == ["ALL"] and "--privileged" not in cmd
    sec = _pairs(cmd, "--security-opt")
    assert "no-new-privileges" in sec and not any("unconfined" in s for s in sec)
    prof = [s for s in sec if s.startswith("seccomp=")]
    assert len(prof) == 1
    path = Path(prof[0][len("seccomp="):])
    assert path.is_absolute() and path.is_file() and path == A.SECCOMP_PROFILE


def test_seccomp_profile_is_valid_and_allows_userns():
    import json
    d = json.loads(A.SECCOMP_PROFILE.read_bytes().decode("utf-8"))
    assert "defaultAction" in d
    names = {n for rule in d["syscalls"] for n in rule.get("names", [])}
    assert "unshare" in names and "clone" in names                        # Chromium's namespace sandbox
    assert (ROOT / "docker" / "seccomp_profile.NOTICE").is_file()


def test_failed_container_output_is_kept_and_tail_printed(monkeypatch, tmp_path, capsys):
    crx = tmp_path / "e.crx"
    crx.write_bytes(b"Cr24")
    out = "\n".join(f"line {i}" for i in range(30))
    monkeypatch.setattr(subprocess, "run", lambda cmd, **k: subprocess.CompletedProcess(cmd, 1, out, "Failed to launch the browser process\n"))
    assert A.run_container("mine:v3", crx, tmp_path / "run", 10) == 1
    log = (tmp_path / "run" / "docker_output.log").read_text(encoding="utf-8")
    assert "line 0" in log and "line 29" in log and "Failed to launch the browser process" in log and "exit code 1" in log
    err = capsys.readouterr().err
    assert "line 29" in err and "Failed to launch" in err and "line 5" not in err      # only the last 20 lines
    monkeypatch.setattr(subprocess, "run", lambda cmd, **k: subprocess.CompletedProcess(cmd, 0, "ok", ""))
    A.run_container("mine:v3", crx, tmp_path / "run2", 10)
    assert not (tmp_path / "run2" / "docker_output.log").exists()
