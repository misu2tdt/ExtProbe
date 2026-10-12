"""extprobe analyze <file.crx | unpacked dir> [--probe] [--out DIR]

One step: run the sandbox image (v3, or v3.1-probe with --probe), score the trace with the unchanged score_v3 / score_v31 and
write report.html and report.json to DIR. Nothing here changes how scores are computed; it only runs the pieces already in the
repository (the container as evaluation/v3/run_v3.py does, then scoring/v3/score_v3.py or scoring/probe/score_v31.py).
"""
import argparse
import hashlib
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

from extprobe import paths

ROOT = paths.setup()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))      # report/ is imported as a namespace package
IMAGE_V3 = "extprobe-sandbox:v3"
IMAGE_PROBE = "extprobe-sandbox:v3.1-probe"
# the file that records the id of each frozen image
IMAGE_DOCS = {IMAGE_V3: ROOT / "docs" / "v3" / "IMAGE.md", IMAGE_PROBE: ROOT / "evaluation" / "probe" / "IMAGE.md"}
SECCOMP_PROFILE = ROOT / "docker" / "seccomp_profile.json"      # Playwright's profile (Apache-2.0), see docker/seccomp_profile.NOTICE
DEFAULT_TIMEOUT = {IMAGE_V3: 180, IMAGE_PROBE: 240}
RUN_NAME = "run"          # folder name of the single run inside <out>/traces (no extension id in paths)
EXIT_OK, EXIT_USAGE, EXIT_ENV, EXIT_RUN = 0, 2, 3, 4


class AnalyzeError(Exception):
    def __init__(self, msg, code=EXIT_ENV):
        super().__init__(msg)
        self.code = code


# ---- level text (thresholds as in score_v3.FLAG_THRESHOLD and the 15-point review line) ----
def label_of(score):
    from report.report_v3 import label_of as f
    return f(score)


# ---- input ----
def pack_input(src, dest):
    """-> path of a .crx (CRX3 header + zip) for the sandbox. A .crx is copied; a directory must hold manifest.json."""
    src = Path(src)
    if src.is_dir():
        if not (src / "manifest.json").is_file():
            raise AnalyzeError(f"{src} has no manifest.json (expected an unpacked extension directory)", EXIT_USAGE)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for f in sorted(src.rglob("*")):
                if f.is_file():
                    z.writestr(f.relative_to(src).as_posix(), f.read_bytes())
        dest.write_bytes(b"Cr24" + struct.pack("<I", 3) + struct.pack("<I", 0) + buf.getvalue())
    elif src.is_file():
        if src.read_bytes()[:4] != b"Cr24":
            raise AnalyzeError(f"{src} is not a .crx file (missing the Cr24 header)", EXIT_USAGE)
        shutil.copy2(src, dest)
    else:
        raise AnalyzeError(f"{src}: no such file or directory", EXIT_USAGE)
    return dest


# ---- docker ----
def _docker(*args, timeout=60):
    return subprocess.run(["docker", *args], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)


def check_docker():
    try:
        p = _docker("version", "--format", "{{.Server.Version}}", timeout=30)
    except FileNotFoundError:
        raise AnalyzeError("Docker was not found on PATH: install Docker (Docker Desktop, or Docker Engine on Linux) and check that `docker version` works.")
    except subprocess.TimeoutExpired:
        raise AnalyzeError("Docker did not answer within 30 s: is the Docker daemon running? (start Docker Desktop, or `sudo systemctl start docker`)")
    if p.returncode != 0:
        raise AnalyzeError("Docker is installed but its daemon is not running: start Docker Desktop (or `sudo systemctl start docker`), then retry.")


def recorded_image_id(image):
    """The sha256 image id recorded for `image` in its IMAGE.md ('local image id' row), or None."""
    doc = IMAGE_DOCS[image]
    if not doc.exists():
        return None
    for line in doc.read_text(encoding="utf-8", errors="replace").splitlines():
        if "local image id" in line:
            m = re.search(r"sha256:[0-9a-f]{64}", line)
            if m:
                return m.group(0)
    return None


def check_image(image, skip_digest=False):
    p = _docker("image", "inspect", image, "--format", "{{.Id}}")
    if p.returncode != 0:
        raise AnalyzeError(f"Docker image {image} is not present locally: build it with `python docker/build.py` and pass `--image extprobe-local:v3` "
                           f"(`--probe --image extprobe-local:v3.1-probe` for probe mode), or load/pull the frozen image (see README).")
    got = p.stdout.strip()
    want = recorded_image_id(image) if image in IMAGE_DOCS else None
    if want and got != want and not skip_digest:
        raise AnalyzeError(f"Image {image} has id {got}, but {IMAGE_DOCS[image].relative_to(ROOT).as_posix()} records {want}: use the frozen image, "
                           f"or pass --skip-image-check (result not tied to the recorded image); an image from docker/build.py is used with --image.")
    return got


def run_container(image, crx, run_dir, timeout, platform=None):
    """Same limits as evaluation/v3/run_v3.py. Returns docker's exit code."""
    (run_dir / "output").mkdir(parents=True, exist_ok=True)
    staged = run_dir / "extension.crx"
    shutil.copy2(crx, staged)
    host = str(run_dir.resolve()).replace("\\", "/")
    if not SECCOMP_PROFILE.is_file():
        raise AnalyzeError(f"seccomp profile not found: {SECCOMP_PROFILE} (is this a complete checkout of the repository?)")
    cmd = ["docker", "run", "--rm", *(["--platform", platform] if platform else []), "-v", f"{host}:/work", "--tmpfs", "/work/output/extension_unpacked:size=1g",
           "--memory", "3g", "--pids-limit", "512", "--cap-drop", "ALL", "--cap-add", "NET_RAW", "--cap-add", "CHOWN",
           "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "KILL",
           # Added for Linux hosts (found in Codespaces: Docker 29, docker-in-docker); the frozen entrypoint and image are unchanged.
           # FOWNER: the entrypoint chmods the bind-mounted /work/output, which the host user owns; without it root gets "Operation not permitted".
           "--cap-add", "FOWNER",
           # SYS_CHROOT: Chromium's zygote chroots to /proc/self/fdinfo/ when its sandbox starts.
           "--cap-add", "SYS_CHROOT",
           # Docker's default seccomp profile blocks unshare(CLONE_NEWUSER), which Chromium's namespace sandbox needs. Playwright's own profile
           # allows it, so the Chromium sandbox stays enabled (seccomp=unconfined would work but is far too broad).
           "--security-opt", f"seccomp={SECCOMP_PROFILE}",
           "--security-opt", "no-new-privileges",
           image, "/work/extension.crx", "/work/output", str(timeout)]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout + 90)
        (run_dir / "container.log").write_text((p.stdout or "")[-20000:], encoding="utf-8")
        if p.returncode != 0:
            log = run_dir / "docker_output.log"                     # the container is --rm: keep what docker printed
            text = f"$ {' '.join(cmd)}\nexit code {p.returncode}\n--- stdout ---\n{p.stdout or ''}\n--- stderr ---\n{p.stderr or ''}\n"
            log.write_text(text, encoding="utf-8")
            tail = "\n".join(((p.stdout or "") + (p.stderr or "")).splitlines()[-20:])
            print(f"[extprobe] container exited with code {p.returncode}; last 20 lines (everything is in {log}):\n{tail}", file=sys.stderr)
        return p.returncode
    except subprocess.TimeoutExpired:
        raise AnalyzeError("The container did not finish in time and was abandoned (docker wall timeout).", EXIT_RUN)
    finally:
        staged.unlink(missing_ok=True)


# ---- scoring ----
def score_run(run_dir, probe, crx):
    """-> (events used for the report, score_trace result, extra dict). Uses the unchanged scoring modules."""
    import score_v3 as S
    evp = run_dir / "output" / "events.json"
    if not evp.exists():
        raise AnalyzeError("The sandbox produced no events.json (see container.log and, if the container failed, docker_output.log in the traces folder).", EXIT_RUN)
    ev = json.loads(evp.read_text(encoding="utf-8"))
    rs = ev.get("run_status") or {}
    if rs.get("status") == "failed":
        raise AnalyzeError(f"The sandbox could not analyze this extension: {rs.get('reason')}. See docs/TROUBLESHOOTING.md.", EXIT_RUN)
    pkg = S.package_text(crx)
    if not probe:
        return ev, S.score_trace(ev, pkg), {}
    import score_v31 as P
    prp = run_dir / "output" / "events_probe.json"
    post = json.loads(prp.read_text(encoding="utf-8")) if prp.exists() else {}
    view, stats = P.build_view(ev, post)
    res = S.score_trace(view, pkg)
    run = P.score_run(ev, post, pkg)
    if run["v31_score"] != res["score"]:        # same function, same inputs: a mismatch would be a bug
        raise AnalyzeError("internal error: probe view score differs from score_v31", EXIT_RUN)
    return view, res, {"probe": run["probe"], "view": stats, "v3_score_without_probe": run["v3_score"]}


def build_json(name, sha, image, image_id, probe, res, extra, started):
    from report.report_v3 import NOTE
    sc = res["score"]
    return {"tool": "ExtProbe", "mode": "probe (v3.1)" if probe else "v3", "image": image, "image_id": image_id,
            "input": {"name": name, "sha256": sha}, "analyzed_at": started,
            "score": sc, "label": label_of(sc), "flagged_for_review": sc >= 40,
            "detectors_fired": res["fired"],
            "signals": {k: {"fired": s["fired"], "weight": s["weight"], "details": s["details"]} for k, s in res["signals"].items()},
            "static_display": res["static_display"], **extra, "note": NOTE}


def build_html(name, ev, res, probe, extra=None):
    import report.report_v3 as R
    mode = "probe mode (v3.1)" if probe else "v3"
    diag = {"probe": extra["probe"], "view": extra["view"]} if extra and probe else None
    return ("<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>ExtProbe report</title><style>{R.CSS}</style></head><body><h1>ExtProbe report</h1>"
            f"<p class='mut'>{R.e(name)} &middot; {R.e(ev.get('manifest', {}).get('name'))} &middot; {mode}</p>"
            + R.headline(res) + R.analyst_sections(ev, res, diag) + "</body></html>")


def parse(argv):
    ap = argparse.ArgumentParser(prog="extprobe analyze", description="Run the ExtProbe sandbox on an extension and write a report.")
    ap.add_argument("target", help="a .crx file or an unpacked extension directory (with manifest.json)")
    ap.add_argument("--probe", action="store_true", help="probe mode: image v3.1-probe, scored with score_v31")
    ap.add_argument("--out", default="extprobe-out", help="output directory (default: ./extprobe-out)")
    ap.add_argument("--timeout", type=int, default=None, help="in-container time budget in seconds (default 180; 240 with --probe)")
    ap.add_argument("--image", default=None, help="local image to run instead of the frozen one (extprobe-sandbox:v3, or :v3.1-probe with --probe); "
                    "the image id is then not compared with IMAGE.md (e.g. an image built by docker/build.py)")
    ap.add_argument("--platform", default=None, help="platform to run the container as, e.g. linux/amd64 on Apple Silicon "
                    "(default: $DOCKER_DEFAULT_PLATFORM if set, else Docker's default)")
    ap.add_argument("--skip-image-check", action="store_true", help="do not compare the local image id with the one recorded in IMAGE.md")
    return ap.parse_args(argv)


def run(a):
    image = a.image or (IMAGE_PROBE if a.probe else IMAGE_V3)
    platform = a.platform or os.environ.get("DOCKER_DEFAULT_PLATFORM") or None
    out = Path(a.out)
    check_docker()
    image_id = check_image(image, a.skip_image_check or image not in IMAGE_DOCS)
    if image not in IMAGE_DOCS:
        print(f"[extprobe] note: custom image {image}; its id is not compared with the recorded one, so the result is not tied to the frozen image", flush=True)
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="extprobe-") as tmp:
        crx = pack_input(a.target, Path(tmp) / "extension.crx")
        sha = hashlib.sha256(crx.read_bytes()).hexdigest()
        run_dir = out / "traces" / RUN_NAME
        shutil.rmtree(run_dir, ignore_errors=True)
        started = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        print(f"[extprobe] running {image} on {Path(a.target).name} ...", flush=True)
        code = run_container(image, crx, run_dir, a.timeout or DEFAULT_TIMEOUT[IMAGE_PROBE if a.probe else IMAGE_V3], platform)
        if code != 0:
            print(f"[extprobe] warning: container exit code {code}", file=sys.stderr)
        ev, res, extra = score_run(run_dir, a.probe, crx)
    name = Path(a.target).name
    (out / "report.json").write_text(json.dumps(build_json(name, sha, image, image_id, a.probe, res, extra, started),
                                                indent=1, ensure_ascii=False, default=str), encoding="utf-8")
    (out / "report.html").write_text(build_html(name, ev, res, a.probe, extra), encoding="utf-8")
    from report.report_v3 import NOTE
    print(f"score:     {res['score']} / 100")
    print(f"level:     {label_of(res['score'])}")
    print(f"detectors: {', '.join(res['fired']) or 'none'}")
    print(f"report:    {(out / 'report.html').resolve()}")
    print(f"           {(out / 'report.json').resolve()}")
    print(NOTE)
    return EXIT_OK


def main(argv=None):
    try:
        a = parse(sys.argv[1:] if argv is None else argv)
        return run(a)
    except AnalyzeError as e:
        print(f"extprobe analyze: {e}", file=sys.stderr)
        return e.code
