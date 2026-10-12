"""Build the ExtProbe sandbox images from source under NEW local tags (Linux, macOS, Windows; needs only Python 3 and Docker).

  python docker/build.py                      # extprobe-local:base, :v3 and :v3.1-probe
  python docker/build.py --prefix mine        # mine:base, mine:v3, mine:v3.1-probe
  python docker/build.py --skip-probe         # base and v3 only
  python docker/build.py --no-cache           # rebuild every layer (downloads the base image and packages again)

The Dockerfiles in docker/ are the frozen ones and start FROM the tags extprobe-sandbox:v2 / :v3. This script does not edit them and does not
touch those tags: it feeds each Dockerfile to `docker build -f -` with the FROM line pointed at the tag built in the previous step. The build is
functionally equivalent to the frozen images but has a different image id (see docker/README.md). Run the result with
`extprobe analyze TARGET --image <prefix>:v3` (or `--probe --image <prefix>:v3.1-probe`).
"""
import argparse
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FROZEN_REPO = "extprobe-sandbox"          # the tags of the frozen images; never built or overwritten here
STEPS = (  # (suffix, Dockerfile, context, tag its FROM line must point to)
    ("base", "docker/Dockerfile.base", "sandbox/base", None),
    ("v3", "docker/Dockerfile.v3", "sandbox/v3", "base"),
    ("v3.1-probe", "docker/Dockerfile.probe", "sandbox/probe", "v3"),
)


def docker(*args, **kw):
    return subprocess.run(["docker", *args], **kw)


def patched_dockerfile(path, from_tag):
    text = path.read_bytes().decode("utf-8").replace("\r\n", "\n")
    if from_tag is None:
        return text
    new, n = re.subn(r"(?m)^FROM extprobe-sandbox:\S+[ \t]*$", f"FROM {from_tag}", text)
    if n != 1:
        raise SystemExit(f"build.py: expected exactly one 'FROM extprobe-sandbox:...' line in {path.name}, found {n}")
    return new


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build the ExtProbe sandbox images under new local tags.")
    ap.add_argument("--prefix", default="extprobe-local", help="image repository name for the new tags (default: extprobe-local)")
    ap.add_argument("--skip-probe", action="store_true", help="do not build the v3.1-probe image")
    ap.add_argument("--no-cache", action="store_true", help="pass --no-cache to docker build")
    ap.add_argument("--platform", default=os.environ.get("DOCKER_DEFAULT_PLATFORM") or None,
                    help="pass --platform to docker build, e.g. linux/amd64 on Apple Silicon (the frozen images are linux/amd64); "
                         "default: $DOCKER_DEFAULT_PLATFORM if set")
    a = ap.parse_args(argv)
    if a.prefix == FROZEN_REPO:
        raise SystemExit(f"build.py: refusing to build into '{FROZEN_REPO}': those tags belong to the frozen images. Use another --prefix.")
    try:
        p = docker("version", "--format", "{{.Server.Version}}", capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        raise SystemExit("build.py: Docker was not found on PATH. Install Docker (Docker Desktop or Docker Engine) first.")
    if p.returncode != 0:
        raise SystemExit("build.py: the Docker daemon is not reachable (start Docker Desktop / the docker service).\n" + p.stderr.strip()[-300:])
    print(f"Docker {p.stdout.strip()}; building {a.prefix}:* from {ROOT}", flush=True)
    t_all = time.time()
    built = {}
    for suffix, dockerfile, context, from_suffix in STEPS:
        if suffix == "v3.1-probe" and a.skip_probe:
            continue
        tag = f"{a.prefix}:{suffix}"
        from_tag = f"{a.prefix}:{from_suffix}" if from_suffix else None
        cmd = ["build", "-f", "-", "-t", tag]
        if a.no_cache:
            cmd.append("--no-cache")
        if a.platform:
            cmd += ["--platform", a.platform]
        cmd.append(str(ROOT / context))
        print(f"\n== {tag}  (Dockerfile {dockerfile}{', FROM ' + from_tag if from_tag else ''})\n$ docker {' '.join(cmd)}", flush=True)
        t0 = time.time()
        r = docker(*cmd, input=patched_dockerfile(ROOT / dockerfile, from_tag).encode("utf-8"), cwd=str(ROOT))
        if r.returncode != 0:
            raise SystemExit(f"build.py: docker build failed for {tag} (exit {r.returncode})")
        iid = docker("image", "inspect", tag, "--format", "{{.Id}}", capture_output=True, text=True).stdout.strip()
        built[tag] = iid
        print(f"== {tag} = {iid}  ({time.time() - t0:.0f} s)", flush=True)
    print(f"\nDone in {time.time() - t_all:.0f} s. Images:")
    for tag, iid in built.items():
        print(f"  {tag}  {iid}")
    v3 = f"{a.prefix}:v3"
    print("\nRun:\n"
          f"  extprobe analyze examples/demo --image {v3} --out out/\n"
          + ("" if a.skip_probe else f"  extprobe analyze examples/demo --probe --image {a.prefix}:v3.1-probe --out out_probe/\n")
          + "These images have different ids from the frozen ones; results are not tied to the recorded image ids.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
