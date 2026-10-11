"""run_v3.py -- run samples through the v3 image (profile v3). The frozen eval/batch_run.py only
knows corpus / v2, so v3 has its own runner; same container limits as batch_run.py.

  py eval/v3/run_v3.py --out eval/v3/smoke/traces --crx samples/malware/<id>.crx ... [--canary]
  py eval/v3/run_v3.py --out eval/v3/dev/traces --samples samples/malware --label malicious

Traces stay local (gitignored). Resumable: a sample with an events.json is skipped.
"""
import argparse
import io
import json
import shutil
import struct
import subprocess
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
IMAGE = "extprobe-sandbox:v3"


def build_canary(dst):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted((REPO / "sandbox" / "canary").iterdir()):
            if f.is_file():
                z.writestr(f.name, f.read_bytes())
    dst.write_bytes(b"Cr24" + struct.pack("<I", 3) + struct.pack("<I", 0) + buf.getvalue())


def run_one(crx, out_root, name, timeout, label=None, image_id=None):
    out = out_root / name
    if (out / "output" / "events.json").exists():
        return {"name": name, "status": "skipped"}
    (out / "output").mkdir(parents=True, exist_ok=True)
    staged = out / "extension.crx"
    shutil.copy2(crx, staged)
    host = str(out.resolve()).replace("\\", "/")
    cmd = ["docker", "run", "--rm", "-v", f"{host}:/work", "--tmpfs", "/work/output/extension_unpacked:size=1g",
           "--memory", "3g", "--pids-limit", "512", "--cap-drop", "ALL", "--cap-add", "NET_RAW", "--cap-add", "CHOWN",
           "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "KILL", "--security-opt", "no-new-privileges",
           IMAGE, "/work/extension.crx", "/work/output", str(timeout)]
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout + 90)
        code, err = p.returncode, ("" if p.returncode == 0 else (p.stderr or p.stdout)[-300:])
        (out / "container.log").write_text((p.stdout or "")[-20000:], encoding="utf-8")
    except subprocess.TimeoutExpired:
        code, err = -1, "docker_wall_timeout"
    dur = round(time.time() - t0, 1)
    staged.unlink(missing_ok=True)
    ev = out / "output" / "events.json"
    rs = {}
    if ev.exists():
        try:
            rs = json.loads(ev.read_text(encoding="utf-8")).get("run_status") or {}
        except ValueError:
            rs = {"status": "unreadable_events"}
    meta = {"name": name, "source_filename": crx.name, "docker_exit": code, "duration_s": dur, "error": err,
            "image": IMAGE, "image_id": image_id, "run_status": rs.get("status", "unknown"),
            "label": label, "folder": crx.parent.name if label else None}
    (out / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--crx", nargs="*", default=[])
    ap.add_argument("--canary", action="store_true")
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--samples", nargs="*", default=[], help="folders: every *.crx in them")
    ap.add_argument("--label", default=None, help="label written to meta.json (malicious / benign)")
    a = ap.parse_args()
    image_id = subprocess.run(["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"],
                              capture_output=True, text=True).stdout.strip() or None
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    jobs = []
    if a.canary:
        c = out / "_canary.crx"
        build_canary(c)
        jobs.append((c, "canary"))
    for p in a.crx:
        p = Path(p)
        jobs.append((p, p.stem))
    for d in a.samples:
        jobs += [(p, p.stem) for p in sorted(Path(d).glob("*.crx"))]
    with ThreadPoolExecutor(a.workers) as ex:
        futs = [ex.submit(run_one, c, out, n, a.timeout, a.label, image_id) for c, n in jobs]
        for f in as_completed(futs):
            r = f.result()
            print(r, flush=True)


if __name__ == "__main__":
    main()
