"""run_probe.py -- run .crx files through extprobe-sandbox:v3.1-probe (prototype). Same docker limits as
eval/v3/run_v3.py (frozen, not reused because its image is fixed to v3); default timeout 240 s (v3: 180 s + the
probe budget). Same capabilities as v3 (no NET_ADMIN: the proxy guard is a Chrome policy + in-browser recorder).

  py eval/v3_1_probe/run_probe.py --out eval/v3_1_probe/proto/traces --crx <a.crx> ... [--names M1 M2 ...]

`--names` gives the folder names (so that no extension id has to appear in logs). Traces stay local (gitignored).
"""
import argparse
import json
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

IMAGE = "extprobe-sandbox:v3.1-probe"


def run_one(crx, out_root, name, timeout):
    out = out_root / name
    if (out / "output" / "events.json").exists():
        return {"name": name, "status": "skipped"}
    (out / "output").mkdir(parents=True, exist_ok=True)
    staged = out / "extension.crx"
    shutil.copy2(crx, staged)
    host = str(out.resolve()).replace("\\", "/")
    cmd = ["docker", "run", "--rm", "-v", f"{host}:/work", "--tmpfs", "/work/output/extension_unpacked:size=1g",
           "--memory", "3g", "--pids-limit", "512", "--cap-drop", "ALL", "--cap-add", "NET_RAW", "--cap-add", "CHOWN",
           "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "KILL",
           "--security-opt", "no-new-privileges",
           IMAGE, "/work/extension.crx", "/work/output", str(timeout)]
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout + 90)
        code = p.returncode
        (out / "container.log").write_text((p.stdout or "")[-20000:], encoding="utf-8")
    except subprocess.TimeoutExpired:
        code = -1
    staged.unlink(missing_ok=True)
    meta = {"name": name, "docker_exit": code, "duration_s": round(time.time() - t0, 1), "image": IMAGE}
    (out / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--crx", nargs="*", default=[])
    ap.add_argument("--names", nargs="*")
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--timeout", type=int, default=240)
    ap.add_argument("--list", default=None, help="file with one .crx path per line (instead of --crx); folder name = file stem")
    ap.add_argument("--quiet", action="store_true", help="print counts only (no sample names)")
    a = ap.parse_args()
    if a.list:
        a.crx = [l.strip() for l in open(a.list, encoding="utf-8") if l.strip()]
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    names = a.names or [Path(c).stem for c in a.crx]
    done = {"ok": 0, "nonzero_exit": 0, "skipped": 0}
    with ThreadPoolExecutor(a.workers) as ex:
        for k, f in enumerate(as_completed([ex.submit(run_one, Path(c), out, n, a.timeout) for c, n in zip(a.crx, names)]), 1):
            r = f.result()
            key = "skipped" if r.get("status") == "skipped" else ("ok" if r.get("docker_exit") == 0 else "nonzero_exit")
            done[key] += 1
            if a.quiet:
                print(f"[{k}/{len(a.crx)}] {key} {r.get('duration_s') or ''}", flush=True)
            else:
                print({x: r.get(x) for x in ("name", "docker_exit", "duration_s", "status")}, flush=True)
    print(f"done: {done}", flush=True)


if __name__ == "__main__":
    main()
