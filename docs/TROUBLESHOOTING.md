# Troubleshooting

A sandbox run that could not analyze the extension ends quickly with `run_status.status = "failed"` in `events.json`; the reason says why:

| `run_status.reason` starts with | Meaning | What to do |
|---|---|---|
| `incompatible_browser` | The manifest's `minimum_chrome_version` is newer than the sandbox's Chrome for Testing (153). | Nothing to fix; the extension cannot run in this browser. |
| `extension_files_missing` | A file the manifest references was gone after unpacking. On Windows hosts this is usually the antivirus deleting detected malicious JavaScript from the bind-mounted output folder. | Run in WSL2 or a Linux VM, or exclude the output folder from the antivirus. |
| `launch_failed` / `no_page_loaded` | Chromium did not start, or its first page did not respond, 3 times in a row. | Check the Docker engine, free memory (the container limit is 3 GB). |
| `soft_timeout_<N>s` | The whole browser run exceeded its time budget. | `stuck_step` says whether this happened during startup or during the phases. |

**Windows antivirus and the samples.** Windows Defender flags several samples (for example `Trojan:JS/ChatGPTStealer`). It may delete or
quarantine files and JavaScript unpacked into shared host folders. Run everything in WSL2 or a Linux VM; if you must run on Windows, check
the sample files against their SHA-256 (`evaluation/manifests/`) before each use.

## Malicious samples - safety rules

- **Never** open a `.crx` of the malicious sets outside the sandbox container. Do not drag it into `chrome://extensions`, do not unzip it on a
  machine with anything sensitive signed in.
- **Never** sign in with real credentials while testing: several samples target Google/Telegram OAuth flows.
- Every sandboxed run is disposable (`docker run --rm`, ephemeral profile).
- You do **not** need to open any sample to check the paper numbers: `python evaluation/v2/check_paper_numbers.py --precomputed` works
  from the precomputed result files.

## Installing and running for the first time

| Symptom | Cause / fix |
|---|---|
| `extprobe: command not found` | The venv is not activated, or the scripts folder is not on PATH. Use `python -m extprobe ...`. |
| `extprobe: scoring/ is not next to the extprobe package` | A plain `pip install .` was used. Install from a clone in editable mode: `pip install -e .`. |
| `Docker was not found` / `daemon is not reachable` | Install Docker; start Docker Desktop (or `sudo systemctl start docker`). On Linux add your user to the `docker` group (`sudo usermod -aG docker $USER`, then log in again). |
| `Docker image ... is not present locally` | Pull the image (README, Option A) or build it: `python docker/build.py` and pass `--image extprobe-local:v3`. |
| `Image ... has id ... but IMAGE.md records ...` | The image under the frozen tag is not the frozen one. Use the pulled image, or `--skip-image-check` (result not tied to the frozen image). Images from `docker/build.py` are used with `--image`, which skips this check. |
| `docker build` fails while pulling `mcr.microsoft.com/...`, `apt-get` or `pip` | No internet or a proxy: set Docker's proxy settings; retry. |
| Apple Silicon / ARM | Untested by the authors. The images are `linux/amd64`: enable Rosetta emulation in Docker Desktop, then use `--platform linux/amd64` with `python docker/build.py` and `extprobe analyze` (or set `DOCKER_DEFAULT_PLATFORM=linux/amd64`). Slow under emulation. GitHub Codespaces (README) avoids it. |
| `standard_init_linux.go ... no such file or directory` (shell scripts) | Shell scripts with Windows line endings. `.gitattributes` forces LF for `*.sh`; re-clone, or `git config core.autocrlf false` and checkout again. |
| Run killed, container exit 137 | Docker has less than 3 GB of memory available (Docker Desktop > Settings > Resources). |
| Codespaces opens in "recovery mode" (the container could not be built) | In the Codespaces command palette run **Codespaces: View Creation Log** and read the first `ERROR`; fix it, then **Codespaces: Rebuild Container**. Example: `NO_PUBKEY ... dl.yarnpkg.com` while installing docker-in-docker was caused by the base image's Yarn apt source; `.devcontainer/Dockerfile` removes it. |
