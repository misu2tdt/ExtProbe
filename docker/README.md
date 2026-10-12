# docker/

Three images, layered: the base image (v2 core), v3 on top of it, and v3.1-probe on top of v3. The context of each build is the matching `sandbox/` folder.

## Option A: the published frozen image (recommended, exact reproduction)

A registry image will be published before submission; until then use Option B, or ask the authors for a pre-built image file (`docker load -i extprobe-sandbox-v3.tar`). It provides `extprobe-sandbox:v3` and `extprobe-sandbox:v3.1-probe`, the images the evaluations were run with. Their ids are recorded in `PROVENANCE.md` and in `docs/v3/IMAGE.md` / `evaluation/probe/IMAGE.md`.

## Option B: build from source (any OS)

```bash
python docker/build.py                       # extprobe-local:base, extprobe-local:v3, extprobe-local:v3.1-probe
python docker/build.py --prefix mine         # other tag names
python docker/build.py --skip-probe          # base and v3 only
python docker/build.py --no-cache            # rebuild every layer
python docker/build.py --platform linux/amd64     # also the default if DOCKER_DEFAULT_PLATFORM is set
```

Needs Python 3 and Docker only (no PowerShell, no bash). The Dockerfiles in this folder are the frozen ones and start `FROM extprobe-sandbox:v2` / `:v3`; `build.py` does not edit them and does not use those tags: it feeds each Dockerfile to `docker build -f -` with the `FROM` line pointed at the image built in the previous step, and it refuses to build into `extprobe-sandbox`. It prints the commands it runs and the resulting image ids. Run with `extprobe analyze TARGET --image extprobe-local:v3` (`--probe --image extprobe-local:v3.1-probe` for probe mode).

The same thing by hand (Linux / macOS shell; each step needs the previous one):

```bash
docker build -f docker/Dockerfile.base -t extprobe-local:base sandbox/base
sed 's#^FROM extprobe-sandbox:v2#FROM extprobe-local:base#' docker/Dockerfile.v3    | docker build -f - -t extprobe-local:v3 sandbox/v3
sed 's#^FROM extprobe-sandbox:v3#FROM extprobe-local:v3#'   docker/Dockerfile.probe | docker build -f - -t extprobe-local:v3.1-probe sandbox/probe
```

A source build is functionally equivalent but has a different image id: local ids depend on the build (layer contents include the build context, `apt-get` packages are not pinned). What pins the build: the base-image digest in `Dockerfile.base`, `sandbox/base/requirements.v2.txt` (Playwright 1.63.0, websockets 12.0; Chrome for Testing 153.0.8010.12 comes with the Playwright base image) and the sha256 of every frozen file (`extprobe verify-freeze`). Needs internet: the base image comes from `mcr.microsoft.com`, plus apt and pip packages.

## `build.ps1` (Windows PowerShell, frozen tags)

`powershell -File docker/build.ps1` builds the three images **under the frozen tags** `extprobe-sandbox:v2`, `:v3`, `:v3.1-probe`. If you already have the frozen images, this replaces those tags with new builds of different ids; use `build.py` instead unless that is what you want. It prints the ids so that you can compare them with `PROVENANCE.md`.

## Notes

The Dockerfiles are byte-identical to the ones used for the evaluations; their header comments still show the old build commands. `Dockerfile.base` plants honeypot decoys on purpose (see the README).
