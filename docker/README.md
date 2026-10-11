# docker/

Build order (the images are layered; the context of each build is the matching `sandbox/` folder):

```bash
docker build -f docker/Dockerfile.base  -t extprobe-sandbox:v2        sandbox/base
docker build -f docker/Dockerfile.v3    -t extprobe-sandbox:v3        sandbox/v3
docker build -f docker/Dockerfile.probe -t extprobe-sandbox:v3.1-probe sandbox/probe
```

or `powershell -File docker/build.ps1`. The Dockerfiles are byte-identical to the ones used for the evaluations (their header comments still
show the old build commands). Local image ids are not reproducible: see `PROVENANCE.md` for the ids that were used and what pins the builds
(base-image digest, `requirements.v2.txt`). `Dockerfile.base` plants honeypot decoys on purpose (see README).
