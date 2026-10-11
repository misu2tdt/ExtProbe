# extprobe-sandbox:v3

| | value |
|---|---|
| image | `extprobe-sandbox:v3` |
| local image id | `sha256:0e4016d18022e9c6d797499c460dfb2ac7ab93594cbed9af6a70afdf1d360337` (round 3: A1–A4 + request source, hook source, node outerHTML, storage UUIDs; image for the dev run) |
| base | `extprobe-sandbox:v2` = `sha256:ffeebda9a77c630a3d9c19a51b7e01b390fcddf1fec99340cb66900ca6d7b45d` (FREEZE.md §2; checked by `build_v3.ps1`) |
| browser | Playwright 1.63.0 / Chrome for Testing 153.0.8010.12 (inherited) |
| added | `/sandbox/v3/` (= `sandbox_v3/`), `SANDBOX_PROFILE=v3`, entrypoint `/sandbox/v3/entrypoint_v3.sh` |
| build | `powershell -ExecutionPolicy Bypass -File eval\v3\build_v3.ps1` |

Local image ids depend on the build. Reproducibility rests on the frozen v2 image plus the
`sandbox_v3/` sources at the commit that records this file.
