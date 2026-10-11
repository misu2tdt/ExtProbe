# extprobe-sandbox:v3.1-probe

| | value |
|---|---|
| image | `extprobe-sandbox:v3.1-probe` |
| local image id | `sha256:67d0ebe6765aa9a63723e58f4175dfc98a2bca05c631b111269e3e9ce436bdb4` (trial image, rebuilt after the second review of 2026-10-11) |
| base | `extprobe-sandbox:v3` = `sha256:0e4016d18022e9c6d797499c460dfb2ac7ab93594cbed9af6a70afdf1d360337` (`eval/v3/IMAGE.md`, frozen) |
| added | `/sandbox/v31/` (= `sandbox_v3_1_probe/` at the commit that records this id), entrypoint `/sandbox/v31/entrypoint_v31.sh`, managed Chrome policy `/etc/opt/chrome_for_testing/policies/managed/extprobe_proxy.json` = `{"ProxyMode": "direct"}` (root, 0644) |
| run | same `docker run` limits and capabilities as v3 (no `NET_ADMIN`; `eval/v3_1_probe/run_probe.py`) |
| build | `docker build -t extprobe-sandbox:v3.1-probe sandbox_v3_1_probe` |
| superseded | `sha256:8348c13a…` (iptables egress gate, commit `e5078b2`) and `sha256:2ae86e6e…` (before review 2): never used for the trial |

`run_probe.ps1` refuses to run if the local image id differs from the one recorded here, or if the policy file in the
image is missing or different.
