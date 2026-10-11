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
