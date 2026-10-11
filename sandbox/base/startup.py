"""Browser startup with pre-launch checks, per-step timeouts and bounded retry.

Why (diagnosed 2026-10 on the 13 corpus runs that ended with no phases): headed Chromium
shows a modal "Failed to load extension" dialog when --load-extension fails, and
launch_persistent_context then never returns. Two causes were confirmed:
  - the manifest's minimum_chrome_version is newer than the bundled Chromium (9 samples);
  - files the manifest references were deleted after unpacking (on a Windows host, the
    antivirus removed detected malicious JS from the bind-mounted output folder; 2 samples).
So: check both before launching and fail fast with a clear status; otherwise bound each
startup step with its own timeout and retry, and record every attempt in events["startup"].
Analysis phases and their budgets are not touched.
"""
import asyncio
import logging
import os
import re
import shutil
import subprocess
import time

from config import (PROFILE_DIR, REMOTE_DEBUG_PORT, PHASE_NAMES, LAUNCH_TIMEOUT_S,
                    PROBE_TIMEOUT_S, LAUNCH_ATTEMPTS, RETRY_BACKOFF_S)

logger = logging.getLogger(__name__)


def browser_version(executable_path):
    """(full version string, major) of the browser binary, e.g. ("Chromium 120.0.6099.28", 120)."""
    try:
        out = subprocess.run([executable_path, "--version"], capture_output=True, text=True,
                             timeout=15).stdout.strip()
        m = re.search(r"(\d+)\.\d+\.\d+", out)
        return out, (int(m.group(1)) if m else None)
    except Exception as e:
        logger.warning("startup: could not read browser version: %s", e)
        return None, None


def playwright_version():
    try:
        from importlib.metadata import version
        return version("playwright")
    except Exception:
        return None


def version_problem(manifest, major):
    required = str(manifest.get("minimum_chrome_version") or "")
    head = required.split(".")[0]
    if major is not None and head.isdigit() and int(head) > major:
        return f"extension requires Chromium {required}, sandbox has {major}"
    return None


def referenced_files(manifest):
    files = []
    bg = manifest.get("background") or {}
    files += [bg["service_worker"]] if bg.get("service_worker") else []
    files += list(bg.get("scripts") or [])
    files += [bg["page"]] if bg.get("page") else []
    for cs in manifest.get("content_scripts") or []:
        files += list(cs.get("js") or []) + list(cs.get("css") or [])
    return [f.lstrip("/") for f in files if isinstance(f, str)]


def missing_files(ext_dir, manifest):
    return [f for f in referenced_files(manifest) if not (ext_dir / f).is_file()]


def chromium_sandbox_wanted():
    """Chromium's own sandbox: requested by the image (SANDBOX_CHROMIUM_SANDBOX=1, set in
    Dockerfile.v2 only) and possible only when not running as root (Chromium refuses a
    sandboxed launch as root, e.g. smoke_test.py or SANDBOX_USER=root)."""
    return (os.environ.get("SANDBOX_CHROMIUM_SANDBOX") == "1"
            and hasattr(os, "geteuid") and os.geteuid() != 0)


def launch_args(ext_dir, chromium_sandbox=False):
    return [
        f"--disable-extensions-except={ext_dir}",
        f"--load-extension={ext_dir}",
        *([] if chromium_sandbox else ["--no-sandbox"]),
        "--disable-dev-shm-usage",
        "--disable-blink-features=AutomationControlled",
        f"--remote-debugging-port={REMOTE_DEBUG_PORT}",
    ]


def launch_kwargs(ext_dir):
    """Corpus launch call is unchanged; only a sandboxed launch adds chromium_sandbox=True."""
    sandboxed = chromium_sandbox_wanted()
    kw = {"user_data_dir": PROFILE_DIR, "headless": False,
          "args": launch_args(ext_dir, chromium_sandbox=sandboxed)}
    if sandboxed:
        kw["chromium_sandbox"] = True
    return kw, sandboxed


def _fail(events, reason, step, detail):
    events.setdefault("phases", [])
    events["startup"]["status"] = reason
    events["run_status"] = {"status": "failed", "reason": f"{reason}: {detail}",
                            "stuck_step": step, "phases_completed": 0,
                            "phases_total": len(PHASE_NAMES)}
    print(f"[Startup] FAILED {reason} at {step}: {detail}", flush=True)
    return reason


async def _first_page_ready(context):
    page = context.pages[0] if context.pages else await context.new_page()
    await page.evaluate("1")


async def run_with_startup(ext_dir, events, run_phases):
    """Launch the browser (checked, timed, retried) and hand the context to run_phases."""
    from playwright.async_api import async_playwright

    manifest = events.get("manifest") or {}
    st = events["startup"] = {"attempts": [], "status": "starting",
                              "profile": os.environ.get("SANDBOX_PROFILE"),
                              "playwright": playwright_version()}
    for attempt in range(1, LAUNCH_ATTEMPTS + 1):
        if attempt > 1:
            await asyncio.sleep(RETRY_BACKOFF_S[attempt - 2])
            shutil.rmtree(PROFILE_DIR, ignore_errors=True)
        missing = missing_files(ext_dir, manifest)
        if missing:
            return _fail(events, "extension_files_missing", "preflight",
                         f"{len(missing)} referenced file(s) not on disk after unpacking "
                         f"(e.g. removed by host antivirus): {missing[:5]}")
        rec = {"attempt": attempt}
        st["attempts"].append(rec)
        try:
            async with async_playwright() as p:
                if "browser_major" not in st:
                    st["browser_version"], st["browser_major"] = browser_version(
                        p.chromium.executable_path)
                    problem = version_problem(manifest, st["browser_major"])
                    if problem:
                        st["attempts"].pop()
                        return _fail(events, "incompatible_browser", "preflight", problem)

                kw, st["chromium_sandbox"] = launch_kwargs(ext_dir)
                events["_t0"] = time.monotonic()
                t = time.monotonic()
                try:
                    context = await asyncio.wait_for(
                        p.chromium.launch_persistent_context(**kw), timeout=LAUNCH_TIMEOUT_S)
                except Exception as e:
                    rec.update(step="launch", secs=round(time.monotonic() - t, 2),
                               status="timeout" if isinstance(e, asyncio.TimeoutError) else "error",
                               error=str(e).split("\n")[0][:150])
                    logger.warning("startup attempt %d: launch %s", attempt, rec["status"])
                    continue  # leaving async_playwright() kills the stuck browser
                rec["launch_secs"] = round(time.monotonic() - t, 2)

                t = time.monotonic()
                try:
                    await asyncio.wait_for(_first_page_ready(context), timeout=PROBE_TIMEOUT_S)
                except Exception as e:
                    rec.update(step="first_page", secs=round(time.monotonic() - t, 2),
                               status="timeout" if isinstance(e, asyncio.TimeoutError) else "error",
                               error=str(e).split("\n")[0][:150])
                    logger.warning("startup attempt %d: first page %s", attempt, rec["status"])
                    try:
                        await asyncio.wait_for(context.close(), timeout=10)
                    except Exception as ce:
                        logger.debug("startup: context.close after failed probe: %s", ce)
                    continue
                rec.update(status="ok", probe_secs=round(time.monotonic() - t, 2))
                st["status"] = "ok"
                await run_phases(context)
                return "ok"
        except asyncio.CancelledError:
            raise
        except Exception as e:
            if rec.get("status") == "ok":
                raise
            # Playwright can raise while tearing down after a cancelled launch
            logger.debug("startup attempt %d: teardown error ignored: %s", attempt, e)

    last = st["attempts"][-1] if st["attempts"] else {}
    reason = "no_page_loaded" if last.get("step") == "first_page" else "launch_failed"
    return _fail(events, reason, last.get("step", "launch"),
                 f"{LAUNCH_ATTEMPTS} attempts, last: {last.get('status')} after {last.get('secs')}s")
