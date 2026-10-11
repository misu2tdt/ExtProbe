import asyncio
import time
import os
from config import PHASE_NAMES


def _phase_budget(name, default):
    """Ngan sach phase, cho phep override qua bien moi truong (khong can rebuild)."""
    try:
        return int(os.environ.get(f"PHASE_BUDGET_{name.upper()}", default))
    except ValueError:
        return default


async def _run_phase(name, coro, budget_s, events):
    """Boc mot phase: cap ngan sach, bat loi/timeout, ghi trang thai."""
    rec = {"name": name, "status": "running", "budget_s": budget_s,
           "t_start": round(time.monotonic() - events["_t0"], 2), "t_end": None, "reason": None}
    events["phases"].append(rec)
    events["_current_phase"] = name          # de sensor gan "phase" vao event
    try:
        await asyncio.wait_for(coro, timeout=budget_s)
        rec["status"] = "completed"
    except asyncio.TimeoutError:
        rec["status"] = "timed_out"
        rec["reason"] = f"vuot ngan sach {budget_s}s"
    except Exception as e:
        rec["status"] = "failed"
        rec["reason"] = str(e)[:150]
    finally:
        rec["t_end"] = round(time.monotonic() - events["_t0"], 2)
    print(f"[Phase] {name}: {rec['status']} "
          f"({rec['t_start']}s - {rec['t_end']}s)", flush=True)
    return rec["status"]


def _finalize_run_status(events):
    """Suy ra run_status tong tu trang thai cac phase."""
    phases = events.get("phases", [])
    by = {p["name"]: p for p in phases}
    load = by.get("load")
    completed = sum(1 for p in phases if p["status"] == "completed")
    if load and load["status"] == "failed":
        status, reason = "failed", "load failed: " + (load.get("reason") or "")
    elif len(phases) == len(PHASE_NAMES) and all(p["status"] == "completed" for p in phases):
        status, reason = "complete", None
    else:
        bad = [p["name"] for p in phases if p["status"] in ("timed_out", "failed", "skipped")]
        status, reason = "partial", ", ".join(f"{n} {by[n]['status']}" for n in bad)
    events["run_status"] = {"status": status, "reason": reason,
                            "phases_completed": completed,
                            "phases_total": len(PHASE_NAMES)}
    print(f"[Run] status={status} ({completed}/{len(PHASE_NAMES)} phases) reason={reason}",
          flush=True)
