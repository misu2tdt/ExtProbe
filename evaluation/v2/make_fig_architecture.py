"""
make_fig_architecture.py -- Figure 1: two-tier architecture.
Tier-1 (Sandbox: 5 phases + 7 sensors)  ->  events.json  ->  Tier-2 (Worker: 6 detectors +
scoring + MITRE)  ->  report.

Drawn with matplotlib (no graphviz). Black-and-white, print-safe.
Output: eval/results/fig_architecture.png (dpi 300) + fig_architecture.pdf (vector).

Run: py -3 eval/make_fig_architecture.py
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

# --- global style: clean sans-serif, thin uniform strokes, grayscale ---
plt.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["DejaVu Sans", "Arial", "Helvetica", "Liberation Sans"],
    "svg.fonttype": "none",
    "axes.linewidth": 0.8,
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
})

REPO = Path(__file__).resolve().parents[2]
RESULTS_DIR = Path(__import__("os").environ.get("EXTPROBE_V2_RESULTS") or REPO / "data" / "v2_results")   # recorded traces (release asset) go here
RESULTS = RESULTS_DIR

FS_TITLE = 10.5
FS_HEAD = 9.5
FS_BODY = 8.0
FS_SMALL = 7.3

LW_FRAME = 1.1      # tier frames
LW_GROUP = 0.9      # group boxes
LW_ITEM = 0.7       # leaf boxes
LW_ARROW = 1.2      # stage arrows
LW_ARROW_IN = 0.9   # internal arrows


def box(ax, x, y, w, h, lw=LW_ITEM, fc="white", ls="round,pad=0.02"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle=ls, linewidth=lw,
                                edgecolor="black", facecolor=fc))


def arrow(ax, x0, y0, x1, y1, lw=LW_ARROW, color="black"):
    ax.add_patch(FancyArrowPatch((x0, y0), (x1, y1), arrowstyle="-|>",
                                 mutation_scale=15, linewidth=lw, color=color))


def main():
    fig, ax = plt.subplots(figsize=(14.0, 7.0))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 68)
    ax.axis("off")

    # ---------------- CRX in ----------------
    box(ax, 1, 41, 9, 7, lw=LW_GROUP, fc="0.92")
    ax.text(5.5, 44.5, "CRX\n(.crx)", ha="center", va="center", fontsize=FS_BODY, weight="bold")

    # ---------------- TIER 1: SANDBOX ----------------
    box(ax, 12, 3, 33, 62, lw=LW_FRAME, fc="0.985")
    ax.text(28.5, 62.0, "TIER 1 - SANDBOX  (ephemeral container)",
            ha="center", va="center", fontsize=FS_TITLE, weight="bold")
    ax.text(28.5, 59.2, "Chromium + Playwright headful (Xvfb) | CDP attach SW",
            ha="center", va="center", fontsize=FS_SMALL, style="italic")

    # 5 phases
    box(ax, 14, 41, 29, 15, lw=LW_GROUP, fc="0.94")
    ax.text(28.5, 53.7, "5 PHASES (sequential, time-budgeted)",
            ha="center", va="center", fontsize=FS_HEAD, weight="bold")
    phases = ["load", "honeypot_pages", "target_matched", "extension_pages", "delayed_observation"]
    for i, p in enumerate(phases):
        px = 15 + i * 5.7
        box(ax, px, 43, 5.2, 7.2, lw=LW_ITEM, fc="white")
        ax.text(px + 2.6, 46.6, p.replace("_", "\n"), ha="center", va="center",
                fontsize=FS_SMALL)
        if i < 4:
            ax.annotate("", xy=(px + 5.7, 46.6), xytext=(px + 5.2, 46.6),
                        arrowprops=dict(arrowstyle="-|>", lw=LW_ARROW_IN))

    # 7 sensors
    box(ax, 14, 7, 29, 30, lw=LW_GROUP, fc="0.94")
    ax.text(28.5, 34.6, "7 SENSORS  (attached at load, span all phases)",
            ha="center", va="center", fontsize=FS_HEAD, weight="bold")
    sensors = [
        "S1  Network + payload (page, Playwright)",
        "S2  Network service worker (CDP raw, MV3)",
        "S3  Deep payload inspection (honeypot marker)",
        "S4  Tab / window monitor (new_tabs + phase)",
        "S5  DOM mutation observer (SCRIPT/IFRAME/FORM)",
        "S6  Extension storage dump (LevelDB, after close)",
        "S7  Chrome API-call capture in SW (CDP hook)",
    ]
    for i, s in enumerate(sensors):
        sy = 31.0 - i * 3.4
        box(ax, 15, sy - 1.35, 27, 2.7, lw=LW_ITEM, fc="white")
        ax.text(16, sy, s, ha="left", va="center", fontsize=FS_SMALL)

    # ---------------- events.json ----------------
    box(ax, 47.5, 15, 12.5, 34, lw=LW_GROUP, fc="0.9")
    ax.text(53.75, 46.4, "events.json", ha="center", va="center", fontsize=FS_HEAD,
            weight="bold")
    ax.text(53.75, 43.9, "(written incrementally)", ha="center", va="center", fontsize=FS_SMALL,
            style="italic")
    fields = ["manifest", "network_requests[]", "new_tabs[] / navigations[]",
              "dom_activity[]", "service_workers[]", "extension_storage",
              "request_provenance{}", "honeypot_exfil", "api_calls[]",
              "phases[] / run_status"]
    for i, f in enumerate(fields):
        ax.text(48.4, 40.5 - i * 2.4, "- " + f, ha="left", va="center",
                fontsize=FS_SMALL - 0.3)

    # ---------------- TIER 2: WORKER ----------------
    box(ax, 62, 3, 30, 62, lw=LW_FRAME, fc="0.985")
    ax.text(77, 62.3, "TIER 2 - WORKER  (offline, no Docker/Playwright)",
            ha="center", va="center", fontsize=FS_TITLE, weight="bold")
    ax.text(77, 59.5, "worker/risk.py : reads events.json  ->  build_behavioral_report",
            ha="center", va="center", fontsize=FS_SMALL, style="italic")

    # 6 detectors
    box(ax, 64, 28, 26, 28, lw=LW_GROUP, fc="0.94")
    ax.text(77, 53.7, "6 DYNAMIC DETECTORS  (+ static signals)",
            ha="center", va="center", fontsize=FS_HEAD, weight="bold")
    dets = [
        "credential_exfil        -> T1041 (CRITICAL)",
        "local_harvest           -> T1074.001 (HIGH)",
        "script_injection        -> T1059.007 (HIGH)",
        "beaconing               -> T1071.001 (MEDIUM)",
        "undeclared_domain_contact -> T1071 (MEDIUM)",
        "unsolicited_tab         -> (no ATT&CK mapping)",
    ]
    for i, d in enumerate(dets):
        dy = 50.5 - i * 3.5
        box(ax, 65, dy - 1.4, 24, 2.8, lw=LW_ITEM, fc="white")
        ax.text(65.8, dy, d, ha="left", va="center", fontsize=FS_SMALL - 0.3)
    ax.text(77, 29.7, "static: overprivileged | suspicious host | broad injection",
            ha="center", va="center", fontsize=FS_SMALL - 0.5, style="italic")

    # scoring + MITRE
    box(ax, 64, 6, 26, 18, lw=LW_GROUP, fc="0.94")
    ax.text(77, 21.6, "SCORING  +  MITRE ATT&CK", ha="center", va="center",
            fontsize=FS_HEAD, weight="bold")
    ax.text(77, 18.4, "static_score  (+)  dynamic_score", ha="center", va="center",
            fontsize=FS_SMALL)
    ax.text(77, 15.8, "risk = max(s,d) + 0.3*min(s,d)   (static capped when dynamic low)",
            ha="center", va="center", fontsize=FS_SMALL - 0.5)
    ax.text(77, 13.0, "level: MINIMAL / LOW / MEDIUM / HIGH / CRITICAL",
            ha="center", va="center", fontsize=FS_SMALL - 0.5)
    ax.text(77, 9.6, "build_findings(): labels ATT&CK techniques\non observed signals",
            ha="center", va="center", fontsize=FS_SMALL - 0.5)

    # ---------------- report ----------------
    box(ax, 93.2, 27, 6.4, 14, lw=LW_GROUP, fc="0.9")
    ax.text(96.4, 34, "report\n\nrisk\nlevel\nindicators\nfindings\n(MITRE)",
            ha="center", va="center", fontsize=FS_SMALL - 0.3, weight="bold")

    # ---------------- arrows between stages ----------------
    arrow(ax, 10, 44.5, 12, 44.5)          # CRX -> Tier1
    arrow(ax, 45, 32, 47.5, 32)            # Tier1 -> events.json
    arrow(ax, 60, 32, 62, 32)              # events.json -> Tier2
    arrow(ax, 90, 42, 93.2, 35)            # detectors -> report
    # phase -> sensor (internal Tier1)
    ax.annotate("", xy=(28.5, 37), xytext=(28.5, 41),
                arrowprops=dict(arrowstyle="-|>", lw=LW_ARROW_IN, color="0.35"))
    # detector -> scoring (internal Tier2)
    ax.annotate("", xy=(77, 24), xytext=(77, 28),
                arrowprops=dict(arrowstyle="-|>", lw=LW_ARROW_IN, color="0.35"))

    ax.text(50, 1.6,
            "Three independent modules: api/ | worker/ | sandbox/  -  worker does not import "
            "sandbox; they communicate via events.json (shared volume)",
            ha="center", va="center", fontsize=FS_SMALL - 0.5, style="italic")

    fig.tight_layout()
    RESULTS.mkdir(parents=True, exist_ok=True)
    for ext, dpi in (("png", 300), ("pdf", 300)):
        out = RESULTS / f"fig_architecture.{ext}"
        fig.savefig(out, dpi=dpi, bbox_inches="tight")
        print(f"  wrote {out}  ({out.stat().st_size // 1024} KB)")
    plt.close(fig)


if __name__ == "__main__":
    main()
