"""The three report levels, and their use on the output of the (unchanged) score-v3 / score-v31 scripts.

score >= 40 "Flagged for review", 15-39 "Review suggested", < 15 "No notable behavior observed". The scoring scripts still print
their legacy severity names (CRITICAL / HIGH / MEDIUM / LOW / MINIMAL); the CLI rewrites those lines, the scripts are not touched.
"""
import contextlib
import io
import re
import runpy
import sys

FLAG_AT, REVIEW_AT = 40, 15
LABELS = ("Flagged for review", "Review suggested", "No notable behavior observed")

_V3_LINE = re.compile(r"^(?P<name>.*?) +(?P<score>\d{1,3}) (?P<level>CRITICAL|HIGH|MEDIUM|LOW|MINIMAL) *(?P<fired>.*)$")
_V31_LINE = re.compile(r"^(?P<head>.*): v3 (?P<v3>\d+) -> v3\.1 (?P<v31>\d+) \|")


def label_of(score):
    return LABELS[0] if score >= FLAG_AT else LABELS[1] if score >= REVIEW_AT else LABELS[2]


def relabel_v3_line(line):
    """'<name> <score> <LEGACY> <detectors>' -> '<name> <score> <label> (legacy: <LEGACY>) <detectors>'."""
    m = _V3_LINE.match(line)
    if not m:
        return line
    return f"{m['name']:34s} {int(m['score']):3d} {label_of(int(m['score']))} (legacy: {m['level']}) {m['fired']}".rstrip()


def relabel_v31_line(line):
    """Append the level of the v3.1 score to '<name>: v3 a -> v3.1 b | ...'."""
    m = _V31_LINE.match(line)
    return f"{line} | level: {label_of(int(m['v31']))}" if m else line


def run_scoring(script, args, relabel):
    """Run a scoring script unchanged and print its output with `relabel` applied to every line."""
    buf = io.StringIO()
    old = sys.argv
    sys.argv = [str(script), *args]
    try:
        with contextlib.redirect_stdout(buf):
            runpy.run_path(str(script), run_name="__main__")
    finally:
        sys.argv = old
        print("\n".join(relabel(l) for l in buf.getvalue().splitlines()), flush=True)
    return 0
