"""ENUM_JS (v31_explorer) in a real Chromium: labels of checkboxes / radios and the click decision (v31_policy).
Skipped when Playwright or its Chromium is not available (it runs in the probe image too)."""
import ast
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "sandbox" / "probe"
sys.path.insert(0, str(SRC))
from v31_policy import PRIORITY, priority, skip_reason  # noqa: E402

PAGE = """<!doctype html><html><body>
<label><input type="checkbox" id="c1"> Delete all history</label>
<input type="checkbox" id="c2"><label for="c2">Uninstall on exit</label>
<input type="checkbox" id="c3"><label for="c3">Enable blocking</label>
<label><input type="checkbox" id="c4">Activate</label>
<input type="checkbox" id="c5">
<input type="checkbox" id="c6" value="Connect">
<span id="lb">Turn on protection</span><input type="radio" id="r1" aria-labelledby="lb">
<input type="checkbox" id="c7" aria-label="Scan pages" title="ignored">
<input type="radio" id="r2" title="Start">
</body></html>"""


def enum_js():
    tree = ast.parse((SRC / "v31_explorer.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", None) == "ENUM_JS":
            return node.value.value
    raise AssertionError("ENUM_JS not found")


@pytest.fixture(scope="module")
def items():
    pw = pytest.importorskip("playwright.sync_api")
    try:
        with pw.sync_playwright() as p:
            b = p.chromium.launch(args=["--no-sandbox"])
            pg = b.new_page()
            pg.set_content(PAGE)
            snap = pg.evaluate(enum_js())
            ids = pg.evaluate("() => Array.from(document.querySelectorAll('[data-xp]')).map(e => [e.dataset.xp, e.id])")
            b.close()
    except Exception as e:                            # no browser binary on this host
        pytest.skip(f"chromium not available: {str(e)[:80]}")
    by_xp = dict(ids)
    return {by_xp[i["xp"]]: i for i in snap["items"]}


def test_destructive_checkboxes_not_clicked(items):
    assert items["c1"]["text"] == "Delete all history" and priority(items["c1"]) is None and skip_reason(items["c1"]) == "deny"
    assert items["c2"]["text"] == "Uninstall on exit" and priority(items["c2"]) is None and skip_reason(items["c2"]) == "deny"


def test_labelled_checkboxes_clicked_with_their_label(items):
    assert items["c3"]["text"] == "Enable blocking" and priority(items["c3"]) == PRIORITY.index("enable")      # <label for>
    assert items["c4"]["text"] == "Activate" and priority(items["c4"]) == PRIORITY.index("activate")           # wrapping <label>
    assert items["r1"]["text"] == "Turn on protection" and priority(items["r1"]) is not None                  # aria-labelledby
    assert items["c7"]["text"] == "Scan pages"                                                                # aria-label first
    assert items["r2"]["text"] == "Start" and priority(items["r2"]) == PRIORITY.index("start")                 # title last


def test_value_never_used_as_label(items):
    assert items["c5"]["text"] == "" and skip_reason(items["c5"]) == "unlabeled"     # default value "on"
    assert items["c6"]["text"] == "" and skip_reason(items["c6"]) == "unlabeled"     # value="Connect" is not a label
