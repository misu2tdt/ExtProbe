# ExtAnalysis qualitative baseline

`comparison.md` compares [ExtAnalysis](https://github.com/Tuhinshubhra/ExtAnalysis)
(static) with ExtProbe (dynamic) on 3 case-study samples from `samples/malware/`.
It is qualitative only and does not feed any paper number.

**Warning:** ExtAnalysis resolves every domain it extracts with
`socket.gethostbyname` (`core/analyze.py:335`). Running it on these samples sends
DNS queries for the malware's C2 domains from your machine. Run it on an isolated
host or network if that matters to you.

## Reproduce

ExtAnalysis commit `9f2ed5b` (2026-02-17), Python 3.11, VirusTotal disabled (no API key):

```bash
git clone https://github.com/Tuhinshubhra/ExtAnalysis.git ../baseline_extanalysis
git -C ../baseline_extanalysis checkout 9f2ed5b
python -m venv ../baseline_extanalysis/.venv
../baseline_extanalysis/.venv/bin/python -m pip install -r ../baseline_extanalysis/requirements.txt
```

(Use `.venv\Scripts\python.exe` instead of `.venv/bin/python` with a standard
Windows Python; MSYS2 Python creates `bin/`.)

Then either upload each `.crx` through the web UI (`python extanalysis.py`,
http://127.0.0.1:13337), or call the analysis function the UI uses, from inside
`../baseline_extanalysis`:

```python
import sys; sys.argv = ["extanalysis.py", "-n"]
import extanalysis, core.settings as settings, core.analyze as analysis
settings.init_settings()
print(analysis.analyze("/abs/path/to/samples/malware/<ext_id>.crx", "local"))
# report: ../baseline_extanalysis/reports/<EXA id>/extanalysis_report.json
# page:   extanalysis.app.test_client().get("/analysis/<EXA id>").data
```

Samples: `akkkopcadaalekbdgpdikhdablkgjagd`, `nigamacoibifjohkmepefofohfedblgg`,
`jacilgchggenbmgbfnehcegalhlgpnhf`.

## What is and is not committed

Only `comparison.md` and this README. The per-sample ExtAnalysis outputs
(`<ext_id>/extanalysis_report.json`, `analysis.html`, `source.json`, `graph.data`,
`extanalysis_log.txt`) are gitignored because they embed verbatim fragments of the
extensions' JavaScript (extracted comments and string literals). Regenerate them
with the steps above.
