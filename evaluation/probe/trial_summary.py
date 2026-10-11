"""trial_summary.py -- one status line per trace of a run_probe.ps1 -Trial run (no id is printed).

  py eval/v3_1_probe/trial_summary.py <traces dir>
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import score_v31 as V  # noqa: E402


def main():
    root = Path(sys.argv[1])
    for k, d in enumerate(sorted(p for p in root.iterdir() if p.is_dir() and not p.name.startswith("_")), 1):
        evp = d / "output" / "events.json"
        if not evp.exists():
            print(f"trial sample {k}: no events.json")
            continue
        pre = json.loads(evp.read_text(encoding="utf-8"))
        pp = d / "output" / "events_probe.json"
        post = json.loads(pp.read_text(encoding="utf-8")) if pp.exists() else {}
        r = V.score_run(pre, post)
        pr = r["probe"]
        print(f"trial sample {k}: run_status={(pre.get('run_status') or {}).get('status')} probe_file={bool(post)} "
              f"pages_opened={pr['pages_opened']} clicks={pr['clicks']} login_gate={pr['login_gate']} yield={pr['yield']} "
              f"extra_s={pr['extra_s']} score v3={r['v3_score']} v3.1={r['v31_score']} "
              f"policy_in_force={pr['policy_in_force']} proxy_unwrapped_set={pr['proxy_unwrapped_set']} "
              f"proxy_set_calls={pr['proxy_set_calls']}")


if __name__ == "__main__":
    main()
