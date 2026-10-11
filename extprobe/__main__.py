"""python -m extprobe <command>: analyze, verify-freeze, score-v3, score-v31."""
import runpy
import sys

from extprobe import paths


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    root = paths.setup()
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: python -m extprobe {analyze TARGET | verify-freeze | score-v3 ARGS... | score-v31 ARGS...}\n"
              "  analyze TARGET     [--probe] [--out DIR]: sandbox run + score + report.html/report.json (TARGET: .crx or unpacked dir)\n"
              "  verify-freeze      check the frozen files against PROVENANCE/frozen_files.tsv (sha256)\n"
              "  score-v3 ARGS      run scoring/v3/score_v3.py unchanged (--traces DIR [--samples DIR] [--out FILE])\n"
              "  score-v31 ARGS     run scoring/probe/score_v31.py (--traces DIR ...)\n"
              )
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd == "verify-freeze":
        from extprobe.verify_freeze import main as vf
        return vf(rest)
    if cmd in ("score-v3", "score-v31"):
        script = root / "scoring" / ("v3" if cmd == "score-v3" else "probe") / ("score_v3.py" if cmd == "score-v3" else "score_v31.py")
        sys.argv = [str(script), *rest]
        runpy.run_path(str(script), run_name="__main__")
        return 0
    if cmd == "analyze":
        from extprobe.analyze import main as an
        return an(rest)
    print(f"extprobe: unknown command '{cmd}' (see --help)")
    return 2


if __name__ == "__main__":
    sys.exit(main())
