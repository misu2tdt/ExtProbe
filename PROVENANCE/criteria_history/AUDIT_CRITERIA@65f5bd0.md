# v3 dev audit: criteria (committed before any sample is examined)

Purpose: (1) check that the v3 true positives fire on real malicious behaviour; (2) explain the v3
false negatives and estimate how much recall Tier-2 scoring could still recover.

Not changed by this audit: `sandbox_v3/`, the image, `eval/v3/score_v3.py`, the labels (manifest,
verified labels). Proposed labels are recorded only in `eval/v3/audit/`.

## Samples

Population: the v3 dev run (`eval/v3/dev/`). Labels and scores exactly as `eval/v3/dev/results.md`:
folder `malware`, final (verified) label `malicious`, `run_status == complete`, v3 score from
`score_v3.py` (the pre-registered rules with amendment 1).
- **TP**: all such samples with v3 score ≥ 40 (41 expected).
- **FN**: 40 drawn from the samples with v3 score < 40, with `random.Random(42).sample(sorted(ext_ids), 40)`.
Selection is done by `eval/v3/audit/select.py`, and its output list is committed before any review.

## Evidence (per sample)

- **Source code**: the `.crx` is unpacked into a temporary folder outside the repository. Each
  finding is cited as `file:line`. Minified code is cited by file and a short distinctive
  snippet (≤ 80 characters).
- **v3 trace**: extension-initiated requests and their initiator, tabs and redirect chains,
  `setUninstallURL`, network errors (DNS / HTTP status / failed loads), SW responses.
- **Manifest**: permissions, host permissions, content scripts, `externally_connectable`,
  `update_url`, CSP.
- **ExtProbe scores and detector outputs are NOT evidence.** For a TP, the detector that fired is
  named, then checked against the code and trace.

## Proposed label (one per sample)

- **malicious-confirmed**: the code clearly does one of the following: collects or sends user
  data (browsing history, page content, credentials, cookies) without it being the
  advertised function; downloads and runs remote code (`eval`, `new Function`, remote script
  injection, remote rule sets driving behaviour); hijacks search or new tab against the
  declared purpose; injects ads or affiliate links; opens tabs to C2 / scam / monetised
  redirect chains.
- **malicious-likely**: the same capability is present and wired up, but it depends on a
  server response not seen, or is partly obfuscated, so the effect cannot be fully confirmed.
- **grey/PUP**: aggressive monetisation or tracking that is disclosed or tied to the stated
  function (install / uninstall tracking pages, own analytics, bundled offers), with no harmful
  capability.
- **benign-looking**: the code does only what the extension says it does. Nothing above is found.
- **inconclusive**: not enough code to judge (heavily obfuscated, or the package depends on remote
  code that is unavailable), or the evidence is contradictory.

## FN cause group (FN only)

- **A, silent**: the malicious code path exists but did not run or was not visible in the run.
  The C2 / config server is dead or gives no useful reply, the code waits for a command / time
  delay / user action / a site the harness did not visit. Evidence from the trace is needed:
  DNS failure, HTTP error, empty or short response, no request at all, a timer value in the code.
- **B, behaviour seen but scored low**: the trace contains the malicious behaviour (or a
  distinctive part of it), but the v3 rules give < 40. Record which signals fired and what was
  missing, which trace feature would have separated it (tab / redirect / `setUninstallURL` / host /
  request content), and how common that feature is in the benign sets (rates from
  `eval/v3/explore/tables.md`).
- **C, label probably wrong**: proposed label benign-looking or grey/PUP.
- **D, run problem**: the run did not exercise the extension properly (crash, SW never started,
  load error, timeout) although `run_status` is complete.

One group per FN. Precedence when several apply: D > C > B > A.

## Synthesis

- Counts of the proposed labels (TP, FN) and of the groups A / B / C / D, with Wilson 95 % intervals.
- Extrapolation to all FN (237 expected): proportion × N, with the Wilson interval × N.
- Realistic Tier-2 recall ceiling: (current TP + estimated B among the FN) / positives. A sample
  in C is not counted as recoverable.
- `eval/v3/audit/spotcheck.md`: 10 rows drawn with `random.Random(7)` from the 81 reviewed rows,
  for an independent manual check.
- IPs, tokens and keys are redacted in every committed file.
