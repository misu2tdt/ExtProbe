# Held-out benign test set: selection criteria (committed BEFORE any v3 dev result exists)
Purpose: measure the false-positive rate of the FROZEN v3 tool on benign extensions never used during development.
- Source and procedure: identical to eval/benign_ext/CRITERIA.md (same store, same categories, same grey rule).
- Exclusions: any extension ID in the 256 development benign_ext set, the 41 legacy benign samples, or the 313 malware.
- Size: target 200 (minimum 150), stratified by the same categories as the development set, seeded random sample
  (seed 2027) from candidates satisfying the criteria; if the existing candidate pool is too small, extend it with
  the same listing procedure and record the date.
- The final ID list + SHA-256 is committed BEFORE the first test run. Labels (benign/grey) assigned from the listing
  BEFORE the run, never after.
- The test set is run exactly once, after tag v3.0-freeze, and scored with both v2.0 and v3 rules.
  Results are reported whatever they are.
