# Reproduce the tests

Use a disposable extraction with synthetic data. Tests make temporary files, launch bounded Python child processes and, on Windows, create the listed local link/probe structures. They require no administrator privileges and do not enable live agent execution or network access.

Run at the extracted project root. Each runner sets the import path for this exact source, retains a JSON result and a text log, and returns nonzero on failures or errors. The original runner fixes AST_TEST_SEED=20261102 and AST_FUZZ_N=2000. Keep the printed seed when investigating any randomized failure.

```text
python tools/run_full_suite.py --source . --output test-output/original
python tools/run_muse_evidence.py --source . --test review_tests/test_toolkit_adversarial.py --output test-output/adversarial
python tools/run_muse_evidence.py --source . --test review_tests/test_muse_followup.py --output test-output/muse-followup
python tools/run_muse_evidence.py --source . --test review_tests/test_public_release.py --output test-output/release
```

On Windows also run:

```text
python tools/run_muse_evidence.py --source . --test review_tests/test_toolkit_windows_review.py --output test-output/native
```

| Suite | Scope |
|---|---|
| Original tests | JSON, policy/path validation, approvals, audit, gate, CLI, hygiene, native reader/probe. |
| Earlier adversarial tests | Short writes, concurrent replay/appends, malformed MACs/anchors, deep path patterns, invalid scenarios, documented rollback. |
| Muse followups | Source-claim reproductions, state capacity, action digest, TTL, error redaction and unexpected-exception classification. Observation tests pin documented limitations rather than claiming they are repaired. |
| Public release tests | Hostile/corrupt ZIPs, external/internal checksum checks, path/member bounds, command resolution and real Windows hostile-working-directory regression. |
| Native fault injection | Enrollment/identity/content checks, orphan hardlinks, handle cleanup and close/read concurrency. |

Windows symlinks may be unavailable without extra rights; do not change privileges to turn a skip into a pass. Linux native tests skip. Races are bounded/probabilistic. Mocked I/O faults are marked in the test source and are not native exploit demonstrations. The actual bad-cmd test uses a harmless invalid text file, not executable malicious code.

Recovered R1 historical evidence: 219 overlapping Windows/Linux executions, 208 passes, 11 skips, no failures/errors. Those counts do not automatically apply to this rc6 archive. Fresh rc6 builder results are supplied in the private QC evidence, with separate failure/error/skip counts and exact manifests. Vex acceptance remains pending.

Release ZIP validation, after the verifier itself is trusted:

```text
python tools/verify_release.py ARCHIVE --sha256 EXPECTED_64_HEX_DIGEST
```

This is read-only. Get EXPECTED_64_HEX_DIGEST externally; an attacker can replace both an untrusted file and its internal manifest. SHA-256 is not an authorship signature. Publication must use the exact hash accepted for distribution.

Final builder QC: `python tools/run_muse_evidence.py --source . --test review_tests/test_final_security.py --output test-output/final-security`. Three of its tests explicitly observe documented rollback, instance-local action IDs and incomplete report pairs; passing them does not claim those limitations are repaired. Mock CloseHandle failures do not induce real OS cleanup faults.

rc7 follow-ups run in review_tests/test_final_security.py alongside the retained rc6 regressions. Its independent EXPECTED_RELEASE_PATHS literal pins all 58 content paths, excluding the generated source manifest itself. Dropped or added members fail this test even when a modified ZIP self-verifies. The probe's zero-substitution root race is an explicit coverage skip. Native intermediate-directory rename coverage still requires Windows and NTFS fixtures.

rc8 cleanup, atomic audit-write and metadata regressions:

```text
python tools/run_muse_evidence.py --source . --test review_tests/test_rc8_cleanup.py --output test-output/rc8-cleanup
```

The modeled tests cover first, middle, last and multiple release failures, primary
security/OS/BaseException preservation, and unchanged success. Windows tests use
real handles but inject a reporting fault after a successful actual close; they
do not induce real OS close failures. The private campaign separately records
audit seeds, every verifier result and failure snapshots before fixture teardown.
The ancestor substitution probe reports actual setup success or an explicit skip;
it never reclassifies the direct-root zero-swap race as exercised.
