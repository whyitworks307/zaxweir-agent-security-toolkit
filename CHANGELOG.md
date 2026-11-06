# 0.5.0rc8 — cleanup/audit repairs and approved metadata; public release HOLD

- AR-04: attempt all held handle releases; preserve the primary exception and
  fail closed on cleanup failure. Add modeled and real-handle reported-fault
  regressions covering multiple held handles.
- Replace obsolete draft license/notice files with NOTICE and LICENSING_STATUS.md;
  incorporate owner-approved Apache-2.0 metadata, Christopher Wright / 2026, and
  verified founder@zaxweir.com daily monitoring. Wheel/license/SBOM metadata agree.
- Add deterministic ancestor namespace-substitution coverage without weakening
  the root pin; keep direct-root and unavailable-symlink skips explicit.
- Reproduce an audit log/anchor split and trace FileExistsError to the reused
  PID-based atomic-write temporary. Use a fresh exclusive sibling per update
  and remove owned temporaries on failed writes. Add collision, short-write,
  fsync and replace-failure regressions; preserve existing symlink protection.
  The original rc7 incident lacks a trace proving an identical cause. True I/O
  failures still fail closed and may require operator review; no crash-atomic
  log/anchor transaction is claimed.
- Preserve provenance evidence limits. Current maintenance is not an independent
  clean-room rewrite.
- Regenerate the pinned source inventory and package under a separate rc8 identity.
  No frozen rc6/rc7 modification, public release, or owner re-signing.

# 0.5.0rc7 — four Vex follow-ups, private candidate

- F1: zero-substitution root-swap runs are skips with passed=false. Record root rename failures and add a separate intermediate-directory rename denial check. Correct the threat-matrix coverage claim.
- F2: scenario IDs reuse full-string policy identifier validation.
- F3: in-tree tests pin the exact 58 content paths independently of the generator and manifest.
- F4: document fsprobe, its pinned system interpreter, scope and symlink privilege gap.
- Preserve rc6 and all license/notice files. Public release remains on hold pending the existing owner and independent review gates.

# 0.5.0rc6 — final builder QC repairs (private candidate)

- Require full-string policy/tool/approver/action identifiers, rejecting terminal newlines. The gate still never executes tools.
- Require integer policy and scenario schema versions; booleans and floats are invalid.
- Check the Windows close result before counting success; explicit cleanup failure denies and invalidates the pin. Controlled API fault injection is separate from native exploit evidence.
- Add 64 bounded synthetic final-QC checks, including documented limitation observations.
- Align the release generator with its own verifier: canonical source root/name, complete review/docs inventory and internal source manifest. Repeated output is tested for reproducibility.
- The frozen rc5 archive is preserved separately. Rights, owner licensing approval, private-channel monitoring and independent exact-artifact acceptance remain release gates.

# Changelog

## 0.5.0rc5 — private public-release-preparation candidate, 2026-11-02

Parent: exact recovered AST_RC4_MUSE_REPAIR_R1_20261102.zip, SHA-256 b4ea1db7895275ed704d29c7dfee870d867a1c28d67f638f8f82060f8139898f, internal version 0.5.0rc4. R1 was recovered intact, not reconstructed, and remains unchanged.

- Confirmed Muse F12's command-search concern on Windows using an invalid synthetic cmd.exe in the working directory; the clean-directory junction control succeeded. Resolve the system command through GetSystemDirectoryW and fail closed on lookup failure. A separate valid ampersand-path reproduction exposed command-argument parsing; quote pathname data, disable AutoRun/delayed expansion for this child process, and reject percent-expansion/invalid command-path inputs. No malicious executable, privilege change or live agent action was used.
- Assign a distinct 0.5.0rc5 version and proposed v0.5.0rc5 tag. This is not the R1 hash or an accepted release.
- Replace stale wheel-install examples with source-based offline instructions; retain original tests and ship the earlier adversarial/Muse regression tests with reproducible runners.
- Add bounded read-only source-archive verification and malformed-archive/command-resolution tests.
- Prepare canonical Apache-2.0 license text, source/dependency manifests, checksums and clear documentation. Copyright holder, native provenance, security reporting and distribution approval remain open; no licensing clearance is claimed.

R1 inherited repairs addressed concurrent approval consumption, short writes, unsafe/deep patterns, malformed data, state-file bounds, approval TTL, action-digest audit records, exception redaction, native-handle cleanup and probe exception classification. Some were earlier GPT findings and some came from Muse; see the preserved private evidence for attribution. Documented rollback/idempotency/argument-schema/recovery limits remain.

Public release: not performed. Independent acceptance of this exact rc5 archive: pending. The public website keeps its release-pending message.
