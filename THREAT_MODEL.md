# Threat model

## Assets
Integrity of allow/deny decisions; confidentiality of files outside an approved root; integrity of the audit trail; the human-approval step.

## Adversary
A semi-trusted or compromised AI agent (or content steering it) that can craft arbitrary tool requests and create, rename, link and race files inside directories it can write, as the same standard Windows user. It cannot read the approval or audit keys and has no administrator rights.

## Out of scope
Administrator/SYSTEM or kernel adversaries; an attacker holding the HMAC keys; physical access; restoration of an older audit log together with its matching anchor and nonce ledger (NOT detected; no rollback protection is claimed against an attacker who controls both log and anchor; see KNOWN_LIMITATIONS); side channels; denial of service beyond fail-closed behaviour; the correctness of the tools an integrator executes after an ALLOW.

## Threats and controls
| ID | Threat | Control | Evidence |
|---|---|---|---|
| T1 | Path traversal / absolute / UNC / device / drive-relative paths | `pathpolicy.components` | test_pathpolicy, fsprobe namespace checks |
| T2 | Aliases: case, 8.3, ADS, trailing dot/space, reserved devices, Unicode format chars | exact components, rejection rules | test_pathpolicy, fsprobe alias checks |
| T3 | Reparse escapes (junction, symlink, root swap) | handle-relative opens, `OBJ_DONT_REPARSE`, root identity pin | fsprobe reparse checks, intermediate-directory rename and root-swap observations only when substitutions occur; [probe scope](SECURITY_ARCHITECTURE.md#fsprobe) |
| T4 | Hard-link provenance (incl. orphaned outside-origin links) | single-link rule + identity/content enrollment | fsprobe hardlink checks |
| T5 | TOCTOU content swap | identity + hash verified on the opened handle | fsprobe content race |
| T6 | Privilege escalation via tool choice/arguments | forbidden capabilities, escalation keys, grants | test_policy_gate, scenarios S03 |
| T7 | Approval forgery, replay, self-approval, scope widening, expiry abuse | HMAC tokens, nonce ledger, digest binding | test_policy_gate, scenarios S04 |
| T8 | Duplicate action replay | action_id uniqueness per gate | scenarios S04 |
| T9 | Audit tampering / truncation / forgery / concurrent writers | hash chain, MAC, anchor, lock | test_policy_gate, tamper checks |
| T10 | Malformed / oversized / ambiguous JSON | strict_json | test_strict_json, CLI tests |
| T11 | Native handle leaks | finally-close, per-module counters | test_winfs, fsprobe handle balance |
