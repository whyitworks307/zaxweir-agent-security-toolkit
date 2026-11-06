# Security architecture

## Principles
1. Deny by default; every unexpected condition (exception, malformed input, audit failure) is a denial.
2. The authorization gate decides and records without executing proposed agent tools. The separate fsprobe harness performs the local operations described below.
3. Separate trust: the agent holds no approval or audit key.
4. Stdlib only, no network, no privilege, no persistent system changes.

## Gate pipeline
`request -> schema/unknown-field check -> action_id format + duplicate check -> Policy.authorize -> (approval verify if required) -> audit append -> ALLOW`.
Denials are audited too. If the audit write fails, the gate denies.

## Policy
- `FORBIDDEN_TOOLS` (shell.exec, process.spawn, os.elevate, registry.write, service.control, credential.read, acl.modify, scheduler.create, network.listen, firewall.modify, certificate.install, account.modify) cannot be registered or granted; requests for them are flagged as escalation attempts.
- Escalation argument keys (`run_as`, `elevate`, `impersonate`, `sudo`, `as_user`, `as_agent`, `privileged`, `admin`, `bypass_approval`, case-insensitive) deny and flag.
- Requests for registered but ungranted medium/high tools are flagged.
- Argument values: str (<=4096), bool or int only.
- Path arguments go through `pathpolicy.components` (relative only; rejects rooted/UNC/device/drive, `.`/`..`/empty, ADS `:`, wildcard and control characters, Unicode format characters, trailing dot/space, DOS device names incl. superscript COM/LPT, 8.3-style `~N` names, >32 components, >255 UTF-16 units) and case-sensitive pattern matching.

## Approval tokens
`{v, approver, action_digest, nonce(256-bit), issued, expires, mac}`; MAC = HMAC-SHA256(key, canonical JSON). Verification: structure and types, constant-time MAC, approver in allow-list, approver != requester, digest equals SHA-256 of canonical `{action_id, agent, tool, args}`, not issued >30 s in the future, window <=1 h, not expired, nonce unused (ledger optionally persisted append-only; corrupt ledger fails closed).

## Audit log
Each JSONL record: `{seq, prev, ts, event, mac}`; `prev` is SHA-256 of the previous canonical record; MAC over the body. A separate anchor `{count, head, mac}` is written atomically (temp + fsync + replace). The log opens only if it verifies, and an O_EXCL lock file enforces a single writer.

## Windows trusted reads (`winfs`)
- `TrustedRoot` opens the root directory once, records volume serial + file index, and re-validates that the path still resolves to the same object before and after operations.
- Each component is opened relative to the parent handle with `NtCreateFile`, `OBJ_DONT_REPARSE` and `FILE_OPEN_REPARSE_POINT`; any reparse attribute denies. Names are compared exactly (no case folding).
- Leaf files must be regular, non-reparse, with link count 1.
- `enroll()` is the trusted bootstrap: exact relative paths with independently known SHA-256. It records identity (volume + file index), size and hash.
- `read_enrolled()` denies unless the opened object's identity, size and hash match the enrollment. This closes the case where an outside-origin hard link becomes single-link after its outside name is removed: such a file was never enrolled, or replaces an enrolled name with a different identity and hash.
- Handles are closed in `finally` blocks; module counters (`HANDLE_STATS`) let tests check open/close balance.

## Rollback limitation

**Rollback limitation:** restoring an older audit log together with its matching anchor (and an older nonce ledger) is NOT detected; the restored state verifies as valid. The toolkit provides no rollback protection against an attacker who can write or restore both the log and its anchor. Durable anti-rollback requires an external monotonic counter or remote witness, which is not provided.


## fsprobe

The Windows-only fsprobe harness creates a disposable tree of fictional files and tests the enrolled reader. It exercises namespace rejection, identity and content checks, hard links, junctions and bounded races. It uses the system command interpreter for junction setup. GetSystemDirectoryW supplies an absolute system cmd.exe path. The invocation pins that executable, disables AutoRun and delayed expansion, quotes paths and has a 30-second timeout. Setup refuses quotes, percent expansion, NUL and line breaks in junction paths.

A probe pass describes the observed check on that machine. It supplies neither OS sandboxing nor exhaustive race coverage. Privilege-dependent symlink creation can fail with WinError 1314 and is reported as a skip. The harness requires no privilege elevation or security-setting changes.

The root_boundary_swap_race record includes successful substitutions, root rename attempts, rename-failure counts and setup errors. With zero successful substitutions it is SKIPPED with passed=false, even when every read returned approved bytes. A pinned root can resist rename with WinError 32. Such refusal does not establish an exercised root-substitution race. A separate enrolled_intermediate_directory_renamed check renames an enrolled file's parent directory while the root is pinned and expects later reads through the old enrolled path to be denied. An unavailable rename setup stays a skip. Unexpected worker/setup errors or leaked bytes fail the check.

Inspect each record and its skip reason before interpreting the overall command result. The CLI can complete successfully while reporting skipped coverage. Use the [threat matrix](THREAT_MODEL.md) and [known limitations](KNOWN_LIMITATIONS.md) alongside the raw outcomes.
