# User guide

## 1. Write a scenario file

A scenario file is strict JSON (duplicate keys, NaN/Infinity, >1 MiB or depth >32 are rejected). See `configs/examples/baseline_scenarios.json`.

```json
{
  "schema_version": 1,
  "name": "my-check",
  "policy": {
    "schema_version": 1, "arbitrary_shell": false, "approval_ttl_seconds": 300,
    "tools":  {"docs.read": {"risk": "low", "path_arg": "path"},
               "docs.write": {"risk": "medium", "requires_approval": true, "path_arg": "path"}},
    "agents": {"agent-1": {"allowed_tools": ["docs.read"], "allowed_paths": ["workspace/docs/**"]}},
    "approvers": ["human-1"]
  },
  "scenarios": [{"id": "S1", "category": "baseline", "steps": [
     {"request": {"action_id": "a1", "agent": "agent-1", "tool": "docs.read",
                  "args": {"path": "workspace/docs/x.txt"}}, "expect": "allow"}]}],
  "audit_tamper_checks": ["edit", "delete", "insert", "reorder", "truncate", "forge", "anchor_rollback"]
}
```

Policy rules: tool names are dotted lowercase; `risk` is low/medium/high; high risk always requires approval; agents and approvers must be different identities; `allowed_paths` are relative, case-sensitive patterns where `*` matches within one component and `**` matches any depth.

Approval modes per step: `none`, `valid`, `forged`, `expired`, `future`, `self`, `wrong_action`, `unknown_approver`, `malformed`, `replay:<earlier action_id>`. Keys are random per run and never written to disk or reports.

## 2. Run

```
ast-toolkit validate my.json
ast-toolkit run my.json --out reports
```

Exit codes: 0 all expectations met; 1 an expectation failed or tampering went undetected; 2 invalid input/config; 3 unsupported platform. Reports are new files only (`scenario_<name>_<utc>.json` and `.md`); existing files are never overwritten.

## 3. Windows filesystem probe

```
ast-toolkit fsprobe --out reports [--iterations 300] [--workdir D:\scratch]
```

Creates a temporary synthetic tree, runs the attacks listed in `TESTING.md`, removes the tree (junctions are removed as links, never followed). Outcomes: DENIED, ALLOWED_SAFE (only approved bytes returned), LEAKED (fail), SKIPPED (setup needs a privilege the user lacks, e.g. symlink creation without Developer Mode, WinError 1314), FAILED.

## 4. Library use

```python
from agent_security_toolkit.policy import Policy
from agent_security_toolkit.approval import ApprovalAuthority
from agent_security_toolkit.audit import AuditLog
from agent_security_toolkit.gate import Gate
```

Keep the approval key with the human-approval service and the audit key away from the agent. `ast-toolkit keygen PATH` makes a new random key file and refuses to overwrite.

## 5. Reading reports

Every report carries `verification_label: BUILDER-VERIFIED ONLY`. A PASS means the configured expectations held on that machine for that run; it is not a certification.
