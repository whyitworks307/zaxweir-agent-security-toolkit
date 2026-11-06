"""Scenario runner: replays synthetic agent requests through the Gate.

Scenario file schema (schema_version 1):
{
  "schema_version": 1,
  "name": "...",
  "policy": { ...see policy.Policy... },
  "scenarios": [
    {"id": "...", "category": "...", "description": "...",
     "steps": [
       {"request": {"action_id": "...", "agent": "...", "tool": "...", "args": {...}},
        "approval": "none|valid|forged|expired|future|self|wrong_action|unknown_approver|malformed|replay:<action_id>",
        "approver": "<approver id, for valid/expired/... >",
        "expect": "allow|deny",
        "expect_escalation": true|false   (optional)}
     ]}
  ],
  "audit_tamper_checks": ["edit", "delete", "insert", "reorder", "truncate", "forge", "anchor_rollback"]  (optional)
}
Keys are ephemeral (os.urandom per run) and never written to reports.
"""
import copy
import os
import shutil
import tempfile
import time
from . import audit as auditmod
from .approval import ApprovalAuthority, NonceLedger
from .errors import ConfigError
from .gate import Gate
from .policy import Policy, _ident
from .strict_json import require_keys, canonical, loads

APPROVAL_MODES = {"none", "valid", "forged", "expired", "future", "self", "wrong_action",
                  "unknown_approver", "malformed"}
TAMPER_MODES = ("edit", "delete", "insert", "reorder", "truncate", "forge", "anchor_rollback")


def validate_config(cfg):
    require_keys(cfg, ("schema_version", "name", "policy", "scenarios"),
                 ("description", "audit_tamper_checks"), "scenario file")
    if type(cfg["schema_version"]) is not int or cfg["schema_version"] != 1:
        raise ConfigError("Unsupported scenario schema_version")
    policy = Policy.from_dict(cfg["policy"])
    if not isinstance(cfg["scenarios"], list) or not cfg["scenarios"]:
        raise ConfigError("scenarios must be a non-empty list")
    ids = set()
    for sc in cfg["scenarios"]:
        require_keys(sc, ("id", "category", "steps"), ("description",), "scenario")
        _ident(sc["id"], "scenario")
        if sc["id"] in ids:
            raise ConfigError("Duplicate or invalid scenario id")
        ids.add(sc["id"])
        if not isinstance(sc["steps"], list) or not sc["steps"]:
            raise ConfigError("Scenario %s needs steps" % sc["id"])
        for st in sc["steps"]:
            require_keys(st, ("request", "expect"), ("approval", "approver", "expect_escalation", "note"), "step")
            if st["expect"] not in ("allow", "deny"):
                raise ConfigError("expect must be allow or deny")
            mode = st.get("approval", "none")
            if not isinstance(mode, str) or not (mode in APPROVAL_MODES or mode.startswith("replay:")):
                raise ConfigError("Unknown approval mode %r" % (mode,))
    for m in cfg.get("audit_tamper_checks", []):
        if m not in TAMPER_MODES:
            raise ConfigError("Unknown audit tamper check %r" % (m,))
    return policy


class _Clock:
    def __init__(self):
        self.now = int(time.time())

    def __call__(self):
        return self.now


def _mint(authority, mode, step, issued_tokens, policy):
    req = step["request"]
    if mode == 'none':
        return None
    if not isinstance(req, dict):
        raise ConfigError('Approval modes require an object request')
    approver = step.get("approver") or (sorted(policy.approvers)[0] if policy.approvers else "nobody")
    action = {k: req.get(k) for k in ("action_id", "agent", "tool")}
    action["args"] = req.get("args", {})
    if mode == "none":
        return None
    if mode.startswith("replay:"):
        src = mode.split(":", 1)[1]
        if src not in issued_tokens:
            raise ConfigError("replay source %s has no token" % src)
        return copy.deepcopy(issued_tokens[src])
    if mode == "malformed":
        return "{not json"
    if mode == "unknown_approver":
        saved = authority.approvers
        authority.approvers = frozenset(saved | {"unlisted-approver"})
        try:
            tok = authority.issue("unlisted-approver", action)
        finally:
            authority.approvers = saved
        return tok
    if mode == "self":
        saved = authority.approvers
        authority.approvers = frozenset(saved | {req.get("agent")})
        try:
            tok = authority.issue(req.get("agent"), action)
        finally:
            authority.approvers = saved
        return tok
    if mode == "wrong_action":
        other = dict(action, args=dict(action["args"], _altered="1"))
        return authority.issue(approver, other)
    if mode == "expired":
        return authority.issue(approver, action, now=authority.clock() - 4000, ttl_seconds=60)
    if mode == "future":
        return authority.issue(approver, action, now=authority.clock() + 600)
    tok = authority.issue(approver, action)
    if mode == "forged":
        tok = dict(tok, mac="0" * 64)
    return tok


def _tamper(log_path, anchor_path, mode, key):
    with open(log_path, "rb") as fh:
        lines = fh.read().split(b"\n")[:-1]
    if len(lines) < 3:
        return None
    if mode == "edit":
        rec = loads(lines[1]); rec["event"]["decision"] = "ALLOW" if rec["event"].get("decision") != "ALLOW" else "DENY"
        lines[1] = canonical(rec)
    elif mode == "delete":
        del lines[1]
    elif mode == "insert":
        lines.insert(1, lines[1])
    elif mode == "reorder":
        lines[0], lines[1] = lines[1], lines[0]
    elif mode == "truncate":
        # torn write: last record cut in half (no trailing newline restored below)
        lines[-1] = lines[-1][: len(lines[-1]) // 2]
    elif mode == "forge":
        rec = loads(lines[-1]); rec["seq"] += 1; rec["event"] = {"decision": "ALLOW", "forged": True}
        lines.append(canonical(rec))
    elif mode == "anchor_rollback":
        # Remove the newest record but keep the newer anchor: anchor must disagree.
        lines = lines[:-1]
    with open(log_path, "wb") as fh:
        fh.write(b"".join(l + b"\n" for l in lines))
    return auditmod.verify(log_path, key, anchor_path)


def run_config(cfg, workdir=None):
    policy = validate_config(cfg)
    clock = _Clock()
    key_approval, key_audit = os.urandom(32), os.urandom(32)
    tmp = tempfile.mkdtemp(prefix="ast_run_", dir=workdir)
    results, tamper_results = [], []
    try:
        log_path, anchor_path = os.path.join(tmp, "audit.jsonl"), os.path.join(tmp, "audit.anchor.json")
        authority = ApprovalAuthority(key_approval, policy.approvers, policy.approval_ttl_seconds,
                                      clock=clock, ledger=NonceLedger(os.path.join(tmp, "nonces.txt")))
        issued = {}
        with auditmod.AuditLog(log_path, anchor_path, key_audit, clock=clock) as log:
            gate = Gate(policy, authority, log)
            for sc in cfg["scenarios"]:
                for idx, st in enumerate(sc["steps"]):
                    req = copy.deepcopy(st["request"])
                    mode = st.get("approval", "none")
                    token = _mint(authority, mode, st, issued, policy)
                    if token is not None:
                        req["approval"] = token
                        if isinstance(req.get("action_id"), str) and isinstance(token, dict):
                            issued.setdefault(req["action_id"], copy.deepcopy(token))
                    out = gate.submit(req)
                    actual = "allow" if out["allowed"] else "deny"
                    passed = actual == st["expect"]
                    if "expect_escalation" in st:
                        passed = passed and bool(out.get("escalation_attempt")) == st["expect_escalation"]
                    results.append({"scenario": sc["id"], "category": sc["category"], "step": idx,
                                    "action_id": req.get("action_id") if isinstance(req, dict) and isinstance(req.get("action_id"), str) else None,
                                    "approval_mode": mode, "expected": st["expect"], "actual": actual,
                                    "reason": out["reason"], "escalation_attempt": bool(out.get("escalation_attempt")),
                                    "passed": passed})
        clean = auditmod.verify(log_path, key_audit, anchor_path)
        allow_records = 0
        with open(log_path, "rb") as fh:
            for line in fh.read().splitlines():
                if loads(line)["event"].get("decision") == "ALLOW":
                    allow_records += 1
        consistency = {"audit_verified": clean["ok"], "audit_entries": clean["entries"],
                       "steps": len(results), "allow_decisions": sum(r["actual"] == "allow" for r in results),
                       "allow_records": allow_records}
        consistency["passed"] = (clean["ok"] and clean["entries"] == len(results)
                                 and consistency["allow_decisions"] == allow_records)
        for mode in cfg.get("audit_tamper_checks", []):
            copy_dir = tempfile.mkdtemp(prefix="tamper_", dir=tmp)
            lp, ap = os.path.join(copy_dir, "a.jsonl"), os.path.join(copy_dir, "a.anchor.json")
            shutil.copyfile(log_path, lp)
            shutil.copyfile(anchor_path, ap)
            res = _tamper(lp, ap, mode, key_audit)
            if res is None:
                tamper_results.append({"mode": mode, "detected": False, "passed": False,
                                       "problems": ["log too short to tamper (need >= 3 records)"]})
            else:
                tamper_results.append({"mode": mode, "detected": not res["ok"], "passed": not res["ok"],
                                       "problems": res["problems"]})
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return {"steps": results, "audit_consistency": consistency, "audit_tamper": tamper_results}
