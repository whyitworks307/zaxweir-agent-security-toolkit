"""Fail-closed action gate: policy -> duplicate check -> approval -> audit.

An action is reported as allowed only after its ALLOW record is durably
appended to the audit log. Any exception, malformed request or audit failure
yields a denial. The gate never executes tools; it decides.
"""
import re
from .approval import ApprovalAuthority, action_digest
from .errors import ApprovalError, ToolkitError

_ACTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class Gate:
    def __init__(self, policy, authority, audit):
        if not isinstance(authority, ApprovalAuthority):
            raise TypeError("ApprovalAuthority required")
        self.policy, self.authority, self.audit = policy, authority, audit
        self._seen_actions = set()

    def submit(self, request):
        try:
            return self._submit(request)
        except Exception as exc:  # fail closed on anything unexpected
            reason = "internal error: %s" % exc.__class__.__name__
            try:
                self.audit.append({"decision": "DENY", "reason": reason})
            except Exception:
                reason += " (audit unavailable)"
            return {"allowed": False, "reason": reason, "escalation_attempt": False}

    def _deny(self, action_id, agent, tool, reason, escalation=False):
        self.audit.append({"decision": "DENY", "action_id": action_id, "agent": agent, "tool": tool,
                           "reason": reason, "escalation_attempt": escalation})
        return {"allowed": False, "reason": reason, "escalation_attempt": escalation}

    def _submit(self, request):
        if not isinstance(request, dict):
            return self._deny(None, None, None, "request must be an object")
        unknown = set(request) - {"action_id", "agent", "tool", "args", "approval"}
        action_id, agent, tool = request.get("action_id"), request.get("agent"), request.get("tool")
        safe = lambda v: v if isinstance(v, str) and len(v) <= 128 else None
        action_id, agent, tool = safe(action_id), safe(agent), safe(tool)
        if unknown:
            return self._deny(action_id, agent, tool, "unknown request fields")
        if not isinstance(action_id, str) or not _ACTION_ID.fullmatch(action_id):
            return self._deny(None, agent, tool, "invalid or missing action_id")
        if action_id in self._seen_actions:
            return self._deny(action_id, agent, tool, "duplicate action_id (replay)")
        self._seen_actions.add(action_id)
        args = request.get("args", {})
        decision = self.policy.authorize(agent, tool, args)
        if not decision.allowed:
            return self._deny(action_id, agent, tool, decision.reason, decision.escalation_attempt)
        approver = None
        if decision.requires_approval:
            token = request.get("approval")
            if token is None:
                return self._deny(action_id, agent, tool, "human approval required")
            action = {"action_id": action_id, "agent": agent, "tool": tool, "args": args}
            try:
                approver = self.authority.verify(token, action, requester=agent)
            except ApprovalError as exc:
                return self._deny(action_id, agent, tool, "approval rejected: %s" % exc)
        self.audit.append({"decision": "ALLOW", "action_id": action_id, "agent": agent, "tool": tool,
                           "approver": approver, "action_digest": action_digest({"action_id": action_id, "agent": agent, "tool": tool, "args": args})})
        return {"allowed": True, "reason": decision.reason, "approver": approver, "escalation_attempt": False}
