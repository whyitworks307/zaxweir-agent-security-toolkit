"""Deny-by-default authorization policy for simulated agent tool calls."""
import re
from dataclasses import dataclass
from . import pathpolicy
from .errors import ConfigError, AccessDenied
from .strict_json import require_keys

SCHEMA_VERSION = 1
# Capabilities this toolkit will never grant. A policy that registers one of
# them is rejected as a configuration error (fail closed).
FORBIDDEN_TOOLS = frozenset({
    "shell.exec", "process.spawn", "os.elevate", "registry.write", "service.control",
    "credential.read", "acl.modify", "scheduler.create", "network.listen",
    "firewall.modify", "certificate.install", "account.modify",
})
ESCALATION_ARG_KEYS = frozenset({"run_as", "elevate", "impersonate", "sudo", "as_user",
                                 "as_agent", "privileged", "admin", "bypass_approval"})
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_RISKS = ("low", "medium", "high")
MAX_ARG_STRING = 4096


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    requires_approval: bool = False
    escalation_attempt: bool = False


def _ident(value, where):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ConfigError("Invalid identifier in %s: %r" % (where, value))
    return value


class Policy:
    def __init__(self, tools, agents, approvers, approval_ttl_seconds):
        self.tools = tools
        self.agents = agents
        self.approvers = approvers
        self.approval_ttl_seconds = approval_ttl_seconds

    @classmethod
    def from_dict(cls, data):
        require_keys(data, ("schema_version", "tools", "agents", "approvers"),
                     ("approval_ttl_seconds", "arbitrary_shell", "description"), "policy")
        if type(data["schema_version"]) is not int or data["schema_version"] != SCHEMA_VERSION:
            raise ConfigError("Unsupported policy schema_version")
        if data.get("arbitrary_shell", False) is not False:
            raise ConfigError("arbitrary_shell must be false; shell execution is never supported")
        ttl = data.get("approval_ttl_seconds", 300)
        if type(ttl) is not int or not 1 <= ttl <= 3600:
            raise ConfigError("approval_ttl_seconds must be an integer 1..3600")
        if not isinstance(data["tools"], dict) or not data["tools"]:
            raise ConfigError("tools must be a non-empty object")
        tools = {}
        for name, spec in data["tools"].items():
            if not isinstance(name, str) or not re.fullmatch(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$", name):
                raise ConfigError("Invalid tool name %r" % (name,))
            if name in FORBIDDEN_TOOLS:
                raise ConfigError("Tool %s is a forbidden capability and cannot be registered" % name)
            require_keys(spec, ("risk",), ("requires_approval", "path_arg"), "tool " + name)
            if spec["risk"] not in _RISKS:
                raise ConfigError("Invalid risk for %s" % name)
            req = spec.get("requires_approval", spec["risk"] == "high")
            if type(req) is not bool:
                raise ConfigError("requires_approval must be boolean")
            if spec["risk"] == "high" and not req:
                raise ConfigError("High-risk tool %s must require approval" % name)
            path_arg = spec.get("path_arg")
            if path_arg is not None and (not isinstance(path_arg, str) or not path_arg):
                raise ConfigError("path_arg must be a non-empty string")
            tools[name] = {"risk": spec["risk"], "requires_approval": req, "path_arg": path_arg}
        if not isinstance(data["agents"], dict) or not data["agents"]:
            raise ConfigError("agents must be a non-empty object")
        agents = {}
        for aid, spec in data["agents"].items():
            _ident(aid, "agents")
            require_keys(spec, ("allowed_tools",), ("allowed_paths",), "agent " + aid)
            allowed = spec["allowed_tools"]
            if not isinstance(allowed, list) or any(not isinstance(t, str) for t in allowed):
                raise ConfigError("allowed_tools must be a list of strings")
            for t in allowed:
                if t in FORBIDDEN_TOOLS:
                    raise ConfigError("Agent %s may not be granted forbidden tool %s" % (aid, t))
                if t not in tools:
                    raise ConfigError("Agent %s references unknown tool %s" % (aid, t))
            paths = spec.get("allowed_paths", [])
            if not isinstance(paths, list):
                raise ConfigError("allowed_paths must be a list")
            try:
                for p in paths:
                    pathpolicy.validate_pattern(p)
            except AccessDenied as exc:
                raise ConfigError("Invalid allowed_paths pattern for %s: %s" % (aid, exc)) from exc
            agents[aid] = {"allowed_tools": frozenset(allowed), "allowed_paths": tuple(paths)}
        approvers = data["approvers"]
        if not isinstance(approvers, list):
            raise ConfigError("approvers must be a list")
        approvers = frozenset(_ident(a, "approvers") for a in approvers)
        overlap = approvers & set(agents)
        if overlap:
            raise ConfigError("Identities cannot be both agent and approver: %s" % sorted(overlap))
        return cls(tools, agents, approvers, ttl)

    def authorize(self, agent, tool, args):
        """Return a Decision. Never raises for untrusted request content."""
        if not isinstance(agent, str) or agent not in self.agents:
            return Decision(False, "unknown agent")
        if not isinstance(tool, str):
            return Decision(False, "invalid tool name")
        if tool in FORBIDDEN_TOOLS:
            return Decision(False, "forbidden capability requested", escalation_attempt=True)
        if tool not in self.tools:
            return Decision(False, "unregistered tool")
        if not isinstance(args, dict):
            return Decision(False, "arguments must be an object")
        for key, value in args.items():
            if not isinstance(key, str):
                return Decision(False, "invalid argument key")
            if key.lower() in ESCALATION_ARG_KEYS:
                return Decision(False, "privilege-escalation argument %s" % key, escalation_attempt=True)
            if not (isinstance(value, (str, bool)) or type(value) is int):
                return Decision(False, "unsupported argument type for %s" % key)
            if isinstance(value, str) and len(value) > MAX_ARG_STRING:
                return Decision(False, "argument %s too long" % key)
        agent_spec = self.agents[agent]
        spec = self.tools[tool]
        if tool not in agent_spec["allowed_tools"]:
            higher = spec["risk"] != "low"
            return Decision(False, "tool not granted to agent", escalation_attempt=higher)
        if spec["path_arg"]:
            path = args.get(spec["path_arg"])
            if not isinstance(path, str):
                return Decision(False, "missing path argument")
            try:
                ok = any(pathpolicy.matches(p, path) for p in agent_spec["allowed_paths"])
            except AccessDenied as exc:
                return Decision(False, "path rejected: %s" % exc)
            if not ok:
                return Decision(False, "path outside agent allowlist")
        return Decision(True, "authorized by policy", requires_approval=spec["requires_approval"])
