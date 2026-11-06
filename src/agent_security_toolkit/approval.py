"""Human approval tokens with action binding, expiry and single-use nonces.

A token is an HMAC-SHA256 over the canonical approval record. The record binds
the approver identity, the exact action digest, a random nonce and a validity
window. Verification is constant-time for the MAC and fails closed on any
structural problem. Each nonce can be consumed once (replay protection). The
HMAC key must be held by the approval service, never by the agent.
"""
import hashlib
import hmac
import os
import secrets
import threading
import time
from .errors import ApprovalError, ConfigError
from .strict_json import canonical, require_keys, loads

TOKEN_VERSION = 1
CLOCK_SKEW_SECONDS = 30
MAX_LEDGER_BYTES = 1024 * 1024


def action_digest(action):
    """Digest of the exact action an approval authorizes."""
    require_keys(action, ("action_id", "agent", "tool", "args"), (), "action")
    return hashlib.sha256(canonical({k: action[k] for k in ("action_id", "agent", "tool", "args")})).hexdigest()


class NonceLedger:
    """Consumed nonces. Optional append-only file persists them across runs."""

    def __init__(self, path=None):
        self.path = path
        self._guard = threading.Lock()
        self._seen = set()
        self._reload()

    def _reload(self):
        path = self.path
        if path and os.path.exists(path):
            with open(path, "rb") as fh:
                data = fh.read(MAX_LEDGER_BYTES + 1)
            if len(data) > MAX_LEDGER_BYTES:
                raise ApprovalError("Nonce ledger size limit exceeded; trusted operator review required")
            try:
                text = data.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ApprovalError("Nonce ledger corrupt") from exc
            for line in text.splitlines():
                if len(line) != 64 or any(c not in "0123456789abcdef" for c in line):
                    raise ApprovalError("Nonce ledger corrupt")
                self._seen.add(line)

    def consume(self, nonce):
        with self._guard:
            return self._consume(nonce)

    def _consume(self, nonce):
        lock_fd = None
        lock_path = os.fspath(self.path) + '.consume.lock' if self.path else None
        if lock_path:
            try:
                lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError as exc:
                raise ApprovalError('Nonce ledger busy or stale lock requires review') from exc
        try:
            self._reload()
            self._consume_locked(nonce)
        finally:
            if lock_fd is not None:
                os.close(lock_fd)
                os.unlink(lock_path)

    def _consume_locked(self, nonce):
        if nonce in self._seen:
            raise ApprovalError("Approval nonce already used (replay)")
        if self.path:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600)
            try:
                data = (nonce + "\n").encode("ascii")
                if os.fstat(fd).st_size + len(data) > MAX_LEDGER_BYTES:
                    raise ApprovalError("Nonce ledger size limit exceeded; trusted operator review required")
                if os.write(fd, data) != len(data):
                    raise ApprovalError('Short nonce-ledger write')
                os.fsync(fd)
            finally:
                os.close(fd)
        self._seen.add(nonce)

    def __contains__(self, nonce):
        return nonce in self._seen


class ApprovalAuthority:
    def __init__(self, key, approvers, ttl_seconds=300, clock=time.time, ledger=None):
        if not isinstance(key, (bytes, bytearray)) or len(key) < 32:
            raise ConfigError("Approval key must be at least 32 bytes")
        self._key = bytes(key)
        self.approvers = frozenset(approvers)
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 3600:
            raise ConfigError("Approval TTL must be an integer 1..3600")
        self.ttl = ttl_seconds
        self.clock = clock
        self.ledger = ledger if ledger is not None else NonceLedger()

    def _mac(self, record):
        return hmac.new(self._key, canonical(record), hashlib.sha256).hexdigest()

    def issue(self, approver, action, ttl_seconds=None, now=None):
        """Called by the human-approval front end after a person approves."""
        if approver not in self.approvers:
            raise ApprovalError("Not an authorized approver")
        now = int(self.clock() if now is None else now)
        ttl = self.ttl if ttl_seconds is None else ttl_seconds
        if type(ttl) is not int or not 1 <= ttl <= 3600:
            raise ConfigError("Approval TTL must be an integer 1..3600")
        record = {"v": TOKEN_VERSION, "approver": approver, "action_digest": action_digest(action),
                  "nonce": secrets.token_hex(32), "issued": now, "expires": now + int(ttl)}
        record["mac"] = self._mac(record)
        return record

    def verify(self, token, action, requester):
        """Validate and consume. Raises ApprovalError on any failure."""
        if isinstance(token, (str, bytes)):
            try:
                token = loads(token)
            except ConfigError as exc:
                raise ApprovalError("Malformed approval token") from exc
        try:
            require_keys(token, ("v", "approver", "action_digest", "nonce", "issued", "expires", "mac"),
                         (), "approval")
        except ConfigError as exc:
            raise ApprovalError(str(exc)) from exc
        if token["v"] != TOKEN_VERSION:
            raise ApprovalError("Unsupported approval version")
        for k in ("issued", "expires"):
            if type(token[k]) is not int:
                raise ApprovalError("Invalid approval timestamps")
        for k in ("approver", "action_digest", "nonce", "mac"):
            if not isinstance(token[k], str):
                raise ApprovalError("Invalid approval field types")
        if len(token["nonce"]) != 64 or any(c not in "0123456789abcdef" for c in token["nonce"]):
            raise ApprovalError("Invalid nonce")
        if len(token['mac']) != 64 or any(c not in '0123456789abcdef' for c in token['mac']):
            raise ApprovalError('Invalid approval signature encoding')
        body = {k: token[k] for k in token if k != "mac"}
        if not hmac.compare_digest(self._mac(body), token["mac"]):
            raise ApprovalError("Approval signature invalid")
        if token["approver"] not in self.approvers:
            raise ApprovalError("Approver not authorized")
        if token["approver"] == requester:
            raise ApprovalError("Self-approval denied")
        try:
            digest = action_digest(action)
        except ConfigError as exc:
            raise ApprovalError("Malformed action") from exc
        if not hmac.compare_digest(digest, token["action_digest"]):
            raise ApprovalError("Approval is bound to a different action")
        now = int(self.clock())
        if token["issued"] > now + CLOCK_SKEW_SECONDS:
            raise ApprovalError("Approval issued in the future")
        if token["expires"] <= token["issued"] or token["expires"] - token["issued"] > 3600:
            raise ApprovalError("Approval validity window invalid")
        if now >= token["expires"]:
            raise ApprovalError("Approval expired")
        self.ledger.consume(token["nonce"])
        return token["approver"]
