"""Tamper-evident, HMAC-chained audit log (JSON Lines) with external anchor.

Each record carries a sequence number, the SHA-256 of the previous record and
an HMAC-SHA256. A separate anchor file records the count and head hash.
Detected: edited, deleted, inserted, reordered or truncated records; forged
records without the key; anchor/log disagreement. NOT detected: an attacker
holding the key, or coordinated rollback of BOTH log and anchor to an older
authentic state (store the anchor somewhere the agent cannot write, and copy
it off-host if rollback matters). Not power-loss certified.
"""
import hashlib
import hmac
import os
import time
import threading
import tempfile
from .errors import AuditError, AuditBusy, ConfigError
from .strict_json import canonical, loads

GENESIS = "0" * 64
MAX_LINE = 64 * 1024
MAX_LOG_BYTES = 8 * 1024 * 1024


def _mac(key, body):
    return hmac.new(key, canonical(body), hashlib.sha256).hexdigest()


def _hash(record):
    return hashlib.sha256(canonical(record)).hexdigest()


def _write_atomic(path, data):
    # Each update owns a fresh exclusive sibling. A stale PID-named temporary
    # must not strand a newly appended log record behind an older anchor.
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(path) + ".tmp-",
                               dir=os.path.dirname(os.path.abspath(path)))
    try:
        try:
            if os.write(fd, data) != len(data):
                raise AuditError('Short atomic audit write')
            os.fsync(fd)
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass  # Preserve the primary write/fsync failure.
            raise
        else:
            os.close(fd)
        os.replace(tmp, path)
        tmp = None
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass  # Cleanup cannot mask the primary I/O failure.


def verify(log_path, key, anchor_path=None):
    """Return {"ok": bool, "entries": n, "head": hash, "problems": [...]}."""
    problems = []
    prev, count = GENESIS, 0
    try:
        with open(log_path, "rb") as fh:
            raw = fh.read(MAX_LOG_BYTES + 1)
        if len(raw) > MAX_LOG_BYTES:
            return {"ok": False, "entries": 0, "head": None, "problems": ["log size limit exceeded; trusted operator review required"]}
    except OSError as exc:
        return {"ok": False, "entries": 0, "head": None, "problems": ["log unreadable: %s" % exc.__class__.__name__]}
    if raw and not raw.endswith(b"\n"):
        problems.append("log ends with a partial record")
    lines = (raw.split(b'\n')[:-1] if raw.endswith(b'\n') else raw.split(b'\n')) if raw else []
    for lineno, line in enumerate(lines, 1):
        if not line:
            problems.append("line %d: empty record" % lineno)
            break
        if len(line) > MAX_LINE:
            problems.append("line %d: oversized record" % lineno)
            break
        try:
            rec = loads(line)
        except ConfigError:
            problems.append("line %d: malformed JSON" % lineno)
            break
        if not isinstance(rec, dict) or set(rec) != {"seq", "prev", "ts", "event", "mac"}:
            problems.append("line %d: unexpected record structure" % lineno)
            break
        if rec["seq"] != count + 1 or type(rec["seq"]) is not int:
            problems.append("line %d: sequence %r, expected %d" % (lineno, rec["seq"], count + 1))
            break
        if rec["prev"] != prev:
            problems.append("line %d: chain break (prev hash mismatch)" % lineno)
            break
        body = {k: rec[k] for k in ("seq", "prev", "ts", "event")}
        mac = rec['mac']
        if not isinstance(mac, str) or len(mac) != 64 or any(c not in '0123456789abcdef' for c in mac) or not hmac.compare_digest(_mac(key, body), mac):
            problems.append("line %d: MAC invalid" % lineno)
            break
        prev, count = _hash(rec), count + 1
    if anchor_path is not None:
        try:
            with open(anchor_path, "rb") as fh:
                data = fh.read(MAX_LINE + 1)
                if len(data) > MAX_LINE:
                    raise ConfigError('Anchor too large')
                anchor = loads(data)
            body = {k: anchor[k] for k in ("count", "head")}
            if set(anchor) != {"count", "head", "mac"} or not hmac.compare_digest(_mac(key, body), anchor["mac"]):
                problems.append("anchor MAC invalid")
            elif anchor["count"] != count or anchor["head"] != prev:
                problems.append("anchor disagrees with log (anchor count %r, log count %d)" % (anchor["count"], count))
        except (OSError, ConfigError, KeyError, TypeError):
            problems.append("anchor missing or malformed")
    return {"ok": not problems, "entries": count, "head": prev, "problems": problems}


class AuditLog:
    """Single-writer audit log. Refuses to open a log that fails verification."""

    def __init__(self, log_path, anchor_path, key, clock=time.time):
        if not isinstance(key, (bytes, bytearray)) or len(key) < 32:
            raise ConfigError("Audit key must be at least 32 bytes")
        self.log_path, self.anchor_path, self._key, self.clock = log_path, anchor_path, bytes(key), clock
        self._guard = threading.RLock()
        self._failed = False
        self.lock_path = log_path + ".lock"
        try:
            self._lock_fd = os.open(self.lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise AuditBusy("Audit log is locked by another writer (or a stale lock needs review)") from exc
        try:
            if os.path.exists(log_path) or os.path.exists(anchor_path):
                result = verify(log_path, self._key, anchor_path)
                if not result["ok"]:
                    raise AuditError("Existing audit log failed verification: %s" % "; ".join(result["problems"]))
                self.count, self.head = result["entries"], result["head"]
            else:
                self.count, self.head = 0, GENESIS
                _write_atomic(log_path, b"")
                self._write_anchor()
        except BaseException:
            self.close()
            raise

    def _write_anchor(self):
        body = {"count": self.count, "head": self.head}
        body["mac"] = _mac(self._key, body)
        _write_atomic(self.anchor_path, canonical(body))

    def append(self, event):
        with self._guard:
            return self._append(event)

    def _append(self, event):
        if self._failed:
            raise AuditError('Audit writer failed; close and independently verify before reopening')
        if self._lock_fd is None:
            raise AuditError("Audit log closed")
        body = {"seq": self.count + 1, "prev": self.head, "ts": int(self.clock()), "event": event}
        rec = dict(body, mac=_mac(self._key, body))
        line = canonical(rec) + b"\n"
        if len(line) > MAX_LINE:
            raise AuditError("Audit event too large")
        try:
            fd = os.open(self.log_path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0))
            try:
                if os.fstat(fd).st_size + len(line) > MAX_LOG_BYTES:
                    raise AuditError("Audit log size limit exceeded; trusted operator review required")
                if os.write(fd, line) != len(line):
                    raise AuditError("Short audit write")
                os.fsync(fd)
            finally:
                os.close(fd)
            self.count, self.head = rec["seq"], _hash(rec)
            self._write_anchor()
        except BaseException:
            self._failed = True
            raise
        return rec["seq"]

    def close(self):
        with self._guard:
            self._close()

    def _close(self):
        if getattr(self, "_lock_fd", None) is not None:
            os.close(self._lock_fd)
            self._lock_fd = None
            try:
                os.unlink(self.lock_path)
            except OSError:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
