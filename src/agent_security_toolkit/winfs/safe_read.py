"""Enrollment and contained reads on top of a TrustedRoot.

Historical procedure-based rc4 implementation from SPEC.md (provenance unresolved) (C1-C3, E1-E3, W1-W7).
"""
import ctypes
import hashlib
import re
from ctypes import wintypes as wt

from ..errors import AccessDenied
from . import _win32 as w
from .trusted_root import TrustedRoot, final_path, identity_of, query, release

MAX_READ = 1024 * 1024
_HEX64 = re.compile(r"[0-9a-f]{64}")
_FORBIDDEN_CHARS = set('<>"|?*:')
_BIDI = set("\u200e\u200f\u061c") | {chr(c) for c in range(0x202A, 0x202F)} | {chr(c) for c in range(0x2066, 0x206A)}
_DEVICES = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {
    p + d for p in ("COM", "LPT") for d in "0123456789\u00b9\u00b2\u00b3"}


def _component_ok(c):
    if c in ("", ".", ".."):
        return False
    if c[-1] in ". ":
        return False
    for ch in c:
        o = ord(ch)
        if o < 0x20 or o == 0x7F or ch in _FORBIDDEN_CHARS or ch in _BIDI or 0xD800 <= o <= 0xDFFF:
            return False
    if c.split(".", 1)[0].rstrip(" ").upper() in _DEVICES:
        return False
    return len(c.encode("utf-16-le")) // 2 <= 255


def canonical(request):
    """Return the tuple of components for a request, or raise ValueError."""
    if not isinstance(request, str) or not request:
        raise ValueError("Request must be a non-empty string")
    parts = request.replace("\\", "/").split("/")
    if not all(_component_ok(p) for p in parts):
        raise ValueError("Request path rejected by canonicalization rules")
    return tuple(parts)


class EnrollmentRecord:
    __slots__ = ("pin", "_entries")

    def __init__(self, pin, entries):
        self.pin = pin
        self._entries = dict(entries)

    def lookup(self, parts):
        return self._entries.get(parts)

    def __contains__(self, parts):
        return parts in self._entries


def _check_cap(max_bytes):
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_READ:
        raise ValueError("max_bytes must be an int between 1 and %d" % MAX_READ)


def _walk_and_read(pin, parts, cap, expected_identity=None):
    """Open parts relative to the pin, verify the leaf, read <= cap bytes. Returns (data, identity)."""
    root = pin.validate()
    a = w.api()
    held = []
    primary_error = None
    try:
        parent = root
        for name in parts[:-1]:
            h, _ = pin.open_relative(parent, name, True)
            held.append(h)
            parent = h
        leaf, info = pin.open_relative(parent, parts[-1], False)
        held.append(leaf)
        ident = identity_of(info)
        if expected_identity is not None and ident != expected_identity:
            raise AccessDenied("Leaf is not the enrolled file object")
        where = final_path(leaf)
        if not where.startswith(pin.final + "\\"):
            raise AccessDenied("File resolves outside the trusted root")
        size = (info.nFileSizeHigh << 32) | info.nFileSizeLow
        if size > cap:
            raise AccessDenied("Content larger than allowed cap")
        buf = ctypes.create_string_buffer(cap + 1)
        got = 0
        while got <= cap:
            n = wt.DWORD(0)
            if not a.read(leaf, ctypes.byref(buf, got), cap + 1 - got, ctypes.byref(n), None):
                raise AccessDenied("ReadFile failed")
            if n.value == 0:
                break
            got += n.value
        if got > cap:
            raise AccessDenied("Content larger than allowed cap")
        after = query(leaf)
        if identity_of(after) != ident or after.nNumberOfLinks != 1:
            raise AccessDenied("File identity or link count changed during read")
        return buf.raw[:got], ident
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        cleanup_errors = []
        for h in reversed(held):
            try:
                release(h)
            except BaseException as exc:
                cleanup_errors.append(exc)
        if cleanup_errors:
            if primary_error is not None:
                # Keep the original denial/fault and finish all remaining closes.
                try:
                    BaseException.add_note(primary_error,
                        "Native cleanup also failed for %d handle(s)" % len(cleanup_errors))
                except Exception:
                    pass  # Diagnostics must never mask the primary exception.
            else:
                # A successful read is not returned when any cleanup failed.
                first_error = cleanup_errors[0]
                if len(cleanup_errors) > 1:
                    try:
                        BaseException.add_note(first_error,
                            "%d additional native cleanup failure(s)" % (len(cleanup_errors) - 1))
                    except Exception:
                        pass  # A malformed pre-existing __notes__ must not mask it.
                raise first_error


def enroll(pin, approved_sha256):  # signature fixed by public API/tests
    """Bind {relative_path: sha256} to this pin after verifying content and recording identity."""
    if not isinstance(pin, TrustedRoot) or pin.closed:
        raise AccessDenied("Open TrustedRoot required")
    if not isinstance(approved_sha256, dict) or not approved_sha256:
        raise ValueError("enroll() needs a non-empty dict of path -> sha256")
    approved = {}
    for rel, digest in approved_sha256.items():
        parts = canonical(rel)
        if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            raise ValueError("sha256 must be 64 lowercase hex characters")
        if parts in approved:
            raise ValueError("Path listed twice after canonicalization")
        data, ident = _walk_and_read(pin, parts, MAX_READ)
        if hashlib.sha256(data).hexdigest() != digest:
            raise AccessDenied("Digest mismatch while enrolling")
        approved[parts] = (digest, ident)
    return EnrollmentRecord(pin, approved)


def read_enrolled(pin, enrollment, requested, max_bytes=MAX_READ):
    """Return the bytes of an enrolled file, or deny."""
    if type(pin) is not TrustedRoot:
        raise AccessDenied("pin must be a TrustedRoot")
    if type(enrollment) is not EnrollmentRecord or enrollment.pin is not pin:
        raise AccessDenied("Enrollment bound to this pin required")
    _check_cap(max_bytes)
    parts = canonical(requested)
    entry = enrollment.lookup(parts)
    if entry is None:
        raise AccessDenied("Path is not enrolled")
    digest, ident = entry
    data, _ = _walk_and_read(pin, parts, max_bytes, ident)
    if hashlib.sha256(data).hexdigest() != digest:
        raise AccessDenied("Content digest differs from enrollment")
    return data
