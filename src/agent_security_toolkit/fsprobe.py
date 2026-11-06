"""Native Windows filesystem adversarial probe (standard user, synthetic data).

Creates a disposable synthetic tree, attacks the enrollment-gated reader with
traversal, namespace, alias, reparse-point, hard-link and race techniques, and
reports per-attack outcomes. Outcomes:
  DENIED        access refused (expected for attacks)
  ALLOWED_SAFE  bytes returned and they equal the approved bytes
  LEAKED        any non-approved bytes returned  -> probe FAILS
  EXERCISED     root substitution occurred; no leak or unexpected error observed
  SKIPPED       setup unavailable or no substitution occurred (never a pass)
  FAILED        a legitimate read was refused, or the harness errored
No permissions, ACLs, services or system settings are changed.
"""
import ctypes
import hashlib
import os
import shutil
import subprocess
import tempfile
import threading
import time
from .errors import AccessDenied

OUTSIDE = b"SYNTHETIC_OUTSIDE_SECRET_DO_NOT_LEAK"
APPROVED = b"SYNTHETIC_APPROVED_CONTENT_v1"


def _sha(b):
    return hashlib.sha256(b).hexdigest()


# Modified 2026-11-02: resolve the system command through the OS, not command search.
def _system_cmd():
    get_directory = ctypes.WinDLL("kernel32", use_last_error=True).GetSystemDirectoryW
    get_directory.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
    get_directory.restype = ctypes.c_uint
    buf = ctypes.create_unicode_buffer(32768)
    size = get_directory(buf, len(buf))
    if size == 0 or size >= len(buf) or not os.path.isabs(buf.value):
        raise RuntimeError("System command directory unavailable")
    return os.path.join(buf.value, "cmd.exe")


def _junction(link, target):
    # The command processor needs quoted paths even when they contain no spaces.
    # Percent expansion cannot represent arbitrary literal paths safely here.
    paths = (str(link), str(target))
    if any(any(ch in p for ch in ('"', '%', '\x00', '\r', '\n')) for p in paths):
        raise RuntimeError("Unsupported junction setup path")
    cmd = _system_cmd()
    command = '"%s" /d /v:off /s /c "mklink /J "%s" "%s""' % (cmd, paths[0], paths[1])
    r = subprocess.run(command, executable=cmd,
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0 or not os.path.isdir(link):
        raise RuntimeError("junction creation failed: %s" % (r.stdout + r.stderr).strip())


def _err(exc):
    """Exception summary without file paths (reports must not carry local paths/user names)."""
    if isinstance(exc, OSError):
        return "%s errno=%s winerror=%s" % (exc.__class__.__name__, exc.errno, getattr(exc, "winerror", None))
    return exc.__class__.__name__



def _remove_reparse(path):
    try:
        if os.path.islink(path) or (hasattr(os.path, "isjunction") and os.path.isjunction(path)):
            os.rmdir(path) if os.path.isdir(path) else os.unlink(path)
    except OSError:
        pass


class Probe:
    def __init__(self, workdir=None, race_iterations=300):
        if os.name != "nt":
            raise NotImplementedError("fsprobe requires Windows")
        self.base = tempfile.mkdtemp(prefix="ast_fsprobe_", dir=workdir)
        self.root = os.path.join(self.base, "root")
        self.outside = os.path.join(self.base, "outside")
        self.results = []
        self.race_iterations = race_iterations
        self._reparse = []

    # ---- helpers -------------------------------------------------------
    def _record(self, rid, category, expected, outcome, detail=""):
        self.results.append({"id": rid, "category": category, "expected": sorted(expected),
                             "outcome": outcome, "passed": outcome in expected, "detail": detail})

    def _attempt(self, rid, category, request, expected=("DENIED",), pin=None, enr=None):
        from .winfs.safe_read import read_enrolled
        try:
            data = read_enrolled(pin or self.pin, enr or self.enr, request)
        except (AccessDenied, ValueError) as exc:
            self._record(rid, category, expected, "DENIED", _err(exc))
            return
        except Exception as exc:  # refusal after a harness error is not a passing security test
            self._record(rid, category, expected, "FAILED", "unexpected " + _err(exc))
            return
        outcome = "ALLOWED_SAFE" if data == APPROVED else "LEAKED"
        self._record(rid, category, expected, outcome, "returned %d bytes" % len(data))

    def _w(self, rel, data, base=None):
        p = os.path.join(base or self.root, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(data)
        return p

    # ---- run -----------------------------------------------------------
    def run(self):
        from .winfs.trusted_root import TrustedRoot, HANDLE_STATS
        from .winfs.safe_read import enroll
        start = dict(HANDLE_STATS)
        os.makedirs(self.root)
        os.makedirs(self.outside)
        secret = self._w("secret.txt", OUTSIDE, self.outside)
        self._w("docs/readme.txt", APPROVED)
        self._w("docs/long_descriptive_filename_for_shortname.txt", APPROVED)
        self._w("docs/race.txt", APPROVED)
        self._w("docs/unenrolled.txt", APPROVED)
        self._w("docs/big.bin", APPROVED)
        self._w("jdir/x.txt", APPROVED)
        self._w("links/l.txt", APPROVED)
        self._w("sdir/s.txt", APPROVED)
        self._w("x.txt", APPROVED, self.outside)
        try:
            with TrustedRoot(self.root) as pin:
                self.pin = pin
                self.enr = enroll(pin, {"docs/readme.txt": _sha(APPROVED),
                                        "docs/long_descriptive_filename_for_shortname.txt": _sha(APPROVED),
                                        "docs/race.txt": _sha(APPROVED),
                                        "docs/big.bin": _sha(APPROVED),
                                        "jdir/x.txt": _sha(APPROVED),
                                        "links/l.txt": _sha(APPROVED),
                                        "sdir/s.txt": _sha(APPROVED)})
                self._attempt("legit_read", "functional", "docs/readme.txt", ("ALLOWED_SAFE",))
                self._namespace(secret)
                self._aliases()
                self._reparse_points()
                self._hardlinks(secret)
                self._enrolled_reparse()
                self._limits()
                self._content_race()
            self._root_swap_race()
            self._root_ancestor_substitution()
            self._intermediate_directory_rename()
        finally:
            for p in self._reparse:
                _remove_reparse(p)
        balance = {k: HANDLE_STATS[k] - start[k] for k in HANDLE_STATS}
        self._record("native_handle_balance", "resource", ("BALANCED",),
                     "BALANCED" if balance["opened"] == balance["closed"] else "FAILED",
                     "opened=%(opened)d closed=%(closed)d" % balance)
        return self.results

    def _namespace(self, secret):
        for rid, req in [("traversal_dotdot", "../outside/secret.txt"),
                         ("traversal_backslash", "docs\\..\\..\\outside\\secret.txt"),
                         ("absolute_path", secret),
                         ("win32_file_namespace", "\\\\?\\" + secret),
                         ("win32_device_namespace", "\\\\.\\" + secret),
                         ("unc_loopback", "\\\\localhost\\C$\\Windows\\win.ini"),
                         ("drive_relative", secret[:2] + "secret.txt"),
                         ("forward_slash_rooted", "/outside/secret.txt"),
                         ("reserved_device_con", "docs/CON"),
                         ("reserved_device_ext", "NUL.txt"),
                         ("reserved_superscript", "COM\u00b9"),
                         ("trailing_dot", "docs/readme.txt."),
                         ("trailing_space", "docs/readme.txt "),
                         ("empty_component", "docs//readme.txt"),
                         ("nul_byte", "docs/readme.txt\x00.png"),
                         ("unpaired_surrogate", "docs/\ud800.txt"),
                         ("bidi_override", "docs/\u202etxt.exe"),
                         ("directory_as_file", "docs")]:
            self._attempt(rid, "path_canonicalization", req)
        ads = os.path.join(self.root, "docs", "readme.txt") + ":hidden"
        try:
            with open(ads, "wb") as fh:
                fh.write(OUTSIDE)
            self._attempt("alternate_data_stream", "path_canonicalization", "docs/readme.txt:hidden")
        except OSError as exc:
            self._record("alternate_data_stream", "path_canonicalization", ("DENIED",), "SKIPPED", _err(exc))

    def _aliases(self):
        self._attempt("case_variant", "alias", "DOCS/README.TXT")
        self._attempt("unenrolled_inside_root", "authorization", "docs/unenrolled.txt")
        long_path = os.path.join(self.root, "docs", "long_descriptive_filename_for_shortname.txt")
        buf = ctypes.create_unicode_buffer(1024)
        n = ctypes.windll.kernel32.GetShortPathNameW(long_path, buf, 1024)
        short = os.path.basename(buf.value) if n else ""
        if short and short.lower() != "long_descriptive_filename_for_shortname.txt":
            self._attempt("short_8dot3_alias", "alias", "docs/" + short)
        else:
            # 8.3 generation disabled on this volume; validate syntax denial instead.
            self._attempt("short_8dot3_alias_syntax", "alias", "docs/LONG_D~1.TXT")

    def _reparse_points(self):
        j = os.path.join(self.root, "jx")
        try:
            _junction(j, self.outside)
            self._reparse.append(j)
            self._attempt("junction_to_outside", "reparse", "jx/secret.txt")
        except Exception as exc:
            self._record("junction_to_outside", "reparse", ("DENIED",), "SKIPPED", _err(exc))
        s = os.path.join(self.root, "docs", "sym.txt")
        try:
            os.symlink(os.path.join(self.outside, "secret.txt"), s)
            self._reparse.append(s)
            self._attempt("file_symlink_to_outside", "reparse", "docs/sym.txt")
        except OSError as exc:
            self._record("file_symlink_to_outside", "reparse", ("DENIED",), "SKIPPED",
                         "symlink creation unavailable for this standard user: %s" % _err(exc))
        d = os.path.join(self.root, "dsym")
        try:
            os.symlink(self.outside, d, target_is_directory=True)
            self._reparse.append(d)
            self._attempt("dir_symlink_to_outside", "reparse", "dsym/secret.txt")
        except OSError as exc:
            self._record("dir_symlink_to_outside", "reparse", ("DENIED",), "SKIPPED",
                         "symlink creation unavailable for this standard user: %s" % _err(exc))

    def _enrolled_reparse(self):
        """Exercise the reparse/link layer itself: the request names an ENROLLED path."""
        # Directory of an enrolled file replaced by a junction to an outside dir holding the same bytes.
        jdir = os.path.join(self.root, "jdir")
        os.rename(jdir, jdir + "_orig")
        try:
            _junction(jdir, self.outside)
            self._reparse.append(jdir)
            # outside/x.txt has APPROVED bytes, so only the reparse rule (not the hash) can stop it.
            self._attempt("enrolled_parent_replaced_by_junction", "reparse", "jdir/x.txt")
        except Exception as exc:
            self._record("enrolled_parent_replaced_by_junction", "reparse", ("DENIED",), "SKIPPED", _err(exc))
        sdir = os.path.join(self.root, "sdir")
        os.rename(sdir, sdir + "_orig")
        try:
            os.symlink(self.outside, sdir, target_is_directory=True)
            self._reparse.append(sdir)
            self._attempt("enrolled_parent_replaced_by_dir_symlink", "reparse", "sdir/s.txt")
        except OSError as exc:
            self._record("enrolled_parent_replaced_by_dir_symlink", "reparse", ("DENIED",), "SKIPPED",
                         "symlink creation unavailable for this standard user: %s" % _err(exc))
        # Enrolled single-link file later gains a second hard link: link-count rule must deny.
        extra = os.path.join(self.outside, "second_name.txt")
        os.link(os.path.join(self.root, "links", "l.txt"), extra)
        self._attempt("enrolled_file_gains_hardlink", "hardlink", "links/l.txt")
        os.unlink(extra)
        self._attempt("enrolled_file_link_removed_again", "functional", "links/l.txt", ("ALLOWED_SAFE",))

    def _hardlinks(self, secret):
        from .winfs.safe_read import enroll
        hl = os.path.join(self.root, "docs", "hl.txt")
        os.link(secret, hl)
        self._attempt("hardlink_multi_link", "hardlink", "docs/hl.txt")
        try:
            enroll(self.pin, {"docs/hl.txt": _sha(OUTSIDE)})
            self._record("enroll_hardlink_refused", "hardlink", ("DENIED",), "LEAKED", "enrollment accepted multi-link file")
        except (AccessDenied, ValueError) as exc:
            self._record("enroll_hardlink_refused", "hardlink", ("DENIED",), "DENIED", str(exc))
        # R03 HIGH: orphaned hard link (outside name removed -> single link).
        secret2 = self._w("secret2.txt", OUTSIDE, self.outside)
        orphan = os.path.join(self.root, "docs", "orphan.txt")
        os.link(secret2, orphan)
        os.unlink(secret2)
        self._attempt("orphaned_hardlink_unenrolled", "hardlink", "docs/orphan.txt")
        # Replace an ENROLLED name with an orphaned outside-origin link.
        secret3 = self._w("secret3.txt", OUTSIDE, self.outside)
        target = os.path.join(self.root, "docs", "readme.txt")
        os.unlink(target)
        os.link(secret3, target)
        os.unlink(secret3)
        self._attempt("enrolled_name_replaced_by_orphaned_link", "hardlink", "docs/readme.txt")
        os.unlink(target)
        self._w("docs/readme.txt", APPROVED)
        self._attempt("enrolled_name_recreated_same_content_new_identity", "identity", "docs/readme.txt")

    def _limits(self):
        from .winfs.safe_read import read_enrolled
        try:
            read_enrolled(self.pin, self.enr, "docs/big.bin", max_bytes=4)
            self._record("read_cap_enforced", "limits", ("DENIED",), "LEAKED", "cap not enforced")
        except (AccessDenied, ValueError) as exc:
            self._record("read_cap_enforced", "limits", ("DENIED",), "DENIED", str(exc))
        for rid, cap in [("read_cap_zero", 0), ("read_cap_bool", True), ("read_cap_huge", 1 << 40)]:
            try:
                read_enrolled(self.pin, self.enr, "docs/big.bin", max_bytes=cap)
                self._record(rid, "malformed_input", ("DENIED",), "LEAKED", "invalid cap accepted")
            except (AccessDenied, ValueError) as exc:
                self._record(rid, "malformed_input", ("DENIED",), "DENIED", str(exc))

    def _content_race(self):
        target = os.path.join(self.root, "docs", "race.txt")
        stop = threading.Event()
        errors = []
        evil = (b"EVIL" * 16)[:len(APPROVED)]  # same size, same file object: only the hash can catch it
        writes = [0]

        def mutate():
            i = 0
            while not stop.is_set():
                try:
                    with open(target, "r+b") as fh:
                        fh.write(evil if i % 2 else APPROVED)
                    writes[0] += 1
                except OSError:
                    pass
                i += 1
        t = threading.Thread(target=mutate, daemon=True)
        t.start()
        leaked = safe = denied = 0
        from .winfs.safe_read import read_enrolled
        try:
            for _ in range(self.race_iterations):
                try:
                    data = read_enrolled(self.pin, self.enr, "docs/race.txt")
                    if data == APPROVED:
                        safe += 1
                    else:
                        leaked += 1
                except (AccessDenied, ValueError):
                    denied += 1
                except Exception as exc:
                    errors.append(repr(exc))
                    denied += 1
        finally:
            stop.set()
            t.join(10)
        self._record("toctou_inplace_content_race", "toctou", ("DENIED", "ALLOWED_SAFE"),
                     "LEAKED" if leaked else ("ALLOWED_SAFE" if safe else "DENIED"),
                     "iterations=%d writes=%d safe=%d denied=%d leaked=%d unexpected=%d" % (
                         self.race_iterations, writes[0], safe, denied, leaked, len(errors)))
        if not safe or not denied:
            self._record("toctou_inplace_race_effective", "toctou", ("EXERCISED",), "SKIPPED",
                         "race did not interleave both outcomes this run (safe=%d denied=%d)" % (safe, denied))
        else:
            self._record("toctou_inplace_race_effective", "toctou", ("EXERCISED",), "EXERCISED",
                         "both approved reads and denials observed")

    def _root_swap_race(self):
        from .winfs.trusted_root import TrustedRoot
        from .winfs.safe_read import enroll, read_enrolled
        # fresh small tree for the root-boundary race
        rroot = os.path.join(self.base, "raceroot")
        moved = rroot + "_moved"
        os.makedirs(os.path.join(rroot, "docs"))
        with open(os.path.join(rroot, "docs", "a.txt"), "wb") as fh:
            fh.write(APPROVED)
        decoy = os.path.join(self.base, "decoy", "docs")
        os.makedirs(decoy)
        with open(os.path.join(decoy, "a.txt"), "wb") as fh:
            fh.write(OUTSIDE)
        stop = threading.Event()
        swaps = [0]
        rename_attempts = [0]
        rename_failures = {}
        setup_failures = {}
        unexpected = []

        def swapper():
            while not stop.is_set():
                rename_attempts[0] += 1
                try:
                    os.rename(rroot, moved)
                except OSError as exc:
                    error = _err(exc)
                    rename_failures[error] = rename_failures.get(error, 0) + 1
                    time.sleep(0.001)
                    continue
                except Exception as exc:
                    error = _err(exc)
                    setup_failures[error] = setup_failures.get(error, 0) + 1
                    stop.set()
                    return
                try:
                    _junction(rroot, os.path.dirname(decoy))
                    swaps[0] += 1  # Count installed substitutions, not completed cleanup cycles.
                    time.sleep(0.001)
                    os.rmdir(rroot)
                    os.rename(moved, rroot)
                except Exception as exc:
                    error = _err(exc)
                    setup_failures[error] = setup_failures.get(error, 0) + 1
                    stop.set()
                    time.sleep(0.001)
        leaked = safe = denied = 0
        with TrustedRoot(rroot) as pin:
            enr = enroll(pin, {"docs/a.txt": _sha(APPROVED)})
            t = threading.Thread(target=swapper, daemon=True)
            t.start()
            try:
                for _ in range(self.race_iterations):
                    try:
                        data = read_enrolled(pin, enr, "docs/a.txt")
                        safe += data == APPROVED
                        leaked += data != APPROVED
                    except (AccessDenied, ValueError, OSError):
                        denied += 1
                    except Exception as exc:
                        unexpected.append(_err(exc))
            finally:
                stop.set()
                t.join(35)  # Allow the bounded 30-second junction subprocess to finish.
                if t.is_alive():
                    unexpected.append("root substitution worker did not stop")
                if os.path.isdir(moved):
                    _remove_reparse(rroot)
                    if not os.path.exists(rroot):
                        os.rename(moved, rroot)
        self._record_root_swap_result(swaps[0], safe, denied, leaked, rename_attempts[0],
                                      rename_failures, setup_failures, unexpected)

    def _record_root_swap_result(self, swaps, safe, denied, leaked, attempts,
                                 rename_failures, setup_failures, unexpected):
        """Report observed coverage separately from safe reads with no substitution."""
        if leaked:
            outcome = "LEAKED"
        elif unexpected or setup_failures:
            outcome = "FAILED"
        elif not swaps:
            outcome = "SKIPPED"
        else:
            outcome = "EXERCISED"
        self._record("root_boundary_swap_race", "toctou", ("EXERCISED",), outcome,
                     "iterations=%d swaps=%d safe=%d denied=%d leaked=%d "
                     "rename_attempts=%d rename_failures=%r setup_failures=%r unexpected=%r" % (
                         self.race_iterations, swaps, safe, denied, leaked, attempts,
                         rename_failures, setup_failures, unexpected))

    def _root_ancestor_substitution(self):
        """Attempt a real ancestor replacement without relaxing root-pin sharing.

        This deterministic namespace replacement is distinct from a successful
        direct-root rename race, which can remain blocked by the root pin.
        """
        from .winfs.trusted_root import TrustedRoot
        from .winfs.safe_read import enroll
        container = os.path.join(self.base, "ancestor_container")
        root = os.path.join(container, "trusted")
        self._w("docs/a.txt", APPROVED, root)
        with TrustedRoot(root) as pin:
            enrollment = enroll(pin, {"docs/a.txt": _sha(APPROVED)})
            try:
                os.rename(container, container + "_moved")
            except OSError as exc:
                self._record("root_ancestor_substitution", "identity", ("EXERCISED",),
                             "SKIPPED", "successful_substitutions=0; ancestor rename unavailable: " + _err(exc))
                return
            try:
                self._w("docs/a.txt", OUTSIDE, root)
            except Exception as exc:
                self._record("root_ancestor_substitution", "identity", ("EXERCISED",),
                             "FAILED", "ancestor renamed; replacement setup failed: " + _err(exc))
                return
            self._record("root_ancestor_substitution", "identity", ("EXERCISED",),
                         "EXERCISED", "successful_substitutions=1; ancestor renamed and original pathname replaced")
            self._attempt("pinned_read_after_ancestor_substitution", "identity", "docs/a.txt",
                          ("DENIED", "ALLOWED_SAFE"), pin=pin, enr=enrollment)

    def _intermediate_directory_rename(self):
        """A renamed intermediate directory must not grant access through its old path."""
        from .winfs.trusted_root import TrustedRoot
        from .winfs.safe_read import enroll
        root = os.path.join(self.base, "intermediate_root")
        self._w("docs/a.txt", APPROVED, root)
        with TrustedRoot(root) as pin:
            enrollment = enroll(pin, {"docs/a.txt": _sha(APPROVED)})
            try:
                os.rename(os.path.join(root, "docs"), os.path.join(root, "docs_moved"))
            except OSError as exc:
                self._record("enrolled_intermediate_directory_renamed", "identity", ("DENIED",),
                             "SKIPPED", "rename setup unavailable: " + _err(exc))
                return
            self._attempt("enrolled_intermediate_directory_renamed", "identity", "docs/a.txt",
                          pin=pin, enr=enrollment)

    def cleanup(self):
        for d, dirs, _ in os.walk(self.base):
            for name in list(dirs):
                p = os.path.join(d, name)
                if os.path.islink(p) or (hasattr(os.path, "isjunction") and os.path.isjunction(p)):
                    _remove_reparse(p)
        shutil.rmtree(self.base, ignore_errors=True)


def run_probe(workdir=None, race_iterations=300, keep=False):
    probe = Probe(workdir, race_iterations)
    try:
        results = probe.run()
    finally:
        if not keep:
            probe.cleanup()
    return results
