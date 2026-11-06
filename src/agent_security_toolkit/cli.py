"""Command-line interface.

  ast run CONFIG.json --out DIR          run scenario file, write JSON + Markdown
  ast validate CONFIG.json               validate a scenario/policy file only
  ast fsprobe --out DIR [--iterations N] native Windows filesystem adversarial probe
  ast verify-audit LOG ANCHOR --key-file K   verify an audit log produced by the library
  ast keygen PATH                        create a random 32-byte key file (new file only)
  ast version

Exit codes: 0 pass, 1 security expectation failed / tamper detected,
2 invalid input or configuration, 3 unsupported platform.
"""
import argparse
import os
import sys
from datetime import datetime, timezone
from . import __version__, report
from .errors import ConfigError, ToolkitError
from .strict_json import load_file


def _stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def cmd_run(a):
    from .scenarios import run_config
    cfg = load_file(a.config)
    res = run_config(cfg)
    passed = (all(s["passed"] for s in res["steps"]) and res["audit_consistency"]["passed"]
              and all(t["passed"] for t in res["audit_tamper"]))
    rep = report.envelope("scenario", res, passed)
    rep["config_name"] = cfg["name"]
    jp, mp = report.write(a.out, "scenario_%s_%s" % (_safe(cfg["name"]), _stamp()), rep,
                          report.scenario_markdown(cfg["name"], rep))
    n_fail = sum(not s["passed"] for s in res["steps"])
    print("%s: %d steps, %d failed, audit %s, tamper checks %d -> %s" % (
        cfg["name"], len(res["steps"]), n_fail, "ok" if res["audit_consistency"]["passed"] else "FAIL",
        len(res["audit_tamper"]), "PASS" if passed else "FAIL"))
    print("JSON: %s\nSummary: %s" % (jp, mp))
    return 0 if passed else 1


def _safe(name):
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in str(name))[:48] or "config"


def cmd_validate(a):
    from .scenarios import validate_config
    validate_config(load_file(a.config))
    print("valid")
    return 0


def cmd_fsprobe(a):
    if os.name != "nt":
        print("fsprobe requires Windows", file=sys.stderr)
        return 3
    from .fsprobe import run_probe
    if type(a.iterations) is not int or not 10 <= a.iterations <= 100000:
        raise ConfigError("--iterations must be 10..100000")
    results = run_probe(a.workdir, a.iterations, keep=False)
    bad = [r for r in results if r["outcome"] in ("LEAKED", "FAILED") or
           (not r["passed"] and r["outcome"] != "SKIPPED")]
    skipped = [r for r in results if r["outcome"] == "SKIPPED"]
    rep = report.envelope("windows_fsprobe", results, not bad)
    rep["summary"] = {"attacks": len(results), "failed": len(bad), "skipped": len(skipped),
                      "passed": len(results) - len(bad) - len(skipped)}
    jp, mp = report.write(a.out, "fsprobe_%s" % _stamp(), rep, report.probe_markdown(rep))
    print("fsprobe: %(attacks)d checks, %(passed)d passed, %(failed)d failed, %(skipped)d skipped" % rep["summary"])
    print("JSON: %s\nSummary: %s" % (jp, mp))
    return 0 if not bad else 1


def cmd_verify_audit(a):
    from .audit import verify
    with open(a.key_file, "rb") as fh:
        key = fh.read(4096)
    if len(key) < 32:
        raise ConfigError("key file must contain at least 32 bytes")
    res = verify(a.log, key, a.anchor)
    print(("OK: %d entries verified" % res["entries"]) if res["ok"] else
          "TAMPER/INTEGRITY FAILURE: " + "; ".join(res["problems"]))
    return 0 if res["ok"] else 1


def cmd_keygen(a):
    fd = os.open(a.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(os.urandom(32))
    print("wrote new 32-byte key: %s (keep it outside agent-writable locations)" % a.path)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="ast", description="Agent Security Toolkit (offline, synthetic)")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run"); r.add_argument("config"); r.add_argument("--out", required=True); r.set_defaults(f=cmd_run)
    v = sub.add_parser("validate"); v.add_argument("config"); v.set_defaults(f=cmd_validate)
    f = sub.add_parser("fsprobe"); f.add_argument("--out", required=True); f.add_argument("--workdir")
    f.add_argument("--iterations", type=int, default=300); f.set_defaults(f=cmd_fsprobe)
    va = sub.add_parser("verify-audit"); va.add_argument("log"); va.add_argument("anchor")
    va.add_argument("--key-file", required=True); va.set_defaults(f=cmd_verify_audit)
    k = sub.add_parser("keygen"); k.add_argument("path"); k.set_defaults(f=cmd_keygen)
    ve = sub.add_parser("version"); ve.set_defaults(f=lambda a: print(__version__) or 0)
    a = p.parse_args(argv)
    try:
        return a.f(a)
    except (ConfigError, ToolkitError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    except FileExistsError as exc:
        print("error: refusing to overwrite existing file: %s" % exc.filename, file=sys.stderr)
        return 2
    except OSError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
