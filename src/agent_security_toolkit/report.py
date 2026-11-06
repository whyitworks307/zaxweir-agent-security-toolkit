"""Machine-readable JSON reports and human-readable Markdown summaries."""
import json
import os
import platform
import sys
from datetime import datetime, timezone
from . import __version__

LABEL = "BUILDER-VERIFIED ONLY - not independent security QC"


def envelope(kind, payload, passed):
    return {"tool": "agent-security-toolkit", "version": __version__, "report_type": kind,
            "generated_utc": datetime.now(timezone.utc).isoformat(), "verification_label": LABEL,
            "environment": {"python": sys.version.split()[0], "platform": platform.system(),
                            "release": platform.release()},
            "passed": passed, "results": payload}


def _write_new(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o644)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def write(out_dir, stem, report, markdown):
    os.makedirs(out_dir, exist_ok=True)
    jp, mp = os.path.join(out_dir, stem + ".json"), os.path.join(out_dir, stem + ".md")
    _write_new(jp, json.dumps(report, indent=2, sort_keys=True).encode("utf-8"))
    _write_new(mp, markdown.encode("utf-8"))
    return jp, mp


def scenario_markdown(name, report):
    r = report["results"]
    lines = ["# Agent Security Toolkit - scenario report: %s" % name, "",
             "Overall: **%s**  " % ("PASS" if report["passed"] else "FAIL"),
             "Label: %s  " % LABEL, "Version: %s" % report["version"], "",
             "| Scenario | Category | Step | Approval | Expected | Actual | Result | Reason |",
             "|---|---|---:|---|---|---|---|---|"]
    for s in r["steps"]:
        lines.append("| %s | %s | %d | %s | %s | %s | %s | %s |" % (
            s["scenario"], s["category"], s["step"], s["approval_mode"], s["expected"], s["actual"],
            "PASS" if s["passed"] else "FAIL", s["reason"].replace("|", "/")))
    c = r["audit_consistency"]
    lines += ["", "## Audit consistency", "",
              "Verified: %s; entries %d for %d steps; ALLOW decisions %d / ALLOW records %d -> %s" % (
                  c["audit_verified"], c["audit_entries"], c["steps"], c["allow_decisions"],
                  c["allow_records"], "PASS" if c["passed"] else "FAIL")]
    if r["audit_tamper"]:
        lines += ["", "## Audit tamper detection", "", "| Mode | Detected | Detail |", "|---|---|---|"]
        for t in r["audit_tamper"]:
            lines.append("| %s | %s | %s |" % (t["mode"], t["detected"], "; ".join(t["problems"])[:160]))
    return "\n".join(lines) + "\n"


def probe_markdown(report):
    lines = ["# Agent Security Toolkit - Windows filesystem probe", "",
             "Overall: **%s**  " % ("PASS" if report["passed"] else "FAIL"), "Label: %s" % LABEL, "",
             "| Attack | Category | Expected | Outcome | Result | Detail |", "|---|---|---|---|---|---|"]
    for x in report["results"]:
        lines.append("| %s | %s | %s | %s | %s | %s |" % (
            x["id"], x["category"], "/".join(x["expected"]), x["outcome"],
            "PASS" if x["passed"] else ("SKIP" if x["outcome"] == "SKIPPED" else "FAIL"),
            x["detail"].replace("|", "/")[:140]))
    return "\n".join(lines) + "\n"
