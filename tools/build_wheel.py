"""Reproducible, stdlib-only wheel builder (no network, no build backend needed).

Usage: python tools/build_wheel.py OUT_DIR
Fixed timestamps, sorted entries and stored (uncompressed) members => byte-identical output
for identical sources on any platform (compressed output varies with the zlib build).
"""
import base64, hashlib, os, re, sys, zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(ROOT, "src", "agent_security_toolkit")
NAME, DIST = "agent-security-toolkit", "agent_security_toolkit"
EPOCH = (2026, 10, 26, 0, 0, 0)


def version():
    with open(os.path.join(PKG, "__init__.py"), encoding="utf-8") as fh:
        return re.search(r'__version__\s*=\s*"([^"]+)"', fh.read()).group(1)


def rec_hash(data):
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()


def main(out):
    v = version()
    files = []
    for d, dirs, fs in os.walk(PKG):
        dirs[:] = sorted(x for x in dirs if x != "__pycache__")
        for f in sorted(fs):
            if f.endswith(".py"):
                p = os.path.join(d, f)
                arc = os.path.relpath(p, os.path.join(ROOT, "src")).replace(os.sep, "/")
                with open(p, "rb") as fh:
                    files.append((arc, fh.read().replace(b"\r\n", b"\n")))
    di = "%s-%s.dist-info" % (DIST, v)
    with open(os.path.join(ROOT, "README.md"), "rb") as fh:
        readme = fh.read().replace(b"\r\n", b"\n").decode("utf-8")
    meta = ("Metadata-Version: 2.1\nName: %s\nVersion: %s\nSummary: Offline guardrail test harness for AI-agent tool use\n"
            "Requires-Python: >=3.11\nLicense: Apache-2.0\n"
            "Classifier: License :: OSI Approved :: Apache Software License\n"
            "Description-Content-Type: text/markdown\n\n%s" % (NAME, v, readme)).encode()
    files += [(di + "/METADATA", meta),
              (di + "/WHEEL", b"Wheel-Version: 1.0\nGenerator: ast-build_wheel\nRoot-Is-Purelib: true\nTag: py3-none-any\n"),
              (di + "/entry_points.txt", b"[console_scripts]\nast-toolkit = agent_security_toolkit.cli:main\n")]
    for name in ("LICENSE", "NOTICE"):
        with open(os.path.join(ROOT, name), "rb") as fh:
            files.append((di + "/" + name, fh.read().replace(b"\r\n", b"\n")))
    record = "".join("%s,%s,%d\n" % (a, rec_hash(b), len(b)) for a, b in files) + di + "/RECORD,,\n"
    files.append((di + "/RECORD", record.encode()))
    os.makedirs(out, exist_ok=True)
    path = os.path.join(out, "%s-%s-py3-none-any.whl" % (DIST, v))
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as z:
        for arc, data in files:
            zi = zipfile.ZipInfo(arc, EPOCH); zi.external_attr = 0o644 << 16; zi.create_system = 3; zi.compress_type = zipfile.ZIP_STORED
            z.writestr(zi, data)
    with open(path, "rb") as fh:
        print("%s  %s" % (hashlib.sha256(fh.read()).hexdigest(), os.path.basename(path)))
    return path


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "dist"))
