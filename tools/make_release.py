"""Build reproducible release artifacts: wheel, source zip, SBOM, manifest, SHA256SUMS.

Usage: python tools/make_release.py OUT_DIR   (OUT_DIR must not exist)
"""
import hashlib, json, os, sys, zipfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_wheel

ROOT = build_wheel.ROOT
INCLUDE_DIRS = ("src", "tests", "review_tests", "configs", "tools")
INCLUDE_FILES = (".gitignore", "HARDENING_NOTES.md", "pyproject.toml", "README.md", "INSTALL.md", "USER_GUIDE.md", "SECURITY_ARCHITECTURE.md",
                 "THREAT_MODEL.md", "TESTING.md", "KNOWN_LIMITATIONS.md", "CONTRIBUTING.md", "SECURITY.md",
                 "CHANGELOG.md", "LICENSING_STATUS.md", "THIRD_PARTY_LICENSES.md",
                 "NOTICE", "LICENSE", "SOURCE_PROVENANCE.md",
                 "DEPENDENCIES.json", "SBOM.cdx.json", "GITHUB_RELEASE_PREPARATION.md")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_files():
    out = []
    for f in INCLUDE_FILES:
        out.append(f)
    for top in INCLUDE_DIRS:
        for d, dirs, fs in os.walk(os.path.join(ROOT, top)):
            dirs[:] = sorted(x for x in dirs if x != "__pycache__")
            for f in sorted(fs):
                if not f.endswith((".pyc", ".pyo")):
                    out.append(os.path.relpath(os.path.join(d, f), ROOT).replace(os.sep, "/"))
    return sorted(out)


def main(out):
    os.makedirs(out)  # must be new
    v = build_wheel.version()
    whl = build_wheel.main(out)
    prefix = "zaxweir-agent-security-toolkit-%s/" % v
    src_zip = os.path.join(out, "zaxweir-agent-security-toolkit-%s-source.zip" % v)
    files = {}
    with zipfile.ZipFile(src_zip, "w", zipfile.ZIP_STORED) as z:
        for rel in source_files():
            with open(os.path.join(ROOT, rel), "rb") as fh:
                data = fh.read().replace(b"\r\n", b"\n")
            files[rel] = sha(data)
            zi = zipfile.ZipInfo(prefix + rel, build_wheel.EPOCH); zi.external_attr = 0o644 << 16; zi.create_system = 3
            zi.compress_type = zipfile.ZIP_STORED
            z.writestr(zi, data)
        manifest_data = (json.dumps(files, indent=2, sort_keys=True) + "\n").encode("utf-8")
        zi = zipfile.ZipInfo(prefix + "SOURCE_MANIFEST.json", build_wheel.EPOCH)
        zi.external_attr = 0o644 << 16; zi.create_system = 3; zi.compress_type = zipfile.ZIP_STORED
        z.writestr(zi, manifest_data)
    def fsha(p):
        with open(p, "rb") as fh:
            return sha(fh.read())
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "name": "agent-security-toolkit", "version": v,
                                       "hashes": [{"alg": "SHA-256", "content": fsha(whl)}],
                                       "licenses": [{"license": {"id": "Apache-2.0"}}]}},
            "components": [{"type": "framework", "name": "cpython-stdlib", "version": ">=3.11",
                            "licenses": [{"license": {"id": "PSF-2.0"}}],
                            "description": "Only runtime dependency; not redistributed"}],
            "dependencies": [{"ref": "agent-security-toolkit", "dependsOn": []}]}
    with open(os.path.join(out, "SBOM.cdx.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(sbom, fh, indent=2, sort_keys=True)
    manifest = {"name": "agent-security-toolkit", "version": v, "verification_label": "BUILDER-VERIFIED ONLY",
                "license": "Apache-2.0; owner grant recorded; inherited provenance/public release HOLD",
                "artifacts": {os.path.basename(whl): fsha(whl), os.path.basename(src_zip): fsha(src_zip),
                              "SBOM.cdx.json": fsha(os.path.join(out, "SBOM.cdx.json"))},
                "source_files": files, "source_file_count": len(files)}
    with open(os.path.join(out, "RELEASE_MANIFEST.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    names = sorted(n for n in os.listdir(out) if n != "SHA256SUMS.txt")
    with open(os.path.join(out, "SHA256SUMS.txt"), "w", encoding="utf-8", newline="\n") as fh:
        for n in names:
            fh.write("%s  %s\n" % (fsha(os.path.join(out, n)), n))
    print(open(os.path.join(out, "SHA256SUMS.txt"), encoding="utf-8").read())


if __name__ == "__main__":
    main(sys.argv[1])
