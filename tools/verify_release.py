"""Read-only verification of a source ZIP against an externally trusted SHA-256.

Never extracts, installs, imports, or runs archive contents. An internal manifest
alone is not authentication; obtain the expected digest from a trusted release.
"""
import argparse
import hashlib
import io
import json
import pathlib
import re
import stat
import sys
import zipfile
import zlib

MAX_ARCHIVE = 16 * 1024 * 1024
MAX_TOTAL = 8 * 1024 * 1024
MAX_FILES = 1000
ROOT = "zaxweir-agent-security-toolkit-0.5.0rc8"
_HEX = re.compile(r"[0-9a-f]{64}")
_PART = re.compile(r"[A-Za-z0-9_.-]{1,128}")
_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {p + str(n) for p in ("COM", "LPT") for n in range(10)}


class VerificationError(ValueError):
    pass


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise VerificationError("Duplicate manifest key")
        result[key] = value
    return result


def verify_bytes(data, expected):
    if not isinstance(expected, str) or not _HEX.fullmatch(expected):
        raise VerificationError("Expected SHA-256 must be 64 lowercase hex characters")
    if len(data) > MAX_ARCHIVE:
        raise VerificationError("Archive size limit exceeded")
    if hashlib.sha256(data).hexdigest() != expected:
        raise VerificationError("Archive SHA-256 mismatch")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos = z.infolist()
            if not infos or len(infos) > MAX_FILES or sum(i.file_size for i in infos) > MAX_TOTAL:
                raise VerificationError("Archive member or expanded-size limit exceeded")
            seen = set()
            contents = {}
            for item in infos:
                parts = item.filename.split("/")
                if (len(parts) < 2 or parts[0] != ROOT or len(item.filename) > 512
                        or any(not _PART.fullmatch(p) or p in (".", "..") or p.endswith((".", " "))
                               or p.split(".")[0].upper() in _RESERVED for p in parts)):
                    raise VerificationError("Unsafe or unexpected member path")
                normalized = item.filename.casefold()
                if normalized in seen:
                    raise VerificationError("Duplicate or case-colliding archive path")
                seen.add(normalized)
                mode = item.external_attr >> 16
                if stat.S_ISLNK(mode) or item.is_dir() or (stat.S_IFMT(mode) not in (0, stat.S_IFREG)):
                    raise VerificationError("Non-regular archive member")
                if item.flag_bits & 1 or item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise VerificationError("Unsupported archive encoding")
                rel = "/".join(parts[1:])
                contents[rel] = z.read(item)
            raw_manifest = contents.pop("SOURCE_MANIFEST.json", None)
            if raw_manifest is None or len(raw_manifest) > 1024 * 1024:
                raise VerificationError("Source manifest missing or too large")
            manifest = json.loads(raw_manifest, object_pairs_hook=_pairs)
            if not isinstance(manifest, dict) or set(manifest) != set(contents):
                raise VerificationError("Manifest member set mismatch")
            for path, digest in manifest.items():
                if not isinstance(digest, str) or not _HEX.fullmatch(digest) or hashlib.sha256(contents[path]).hexdigest() != digest:
                    raise VerificationError("Manifest digest mismatch")
    except VerificationError:
        raise
    except (zipfile.BadZipFile, KeyError, ValueError, OSError, RuntimeError, zlib.error) as exc:
        raise VerificationError("Malformed or corrupt archive") from exc
    return {"ok": True, "sha256": expected, "files": len(contents), "root": ROOT}


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("archive");p.add_argument("--sha256", required=True)
    a = p.parse_args(argv)
    try:
        with pathlib.Path(a.archive).open("rb") as f:
            data = f.read(MAX_ARCHIVE + 1)
        print(json.dumps(verify_bytes(data, a.sha256), sort_keys=True))
        return 0
    except (VerificationError, OSError) as exc:
        print("Verification refused: " + (str(exc) if isinstance(exc, VerificationError) else type(exc).__name__), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
