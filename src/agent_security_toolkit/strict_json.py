"""Strict, bounded JSON loading for untrusted configuration and tokens."""
import json
import math
from .errors import ConfigError

MAX_BYTES = 1024 * 1024
MAX_DEPTH = 32


def _no_dupes(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ConfigError("Duplicate JSON key: %r" % (k,))
        out[k] = v
    return out


def _bad_constant(name):
    raise ConfigError("Non-finite JSON number rejected: %s" % name)


def _depth(value, level=0):
    if level > MAX_DEPTH:
        raise ConfigError("JSON nesting too deep")
    if isinstance(value, dict):
        for v in value.values():
            _depth(v, level + 1)
    elif isinstance(value, list):
        for v in value:
            _depth(v, level + 1)
    elif isinstance(value, float) and not math.isfinite(value):
        raise ConfigError("Non-finite number rejected")


def loads(data):
    if isinstance(data, (bytes, bytearray)):
        if len(data) > MAX_BYTES:
            raise ConfigError("JSON document too large")
        try:
            data = bytes(data).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ConfigError("JSON must be UTF-8") from exc
    if not isinstance(data, str):
        raise ConfigError("JSON input must be text")
    if len(data.encode("utf-8", "surrogatepass")) > MAX_BYTES:
        raise ConfigError("JSON document too large")
    if data.startswith("\ufeff"):
        data = data[1:]
    try:
        value = json.loads(data, object_pairs_hook=_no_dupes, parse_constant=_bad_constant)
    except ConfigError:
        raise
    except (ValueError, RecursionError) as exc:
        raise ConfigError("Malformed JSON: %s" % exc.__class__.__name__) from exc
    _depth(value)
    return value


def load_file(path):
    with open(path, "rb") as fh:
        data = fh.read(MAX_BYTES + 1)
    return loads(data)


def canonical(value):
    """Deterministic encoding used for hashing and MACs."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def require_keys(obj, required, optional=(), where="object"):
    if not isinstance(obj, dict):
        raise ConfigError("%s must be a JSON object" % where)
    missing = [k for k in required if k not in obj]
    if missing:
        raise ConfigError("%s missing keys: %s" % (where, ", ".join(sorted(missing))))
    unknown = [k for k in obj if k not in required and k not in optional]
    if unknown:
        raise ConfigError("%s has unknown keys: %s" % (where, ", ".join(sorted(map(str, unknown)))))
