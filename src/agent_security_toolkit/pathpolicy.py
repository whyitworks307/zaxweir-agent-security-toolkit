"""Platform-independent request path validation (fail closed).

Only *relative* paths made of plain Windows-safe components are accepted.
Anything ambiguous on Windows (drive letters, UNC, device namespaces, alternate
data streams, reserved device names, 8.3 short-name aliases, trailing dots or
spaces, control/format characters) is rejected rather than normalized.
Matching is exact and case-sensitive: different spellings never inherit a
grant. This is syntax validation only; the Windows native reader in
agent_security_toolkit.winfs performs the actual handle-relative opens.
"""
import re
import unicodedata
from functools import lru_cache
from .errors import AccessDenied

MAX_PATH_CHARS = 4096
MAX_COMPONENT_UTF16 = 255
MAX_DEPTH = 32
_RESERVED = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"}
_RESERVED.update("COM%s" % c for c in "123456789\u00b9\u00b2\u00b3")
_RESERVED.update("LPT%s" % c for c in "123456789\u00b9\u00b2\u00b3")
_SHORTNAME = re.compile(r"^[^~]{1,6}~[0-9]+(\.[^.]{0,3})?$")
_BAD_CHARS = set('<>:"|?*')


def components(requested):
    """Return a tuple of validated components or raise AccessDenied."""
    if not isinstance(requested, str):
        raise AccessDenied("Path must be a string")
    if not requested or len(requested) > MAX_PATH_CHARS:
        raise AccessDenied("Empty or oversized path")
    if requested[0] in "\\/":
        raise AccessDenied("Rooted, UNC or device path denied")
    if len(requested) >= 2 and requested[1] == ":":
        raise AccessDenied("Drive-qualified path denied")
    parts = re.split(r"[\\/]", requested)
    if len(parts) > MAX_DEPTH:
        raise AccessDenied("Path too deep")
    for part in parts:
        _check_component(part)
    return tuple(parts)


def _check_component(part):
    if part in ("", ".", ".."):
        raise AccessDenied("Empty, current or parent component denied")
    try:
        units = len(part.encode("utf-16-le")) // 2
    except UnicodeEncodeError as exc:
        raise AccessDenied("Invalid Unicode (unpaired surrogate)") from exc
    if units > MAX_COMPONENT_UTF16:
        raise AccessDenied("Component too long")
    for ch in part:
        if ord(ch) < 32 or ord(ch) == 127 or ch in _BAD_CHARS:
            raise AccessDenied("Unsupported character in component")
        if unicodedata.category(ch) in ("Cf", "Cs", "Co", "Cn", "Zl", "Zp"):
            raise AccessDenied("Format, private or unassigned character denied")
    if part.endswith((".", " ")) or part.startswith(" "):
        raise AccessDenied("Leading space or trailing dot/space denied")
    stem = part.split(".", 1)[0].rstrip(" ").upper()
    if stem in _RESERVED:
        raise AccessDenied("Reserved device name denied")
    if _SHORTNAME.match(part):
        raise AccessDenied("Possible 8.3 short-name alias denied")


def _match(pattern_parts, parts):
    @lru_cache(maxsize=None)
    def visit(i, j):
        if i == len(pattern_parts):
            return j == len(parts)
        if pattern_parts[i] == '**':
            return visit(i + 1, j) or (j < len(parts) and visit(i, j + 1))
        return j < len(parts) and _glob_one(pattern_parts[i], parts[j]) and visit(i + 1, j + 1)
    return visit(0, 0)


def _glob_one(pattern, name):
    # Case-sensitive; only '*' (within one component) is special.
    # Only '*' is special. Avoid regex backtracking while preserving literal names.
    i = j = 0
    star = -1
    restart = 0
    while j < len(name):
        if i < len(pattern) and pattern[i] == name[j]:
            i += 1; j += 1
        elif i < len(pattern) and pattern[i] == '*':
            star = i; i += 1; restart = j
        elif star >= 0:
            restart += 1; j = restart; i = star + 1
        else:
            return False
    return all(c == '*' for c in pattern[i:])


def validate_pattern(pattern):
    if not isinstance(pattern, str) or not pattern:
        raise AccessDenied("Pattern must be a non-empty string")
    if pattern[0] in "\\/" or (len(pattern) > 1 and pattern[1] == ":"):
        raise AccessDenied("Patterns must be relative")
    parts = pattern.split("/")
    if len(pattern) > MAX_PATH_CHARS or len(parts) > MAX_DEPTH:
        raise AccessDenied('Pattern too long or too deep')
    for p in parts:
        if p == "**" or p == "*":
            continue
        _check_component(p.replace("*", "x"))
    return tuple(parts)


def matches(pattern, requested):
    """True when the validated request matches an allow pattern (exact case)."""
    parts = components(requested)
    return _match(validate_pattern(pattern), parts)
