"""Security utilities — argument sanitization, binary validation, path validation."""

from __future__ import annotations

import logging
import os
import re
import unicodedata
from pathlib import Path

from sift_core.case_io import cases_root

from sift_mcp.catalog import load_security_policy
from sift_mcp.config import resolve_case_dir

_DANGEROUS_PATTERNS = [";", "&&", "||", "`", "$(", "${"]
logger = logging.getLogger(__name__)


def _get_policy() -> dict:
    """Lazy-load security policy from YAML catalog."""
    return load_security_policy()


# awk can execute arbitrary commands via language syntax (not flags).
# Scan program text for dangerous constructs.
_AWK_DANGEROUS_RE = re.compile(
    r"system\s*\(|getline|\".*\||\|.*\"|>\s*\"|>>\s*\"", re.IGNORECASE
)

# Tools whose positional args are program text and need content scanning
_PROGRAM_TEXT_TOOLS = {"awk", "gawk", "mawk", "nawk"}


def sanitize_extra_args(extra_args: list[str], tool_name: str = "") -> list[str]:
    """Validate extra_args to block dangerous flags and shell metacharacters.

    Raises ValueError if a dangerous flag or pattern is detected.
    """
    if not extra_args:
        return []

    policy = _get_policy()
    tool_allowed = policy["tool_allowed_flags"].get(tool_name, set())
    tool_blocked = policy["tool_blocked_flags"].get(tool_name, set())

    sanitized = []
    for arg in extra_args:
        if not isinstance(arg, str):
            raise ValueError(f"Non-string argument in extra_args: {type(arg).__name__}")
        if "\x00" in arg:
            raise ValueError(f"Null byte in extra_args for {tool_name}")
        if len(arg) > 4096:
            raise ValueError(
                f"Argument too long ({len(arg)} chars) in extra_args for {tool_name}"
            )
        normalized = unicodedata.normalize("NFC", arg)
        if normalized != arg:
            logger.info(
                "Normalized non-NFC argument for %s: %r to %r",
                tool_name,
                arg,
                normalized,
            )
            arg = normalized
        flag = arg.lower().split("=")[0]
        if flag in tool_blocked:
            raise ValueError(f"Blocked dangerous flag '{arg}' for {tool_name}")
        if flag in policy["dangerous_flags"] and flag not in tool_allowed:
            raise ValueError(
                f"Blocked dangerous flag '{arg}' in extra_args for {tool_name}"
            )
        for pattern in _DANGEROUS_PATTERNS:
            if pattern in arg:
                raise ValueError(
                    f"Blocked shell metacharacter in extra_args for {tool_name}"
                )
        sanitized.append(arg)

    # Scan awk program text for dangerous constructs (system(), getline, pipes)
    if tool_name in _PROGRAM_TEXT_TOOLS:
        for arg in sanitized:
            if arg.startswith("-"):
                continue  # skip flags
            if _AWK_DANGEROUS_RE.search(arg):
                raise ValueError(
                    f"Blocked dangerous awk construct in program text for {tool_name}: "
                    f"system(), getline, and pipe operators are not allowed"
                )

    return sanitized


# Directories where rm is blocked (evidence storage, case data)
def _get_protected_dirs() -> tuple[str, ...]:
    """Resolve protected directories at runtime.

    The operator-configured cases root comes from the canonical
    :func:`sift_core.case_io.cases_root` resolver; ``/cases`` and ``/evidence``
    are kept as static defense-in-depth belts (well-known default mounts).
    """
    return (
        str(cases_root().resolve()),
        "/cases",
        "/evidence",
    )


def is_denied(binary_name: str) -> bool:
    """Check if a binary is on the hard denylist."""
    return binary_name.lower() in _get_policy()["denied_binaries"]


def validate_rm_targets(args: list[str]) -> None:
    """Block rm from targeting evidence storage directories.

    rm is allowed for general cleanup but blocked inside evidence
    storage locations. Also blocks rm -rf / patterns.
    """
    _RM_GUIDANCE = (
        " File deletion in case/evidence directories requires human action "
        "outside the AI session (forensic integrity control). "
        "Exit Claude Code, run the rm command directly, then return."
    )
    path_args = [a for a in args if not a.startswith("-")]
    for arg in path_args:
        resolved = str(Path(arg).resolve())
        if resolved == "/":
            raise ValueError("Blocked: rm targeting filesystem root")
        for protected in _get_protected_dirs():
            if resolved == protected or resolved.startswith(protected + "/"):
                raise ValueError(
                    f"Blocked: rm in protected directory '{protected}'." + _RM_GUIDANCE
                )
        case_dir = resolve_case_dir()
        if case_dir:
            case_resolved = str(Path(case_dir).resolve())
            if resolved == case_resolved or resolved.startswith(case_resolved + "/"):
                raise ValueError("Blocked: rm in case directory." + _RM_GUIDANCE)


_BLOCKED_DIRECTORIES = (
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    os.path.expanduser("~/.sift"),
)

# Exceptions within blocked directories (evidence data, not config)
_BLOCKED_EXCEPTIONS = (
    os.path.expanduser("~/.sift/cases"),
    os.path.expanduser("~/.sift/hayabusa-output"),
)


def get_output_flags() -> frozenset:
    """Return the set of flags that take output path values."""
    return _get_policy()["output_flags"]


# Directories blocked for output (superset of _BLOCKED_DIRECTORIES)
_OUTPUT_BLOCKED_DIRECTORIES = _BLOCKED_DIRECTORIES + (
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/var",
    "/home",
)


def validate_output_path(path: str) -> str:
    """Validate that an output path is safe to write to.

    Stricter than validate_input_path. When SIFT_CASE_DIR is set, the
    output path must be inside the case directory. When not set, only
    /tmp and the current working directory are allowed.

    Case-dir containment is checked first so that case directories
    under /home are allowed.
    """
    resolved = str(Path(path).resolve())

    # Case-dir containment: must resolve only under agent/, extractions/, or tmp/.
    case_dir = resolve_case_dir()
    if case_dir:
        case_resolved = Path(case_dir).resolve()
        allowed_subdirs = [
            case_resolved / "agent",
            case_resolved / "extractions",
            case_resolved / "tmp",
        ]
        for subdir in allowed_subdirs:
            if resolved == str(subdir) or resolved.startswith(str(subdir) + "/"):
                return resolved
        raise ValueError(
            f"Output path '{path}' must be inside the case agent, extractions, or tmp directory: "
            f"'{case_resolved}/agent/', '{case_resolved}/extractions/' or '{case_resolved}/tmp/'"
        )

    # No case dir: allow /tmp and cwd before checking blocked dirs
    if resolved.startswith("/tmp/") or resolved == "/tmp":
        return resolved
    cwd = str(Path.cwd().resolve())
    if resolved == cwd or resolved.startswith(cwd + "/"):
        return resolved

    # Block system directories
    for blocked in _OUTPUT_BLOCKED_DIRECTORIES:
        if resolved == blocked or resolved.startswith(blocked + "/"):
            raise ValueError(
                f"Output denied: path '{path}' resolves to '{resolved}' "
                f"which is inside blocked directory '{blocked}'"
            )

    raise ValueError(
        f"Output denied: path '{path}' resolves to '{resolved}'. "
        f"Without an active case, output is only allowed in /tmp or "
        f"the current working directory"
    )


def validate_input_path(path: str) -> str:
    """Validate that an input file path is not in a blocked system directory.

    Resolves symlinks, then checks against a blocklist of sensitive system
    directories. Also parses flag=value arguments and validates the value
    portion as a path. Raises ValueError if the resolved path falls within
    a blocked directory. Returns the resolved path string if valid.
    """
    # Handle flag=value arguments: validate the value portion as a path
    if "=" in path and path.startswith("-"):
        value = path.split("=", 1)[1]
        if value and (value.startswith("/") or value.startswith("..") or "/" in value):
            return validate_input_path(value)
        return path

    resolved = str(Path(path).resolve())
    for blocked in _BLOCKED_DIRECTORIES:
        if resolved == blocked or resolved.startswith(blocked + "/"):
            # Check if path falls within an allowed exception (evidence data)
            if any(
                resolved == exc or resolved.startswith(exc + "/")
                for exc in _BLOCKED_EXCEPTIONS
            ):
                break  # Allowed exception
            raise ValueError(
                f"Access denied: path '{path}' resolves to '{resolved}' "
                f"which is inside blocked system directory '{blocked}'"
            )
    return resolved
