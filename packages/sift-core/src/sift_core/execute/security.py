"""Security utilities — argument sanitization, binary validation, path validation."""

from __future__ import annotations

import logging
import os
import re
import shlex
import unicodedata
from pathlib import Path
from typing import Any

from sift_core.case_io import case_records_dir, cases_root
from sift_core.execute.environment import find_binary
from sift_core.execute.exceptions import DeniedBinaryError, ExecutionError

from sift_core.execute.catalog import load_security_policy
from sift_core.execute.config import resolve_case_dir
from sift_core.execute.security_policy import matches_allowed_binary, matches_denied_binary

_DANGEROUS_PATTERNS = ["`", "$("]
logger = logging.getLogger(__name__)

# Internal marker wrapped around redirection operators during parsing so that a
# real (unquoted) operator can be told apart from a quoted literal that happens
# to look like one (e.g. ``grep ">" file``). The marker is the control byte
# ``\x01``, which user input can never contain: validate_shell_command rejects
# the whole \x00-\x08 range, and parse_subcommand_argv_and_redirects guards
# against it directly. shlex.split keeps a \x01-wrapped token intact while a
# quoted literal stays as its bare text, making the two unambiguous.
_REDIR_MARK = "\x01"


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
    return matches_denied_binary(binary_name, _get_policy()["denied_binaries"])


def is_allowed_by_mode(binary_name: str) -> bool:
    """Check whether the current policy mode permits a binary.

    The denylist mode is the historical default: anything not denied can run.
    In allowlist mode, the binary must match an operator-configured allowlist
    pattern. The caller must still apply the denylist first.
    """
    policy = _get_policy()
    if policy.get("mode") != "allowlist":
        return True
    return matches_allowed_binary(
        binary_name, policy.get("allowed_binaries", frozenset())
    )


def _resolve_user_path(path: str, *, base_dir: str | Path | None = None) -> Path:
    raw = Path(path)
    if raw.is_absolute():
        return raw.resolve()
    root = Path(base_dir).resolve() if base_dir else Path.cwd().resolve()
    return (root / raw).resolve()


def _path_is_under(path: Path, parent: Path) -> bool:
    try:
        return path == parent or path.is_relative_to(parent)
    except ValueError:
        return False


def _active_case_dir_str() -> str:
    """Resolve the active case dir for policy decisions, DB-authority aware.

    Mirrors executor._active_or_env_case_dir: prefer the request-local
    AuthorityContext (set by the Gateway/worker from Postgres active-case state)
    over the legacy SIFT_CASE_DIR/pointer fallback. Without this, run_command's
    path validators see no case dir under DB authority and collapse to the
    "/tmp + cwd only" branch — the reason in-case writes were blocked even
    though the case dir is the (non-authoritative, see module note) working area.
    """
    try:
        from sift_core.active_case_context import current_active_case

        ctx = current_active_case()
        if ctx and ctx.case_dir is not None:
            return str(ctx.case_dir)
    except ImportError:  # pragma: no cover - defensive
        pass
    return resolve_case_dir()


def _case_dir_path() -> Path | None:
    case_dir = _active_case_dir_str()
    if not case_dir:
        return None
    return Path(case_dir).resolve()


def _case_writable_dirs(case_dir: Path) -> tuple[Path, ...]:
    return (case_dir / "agent", case_dir / "extractions", case_dir / "tmp")


def _case_protected_dirs(case_dir: Path, *, include_evidence: bool = True) -> tuple[Path, ...]:
    dirs = [case_records_dir(case_dir)]
    if include_evidence:
        dirs.append(case_dir / "evidence")
    # Temporary test cases keep legacy record shadows in the case root.
    dirs.append(case_dir / "audit")
    return tuple(path.resolve() for path in dirs)


def _case_protected_record_files(case_dir: Path) -> tuple[Path, ...]:
    names = (
        "approvals.jsonl",
        "evidence-ledger.jsonl",
        "evidence-manifest.json",
        "evidence-verify-state.json",
    )
    return tuple((case_dir / name).resolve() for name in names)


def _reject_if_protected_case_path(resolved: Path, *, action: str) -> None:
    case_dir = _case_dir_path()
    if not case_dir:
        return
    include_evidence = action.lower() != "read"
    for protected in _case_protected_dirs(case_dir, include_evidence=include_evidence):
        if _path_is_under(resolved, protected):
            raise ValueError(
                f"{action} denied: path '{resolved}' is inside protected case "
                f"directory '{protected}'. Evidence and integrity records are "
                "operator-controlled; write analysis outputs under agent/, "
                "extractions/, or tmp/."
            )
    for protected_file in _case_protected_record_files(case_dir):
        if resolved == protected_file:
            raise ValueError(
                f"{action} denied: path '{resolved}' is a protected integrity record."
            )


def _validate_case_output_target(path: str, *, base_dir: str | Path | None = None) -> str:
    resolved = _resolve_user_path(path, base_dir=base_dir)
    _reject_if_protected_case_path(resolved, action="Output")
    return validate_output_path(path, base_dir=base_dir)


def validate_rm_targets(args: list[str], *, base_dir: str | Path | None = None) -> None:
    """Block rm from targeting evidence storage directories.

    rm is allowed for general cleanup but blocked inside evidence
    storage locations. Also blocks rm -rf / patterns.
    """
    _RM_GUIDANCE = (
        " File deletion in case/evidence directories requires human action "
        "outside the AI session (forensic integrity control). "
        "Ask the operator to remove or retire the evidence through the portal or "
        "approved local evidence workflow; do not attempt a side-channel delete."
    )
    path_args = [a for a in args if not a.startswith("-")]
    for arg in path_args:
        resolved_path = _resolve_user_path(arg, base_dir=base_dir)
        resolved = str(resolved_path)
        if resolved_path == Path("/"):
            raise ValueError("Blocked: rm targeting filesystem root")
        case_dir = _active_case_dir_str()
        if case_dir:
            case_resolved_path = Path(case_dir).resolve()
            if any(_path_is_under(resolved_path, d) for d in _case_writable_dirs(case_resolved_path)):
                continue
            protected_roots = [case_resolved_path / "evidence", case_records_dir(case_resolved_path)]
            protected_roots.append(case_resolved_path / "audit")
            for protected in protected_roots:
                protected = protected.resolve()
                if _path_is_under(resolved_path, protected):
                    raise ValueError(
                        f"Blocked: rm in protected directory '{protected}'." + _RM_GUIDANCE
                    )
        for protected in _get_protected_dirs():
            protected_path = Path(protected).resolve()
            if _path_is_under(resolved_path, protected_path):
                raise ValueError(
                    f"Blocked: rm in protected directory '{protected}'." + _RM_GUIDANCE
                )


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


def validate_output_path(path: str, *, base_dir: str | Path | None = None) -> str:
    """Validate that an output path is safe to write to.

    In-case write posture (operator-approved): when an active case is resolved,
    run_command may write ANYWHERE under the active case directory EXCEPT the
    sealed-evidence dir and the protected integrity records. This is safe because
    nothing writable under the case dir is authoritative anymore — audit lives in
    Postgres (app.audit_events, append-only/hash-chained), the manifest/ledger are
    DB-authoritative (the files are export/proof only), and sealed evidence is
    chattr +i immutable. Fencing the agent to agent//extractions//tmp/ only
    crippled the save-output -> read-back -> filter loop for no security gain.

    HARD boundaries that stay (NOT relaxed):
      * sealed evidence/ and integrity records: write/mutation denied
        (_reject_if_protected_case_path) — belt-and-suspenders with chattr +i.
      * out-of-case + host paths: denied (only the ACTIVE case dir opens up;
        /var/lib/sift, /etc, other case dirs, mount points all stay blocked).

    When no active case is resolved, only /tmp and the current working directory
    are allowed (unchanged).
    """
    resolved = str(_resolve_user_path(path, base_dir=base_dir))

    # The null device is always an allowed sink: '> /dev/null' and
    # '2> /dev/null' are ubiquitous, benign idioms for discarding output.
    if resolved == "/dev/null":
        return resolved

    # Case-dir containment (DB-authority aware): allow anywhere under the active
    # case dir except sealed evidence + protected integrity records.
    case_dir = _active_case_dir_str()
    if case_dir:
        case_resolved = Path(case_dir).resolve()
        resolved_path = Path(resolved)
        if _path_is_under(resolved_path, case_resolved):
            # Deny only the sealed-evidence dir and protected integrity records;
            # everything else under the case dir is writable scratch.
            _reject_if_protected_case_path(resolved_path, action="Output")
            return resolved
        raise ValueError(
            f"Output path '{path}' resolves to '{resolved}', outside the active "
            f"case directory '{case_resolved}'. run_command may only write under "
            "the active case dir (excluding evidence/ and integrity records)."
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


def validate_input_path(path: str, *, base_dir: str | Path | None = None) -> str:
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
            return validate_input_path(value, base_dir=base_dir)
        return path

    resolved_path = _resolve_user_path(path, base_dir=base_dir)
    _reject_if_protected_case_path(resolved_path, action="Read")
    resolved = str(resolved_path)
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


# Tools that legitimately use /dev/ paths as device specifiers
_DEV_PATH_TOOLS = {
    "mount",
    "umount",
    "mmls",
    "fls",
    "icat",
    "img_stat",
    "blkid",
    "fdisk",
    "losetup",
    "fsstat",
    "ifind",
    "istat",
    "mmcat",
    "sigfind",
    "tsk_recover",
    "sorter",
    "dd",
}

_PRIVILEGED_TARGETS = {
    "mount", "umount", "losetup", "blkid", "fdisk",
    "dd", "dc3dd", "dcfldd", "vol", "vol3", "palso", "yara"
}

_MUTATING_POSITIONAL_TOOLS = {
    "chmod",
    "chown",
    "chgrp",
    "cp",
    "install",
    "mkdir",
    "mv",
    "rm",
    "rmdir",
    "rsync",
    "setfacl",
    "tee",
    "touch",
    "truncate",
}

_DESTRUCTIVE_PATTERNS = [
    # Database destructive commands
    re.compile(r"\b(drop|truncate)\s+(table|database|schema)\b", re.IGNORECASE),
    re.compile(r"\bdelete\s+from\s+\w+[ \t]*(?:;|\"|'|\n|$)", re.IGNORECASE),
]

def _is_in_directory(
    path_str: str, parent: Path, *, base_dir: str | Path | None = None
) -> bool:
    try:
        p = _resolve_user_path(path_str, base_dir=base_dir)
        par = parent.resolve()
        return p == par or p.is_relative_to(par)
    except Exception:
        return False


def split_command_by_operators(cmd_str: str) -> list[tuple[str, str]]:
    """Splits a command string by shell operators (&&, ||, |, ;).
    
    Returns a list of tuples: (subcommand_str, operator)
    """
    subcommands = []
    current = []
    state = "NORMAL"  # NORMAL, SINGLE, DOUBLE, ESCAPE, ESCAPE_DOUBLE
    i = 0
    n = len(cmd_str)
    
    while i < n:
        char = cmd_str[i]
        
        if state == "ESCAPE":
            current.append(char)
            state = "NORMAL"
            i += 1
            continue
            
        if state == "ESCAPE_DOUBLE":
            current.append(char)
            state = "DOUBLE"
            i += 1
            continue
            
        if state == "SINGLE":
            current.append(char)
            if char == "'":
                state = "NORMAL"
            i += 1
            continue
            
        if state == "DOUBLE":
            if char == "\\":
                current.append(char)
                state = "ESCAPE_DOUBLE"
                i += 1
                continue
            current.append(char)
            if char == '"':
                state = "NORMAL"
            i += 1
            continue
            
        # NORMAL state
        if char == "\\":
            current.append(char)
            state = "ESCAPE"
            i += 1
            continue
        elif char == "'":
            current.append(char)
            state = "SINGLE"
            i += 1
            continue
        elif char == '"':
            current.append(char)
            state = "DOUBLE"
            i += 1
            continue
            
        # Check operators
        if cmd_str[i:i+2] == "&&":
            subcommands.append(("".join(current).strip(), "&&"))
            current = []
            i += 2
            continue
        elif cmd_str[i:i+2] == "||":
            subcommands.append(("".join(current).strip(), "||"))
            current = []
            i += 2
            continue
        elif char == "&":
            # Do not split when '&' is part of a redirection (2>&1, >&, &>).
            # Stderr handling is dealt with by the redirect parser, not as a
            # statement separator.
            nxt = cmd_str[i + 1] if i + 1 < n else ""
            prev = next((c for c in reversed(current) if not c.isspace()), "")
            if nxt == ">" or prev == ">":
                current.append(char)
                i += 1
                continue
            subcommands.append(("".join(current).strip(), "&"))
            current = []
            i += 1
            continue
        elif char in ("\n", "\r"):
            subcommands.append(("".join(current).strip(), ";"))
            current = []
            i += 1
            continue
        elif char == "|":
            subcommands.append(("".join(current).strip(), "|"))
            current = []
            i += 1
            continue
        elif char == ";":
            subcommands.append(("".join(current).strip(), ";"))
            current = []
            i += 1
            continue
            
        current.append(char)
        i += 1
        
    if current:
        subcommands.append(("".join(current).strip(), ""))
        
    return subcommands


def parse_subcommand_argv_and_redirects(subcmd_str: str) -> tuple[list[str], list[tuple[str, str]]]:
    """Parses a subcommand string into an argv list and a list of redirects.
    
    E.g. "ls -la > out.txt" -> (["ls", "-la"], [(">", "out.txt")])
    """
    if "\x00" in subcmd_str or _REDIR_MARK in subcmd_str:
        raise ValueError("Command contains non-printable control characters")

    processed_chars = []
    state = "NORMAL"
    i = 0
    n = len(subcmd_str)

    while i < n:
        char = subcmd_str[i]
        if state == "ESCAPE":
            processed_chars.append(char)
            state = "NORMAL"
            i += 1
            continue
        if state == "ESCAPE_DOUBLE":
            processed_chars.append(char)
            state = "DOUBLE"
            i += 1
            continue
        if state == "SINGLE":
            processed_chars.append(char)
            if char == "'":
                state = "NORMAL"
            i += 1
            continue
        if state == "DOUBLE":
            if char == "\\":
                processed_chars.append(char)
                state = "ESCAPE_DOUBLE"
                i += 1
                continue
            processed_chars.append(char)
            if char == '"':
                state = "NORMAL"
            i += 1
            continue
            
        if char == "\\":
            processed_chars.append(char)
            state = "ESCAPE"
            i += 1
            continue
        elif char == "'":
            processed_chars.append(char)
            state = "SINGLE"
            i += 1
            continue
        elif char == '"':
            processed_chars.append(char)
            state = "DOUBLE"
            i += 1
            continue
            
        # Stderr / combined redirections. Supported forms: '2>&1' (merge stderr
        # into stdout/pipe), '2>'/'2>>' (stderr to file), and '&>'/'&>>' (both
        # streams to file). Exotic fd duplication (e.g. '>&2', '1>&2', '3>')
        # has no forensic use and is rejected with a clear message. Each
        # supported operator is wrapped in _REDIR_MARK so a quoted literal that
        # looks the same stays an argument.
        if subcmd_str[i:i+4] == "2>&1":
            processed_chars.append(f" {_REDIR_MARK}2>&1{_REDIR_MARK} ")
            i += 4
            continue
        if subcmd_str[i:i+3] == "2>>":
            processed_chars.append(f" {_REDIR_MARK}2>>{_REDIR_MARK} ")
            i += 3
            continue
        if subcmd_str[i:i+2] == "2>":
            processed_chars.append(f" {_REDIR_MARK}2>{_REDIR_MARK} ")
            i += 2
            continue
        if subcmd_str[i:i+3] == "&>>":
            processed_chars.append(f" {_REDIR_MARK}&>>{_REDIR_MARK} ")
            i += 3
            continue
        if subcmd_str[i:i+2] == "&>":
            processed_chars.append(f" {_REDIR_MARK}&>{_REDIR_MARK} ")
            i += 2
            continue
        if subcmd_str[i:i+2] == ">&" or (char.isdigit() and subcmd_str[i+1:i+2] == ">"):
            raise ValueError(
                "Unsupported redirection: only '2>&1', '2>'/'2>>' (stderr to file), "
                "and '&>'/'&>>' (both streams to file) are allowed; "
                "file-descriptor duplication like '>&N' or '1>&2' is not."
            )

        # Redirection operators. Each is wrapped in the _REDIR_MARK sentinel so a
        # genuine unquoted operator stays distinguishable from a quoted literal
        # (e.g. ``grep ">" file`` must keep ">" as an argument, not a redirect).
        if subcmd_str[i:i+2] == ">>":
            processed_chars.append(f" {_REDIR_MARK}>>{_REDIR_MARK} ")
            i += 2
            continue
        elif char == ">":
            processed_chars.append(f" {_REDIR_MARK}>{_REDIR_MARK} ")
            i += 1
            continue
        elif subcmd_str[i:i+2] == "<<":
            processed_chars.append(f" {_REDIR_MARK}<<{_REDIR_MARK} ")
            i += 2
            continue
        elif char == "<":
            processed_chars.append(f" {_REDIR_MARK}<{_REDIR_MARK} ")
            i += 1
            continue
            
        processed_chars.append(char)
        i += 1
        
    spaced_str = "".join(processed_chars)
    tokens = shlex.split(spaced_str, comments=True)
    
    argv = []
    redirects = []
    
    j = 0
    num_tokens = len(tokens)
    while j < num_tokens:
        tok = tokens[j]
        # A redirect operator is only the sentinel-wrapped form emitted above;
        # a bare ">"/"<"/"2>&1" token here came from quoted input and is a
        # literal argument.
        op = (
            tok[len(_REDIR_MARK):-len(_REDIR_MARK)]
            if tok.startswith(_REDIR_MARK) and tok.endswith(_REDIR_MARK) and len(tok) > 2 * len(_REDIR_MARK)
            else None
        )
        if op == "2>&1":
            redirects.append(("2>&1", ""))
            j += 1
            continue
        if op in (">", ">>", "<", "<<", "2>", "2>>", "&>", "&>>"):
            if j + 1 < num_tokens:
                target = tokens[j + 1]
                redirects.append((op, target))
                j += 2
            else:
                raise ValueError(f"Redirection operator '{op}' lacks a target path")
        else:
            argv.append(tok)
            j += 1

    return argv, redirects


def _path_args(argv: list[str]) -> list[str]:
    return [arg for arg in argv[1:] if arg and not arg.startswith("-")]


def _validate_no_protected_targets(
    paths: list[str], *, base_dir: str | Path | None, action: str
) -> None:
    for path in paths:
        if "=" in path and path.startswith("-"):
            continue
        resolved = _resolve_user_path(path, base_dir=base_dir)
        _reject_if_protected_case_path(resolved, action=action)


def validate_mutating_command_targets(
    binary: str, argv: list[str], *, base_dir: str | Path | None = None
) -> None:
    """Validate common file-mutating tools against the case write policy."""
    path_args = _path_args(argv)
    if not path_args:
        return

    if binary == "rm":
        validate_rm_targets(argv[1:], base_dir=base_dir)
        return

    if binary in {"mkdir", "rmdir", "touch", "truncate", "tee"}:
        for target in path_args:
            _validate_case_output_target(target, base_dir=base_dir)
        return

    if binary == "cp":
        if len(path_args) >= 2:
            for source in path_args[:-1]:
                validate_input_path(source, base_dir=base_dir)
            _validate_case_output_target(path_args[-1], base_dir=base_dir)
        return

    if binary == "mv":
        if len(path_args) >= 2:
            _validate_no_protected_targets(
                path_args[:-1], base_dir=base_dir, action="Move"
            )
            _validate_case_output_target(path_args[-1], base_dir=base_dir)
        return

    if binary in {"chmod", "chown", "chgrp", "setfacl"}:
        _validate_no_protected_targets(path_args, base_dir=base_dir, action="Metadata change")
        return

    if binary in {"install", "rsync"} and len(path_args) >= 2:
        for source in path_args[:-1]:
            validate_input_path(source, base_dir=base_dir)
        _validate_case_output_target(path_args[-1], base_dir=base_dir)


def validate_shell_command(
    command_str: str, *, cwd: str | Path | None = None
) -> list[dict[str, Any]]:
    """Validate a shell command string for safety across all subcommands.
    
    Returns a list of parsed and validated subcommand dictionaries.
    Raises ValueError or DeniedBinaryError if validation fails.
    """
    if not command_str.strip():
        raise ValueError("Empty command string")

    # 1. Block control characters
    if re.search(r"[\x00-\x08\x0E-\x1F\x7F]", command_str):
        raise ValueError("Command contains non-printable control characters that could bypass security checks")
        
    # 2. Block IFS Injection
    if re.search(r"\bIFS\s*=", command_str):
        raise ValueError("Modifying the IFS variable is blocked by security policy")
        
    # 3. Block Proc/Environ access
    if re.search(r"/proc/\w+/environ|/proc/self/environ", command_str):
        raise ValueError("Direct access to process environment info is blocked")

    # 4. Block Process Substitution
    if re.search(r">>\s*>\s*\(|>\s*>\s*\(|<\s*\(", command_str):
        raise ValueError("Process substitution (>(...) or <(...)) is blocked by security policy")

    # 5. Check Destructive Patterns
    for pattern in _DESTRUCTIVE_PATTERNS:
        if pattern.search(command_str):
            raise ValueError("Command matches a blocked destructive pattern")

    # 6. Parse and check subcommands
    validated_stages = []
    subcmds = split_command_by_operators(command_str)
    for subcmd_str, operator in subcmds:
        if operator == "&":
            raise ValueError(
                "Background operator '&' is not supported by run_command. "
                "Use a tool-specific persistent mount command, or run a separate "
                "foreground command."
            )
        if not subcmd_str.strip():
            continue
            
        argv, redirects = parse_subcommand_argv_and_redirects(subcmd_str)
        if not argv:
            raise ValueError("Empty subcommand in pipeline/logical chain")
            
        binary = argv[0].split('/')[-1]
        
        # Deny sudo
        if binary == "sudo":
            raise DeniedBinaryError("Agent-supplied sudo is blocked. Commands must be run directly.")
            
        # Allowed/Denied Binary Check
        if is_denied(binary):
            raise DeniedBinaryError(
                f"Binary '{binary}' is blocked by security policy. "
                f"This restriction cannot be overridden."
            )
        if not is_allowed_by_mode(binary):
            raise DeniedBinaryError(
                f"Binary '{binary}' is not allowed by execute.security allowlist mode."
            )
            
        # Resolve binary via find_binary
        resolved = find_binary(binary)
        if not resolved:
            raise ValueError(f"Binary '{binary}' not found on this system.")

        # P2.3 (Basename-Evasion Prevention): Verify resolved binary is not in the case directory
        case_dir_str = _active_case_dir_str()
        if case_dir_str:
            case_resolved = Path(case_dir_str).resolve()
            resolved_path = Path(resolved).resolve()
            if resolved_path == case_resolved or case_resolved in resolved_path.parents:
                raise ValueError(
                    f"Binary '{binary}' resolves to '{resolved_path}' "
                    f"which is inside the case directory '{case_resolved}'"
                )

        # Path-shadow prevention: when the caller supplies a path (not a bare
        # name), execute the validated *resolved* binary rather than the literal
        # argv[0]. Otherwise a file named after an allowed tool (e.g. a copy of
        # python3 at <case>/tmp/ls, referenced as ./ls) would pass basename
        # validation yet execute the attacker-controlled file. find_binary()
        # resolves by basename via PATH / forensic dirs, so `resolved` is the
        # exact binary that was validated above.
        argv[0] = resolved

        # Validate redirection targets
        resolved_redirects = []
        for op, target in redirects:
            if op == "2>&1":
                resolved_redirects.append((op, target))
                # stderr-into-stdout merge: no path to validate.
                continue
            if op == "<<":
                raise ValueError(
                    "Heredocs ('<<') are not supported by run_command. "
                    "Use an input file with '<' instead."
                )
            if "$" in target or "%" in target:
                raise ValueError("Shell expansion syntax in paths is blocked by security policy")
            if op in (">", ">>", "2>", "2>>", "&>", "&>>"):
                resolved_target = validate_output_path(target, base_dir=cwd)
            elif op == "<":
                resolved_target = validate_input_path(target, base_dir=cwd)
            else:
                resolved_target = target
            resolved_redirects.append((op, resolved_target))
                
        # Validate argv paths. Common mutating positional tools need
        # command-specific source/destination handling, so do not treat every
        # path-looking positional argument as an input.
        if binary in _MUTATING_POSITIONAL_TOOLS:
            validate_mutating_command_targets(binary, argv, base_dir=cwd)
        else:
            output_flags = get_output_flags()
            prev_was_output_flag = False
            for arg in argv[1:]:
                if "=" in arg and arg.startswith("-"):
                    flag_part = arg.split("=", 1)[0]
                    value = arg.split("=", 1)[1]
                    if value and (value.startswith("/") or value.startswith("..") or "/" in value):
                        if value.startswith("/dev/") and binary in _DEV_PATH_TOOLS:
                            pass
                        elif flag_part in output_flags:
                            validate_output_path(value, base_dir=cwd)
                        else:
                            validate_input_path(value, base_dir=cwd)
                    prev_was_output_flag = False
                    continue
                if arg.startswith("-") and "=" not in arg:
                    prev_was_output_flag = arg in output_flags
                    continue
                if arg.startswith("/") or arg.startswith("..") or "/" in arg:
                    if arg.startswith("/dev/") and binary in _DEV_PATH_TOOLS:
                        pass
                    elif prev_was_output_flag:
                        validate_output_path(arg, base_dir=cwd)
                    else:
                        validate_input_path(arg, base_dir=cwd)
                prev_was_output_flag = False
            
        # Sanitize extra args
        sanitize_extra_args(argv[1:], tool_name=binary)
        
        # rm protection
            
        # Privileged target checks
        if binary in _PRIVILEGED_TARGETS:
            for arg in argv:
                for char in ["*", "?", "[", "]"]:
                     if char in arg:
                         raise ValueError(f"Wildcard/glob characters ('{char}') are not permitted in command arguments.")
                         
            case_dir_str = _active_case_dir_str()
            case_dir = Path(case_dir_str) if case_dir_str else None
            cases_root_dir = cases_root()
            
            if binary == "mount":
                positional_args = [arg for arg in argv[1:] if not arg.startswith("-")]
                if len(positional_args) < 2:
                    raise ValueError("mount command requires at least source and target arguments.")
                source = positional_args[-2]
                target = positional_args[-1]
                
                if not case_dir:
                    raise ValueError("An active case is required to execute mount.")
                allowed_target_dirs = [case_dir / "tmp", case_dir / "extractions", case_dir / "agent"]
                if not any(_is_in_directory(target, d, base_dir=cwd) for d in allowed_target_dirs):
                    raise ValueError("mount target directory must be inside the case tmp/, extractions/, or agent/ directories.")
                    
                source_ok = (
                    source.startswith("/dev/") or 
                    _is_in_directory(source, Path("/dev"), base_dir=cwd) or
                    (case_dir and _is_in_directory(source, case_dir, base_dir=cwd)) or
                    (cases_root_dir and _is_in_directory(source, cases_root_dir, base_dir=cwd))
                )
                if not source_ok:
                    raise ValueError("mount source must be under /dev/*, inside the active case, or the cases root.")
                    
            elif binary == "umount":
                positional_args = [arg for arg in argv[1:] if not arg.startswith("-")]
                if len(positional_args) < 1:
                    raise ValueError("umount command requires a target argument.")
                target = positional_args[-1]
                
                if not case_dir:
                    raise ValueError("An active case is required to execute umount.")
                allowed_target_dirs = [case_dir / "tmp", case_dir / "extractions", case_dir / "agent"]
                if not any(_is_in_directory(target, d, base_dir=cwd) for d in allowed_target_dirs):
                    raise ValueError("umount target must be under case controlled mount directories (tmp/, extractions/, or agent/).")
                    
            elif binary == "losetup":
                losetup_flags = set(argv[1:])
                is_list_or_detach = any(
                    f in losetup_flags 
                    for f in {"-a", "--all", "-l", "--list", "-j", "--associated", "-d", "--detach"}
                )
                if not is_list_or_detach:
                    if not any(f in losetup_flags for f in {"-r", "--read-only"}):
                        raise ValueError("losetup loop device setup requires the read-only flag (-r or --read-only).")
                    positional_args = [arg for arg in argv[1:] if not arg.startswith("-")]
                    file_args = []
                    for arg in positional_args:
                        if arg.startswith("/dev/") or _is_in_directory(arg, Path("/dev"), base_dir=cwd):
                            continue
                        file_args.append(arg)
                    for farg in file_args:
                        ok = (
                            (case_dir and _is_in_directory(farg, case_dir, base_dir=cwd)) or
                            (cases_root_dir and _is_in_directory(farg, cases_root_dir, base_dir=cwd))
                        )
                        if not ok:
                            raise ValueError(f"losetup file target '{farg}' must be inside the active case or cases root.")
                            
            elif binary in {"dd", "dc3dd", "dcfldd"}:
                if_val = None
                of_val = None
                for arg in argv[1:]:
                    if arg.startswith("if="):
                        if_val = arg.split("=", 1)[1]
                    elif arg.startswith("of="):
                        of_val = arg.split("=", 1)[1]
                        
                if if_val is None or of_val is None:
                    raise ValueError(f"{binary} requires explicit if= and of= parameters.")
                    
                if_ok = (
                    if_val.startswith("/dev/") or 
                    _is_in_directory(if_val, Path("/dev"), base_dir=cwd) or
                    (case_dir and _is_in_directory(if_val, case_dir, base_dir=cwd)) or
                    (cases_root_dir and _is_in_directory(if_val, cases_root_dir, base_dir=cwd))
                )
                if not if_ok:
                    raise ValueError(f"{binary} if= source must be under /dev/*, inside the active case, or the cases root.")
                    
                if not case_dir:
                    raise ValueError("An active case is required to execute dd.")
                # In-case write posture: dd may write anywhere under the active
                # case dir except sealed evidence + protected integrity records
                # (same rule as validate_output_path / redirect targets).
                of_resolved = _resolve_user_path(of_val, base_dir=cwd)
                if not _path_is_under(of_resolved, case_dir.resolve()):
                    raise ValueError(
                        f"{binary} of= target '{of_val}' must be inside the active case directory."
                    )
                _reject_if_protected_case_path(of_resolved, action="Output")
                    
            elif binary == "fdisk":
                fdisk_flags = set(argv[1:])
                has_ro_flag = any(f in fdisk_flags for f in {"-l", "--list", "-s"})
                if not has_ro_flag:
                    raise ValueError("fdisk command is restricted to read-only inspection flags (-l, --list, -s).")
                    
        validated_stages.append({
            "subcmd_str": subcmd_str,
            "operator": operator,
            "argv": argv,
            "redirects": resolved_redirects,
            "binary": binary,
            "resolved": resolved,
            "privileged": binary in _PRIVILEGED_TARGETS,
        })

    return validated_stages


# ---------------------------------------------------------------------------
# BATCH-I1: evidence-ref / output-ref resolution + agent-facing path sanitizer
# ---------------------------------------------------------------------------
#
# run_command is the only forensic-CLI surface the agent can reach. The agent
# must never hand us an absolute case/evidence/mount path, and must never see
# one back. These helpers turn opaque references into the absolute paths the
# worker needs *inside* policy code, and collapse any path-like value down to a
# case-relative display path (or a redaction marker) before it leaves the tool.
#
# Resolution is fail-closed: an evidence ref must resolve to an ACTIVE entry in
# the sealed manifest, so the agent can only operate on evidence the operator
# has already registered and sealed (the evidence-gate / seal posture upstream
# still applies; this is the in-process belt).


class EvidenceRefError(ValueError):
    """An evidence/output reference could not be resolved to a sealed target."""


def _evidence_manifest_entries(case_dir: Path) -> list[dict]:
    """ACTIVE sealed-manifest entries for the active case (empty if unsealed)."""
    try:
        from sift_core.evidence_chain import load_manifest

        manifest = load_manifest(case_dir)
    except Exception:  # pragma: no cover - defensive against packaging issues
        return []
    if not manifest:
        return []
    return [
        f
        for f in manifest.get("files", [])
        if isinstance(f, dict) and f.get("status") == "ACTIVE"
    ]


def resolve_evidence_ref(ref: str, *, case_dir: str | Path | None = None) -> str:
    """Resolve an opaque evidence reference to an absolute path under evidence/.

    A reference is matched, in order, against the ACTIVE entries of the sealed
    evidence manifest by:
      * exact ``evidence_id`` (manifest entry ``evidence_id`` / ``id``),
      * exact relative display ``path`` (e.g. ``evidence/disk.E01``),
      * basename of the relative path (e.g. ``disk.E01``).

    Returns the absolute path the worker should read. Raises EvidenceRefError if
    no active sealed entry matches — the agent cannot reach arbitrary paths and
    cannot reach unsealed/ignored/retired evidence through this door.
    """
    if not isinstance(ref, str) or not ref.strip():
        raise EvidenceRefError("evidence reference must be a non-empty string")
    ref = ref.strip()
    if "\x00" in ref:
        raise EvidenceRefError("evidence reference contains a null byte")

    case_str = str(case_dir) if case_dir else _active_case_dir_str()
    if not case_str:
        raise EvidenceRefError(
            "No active case: an evidence reference can only be resolved with an "
            "active sealed case."
        )
    case_resolved = Path(case_str).resolve()

    entries = _evidence_manifest_entries(case_resolved)
    if not entries:
        raise EvidenceRefError(
            f"Evidence reference '{ref}' could not be resolved: the case has no "
            "sealed evidence. Ask the operator to register and seal evidence "
            "via the Examiner Portal first."
        )

    match: dict | None = None
    for entry in entries:
        rel = str(entry.get("path", ""))
        ev_id = str(entry.get("evidence_id") or entry.get("id") or "")
        if ref == ev_id or ref == rel or ref == Path(rel).name:
            match = entry
            break
    if match is None:
        raise EvidenceRefError(
            f"Evidence reference '{ref}' does not match any sealed evidence in "
            "this case. Reference sealed evidence by its evidence_id or relative "
            "display path."
        )

    rel_path = str(match.get("path", ""))
    # Reuse the input-path jail so the resolved target is provably inside the
    # case and never escapes via traversal in a manifest entry.
    resolved = _resolve_user_path(rel_path, base_dir=case_resolved)
    if not (resolved == case_resolved or resolved.is_relative_to(case_resolved)):
        raise EvidenceRefError(
            f"Evidence reference '{ref}' resolves outside the case directory."
        )
    return str(resolved)


def resolve_output_ref(ref: str, *, case_dir: str | Path | None = None) -> str:
    """Resolve a logical output-ref name to an absolute path under agent/.

    The agent supplies a short logical name (no separators, no traversal); the
    real, writable location is chosen here — always inside ``agent/run_commands``
    — so the agent never picks an output path. Reuses validate_output_path so the
    result is provably inside the case write-jail (agent/extractions/tmp).
    """
    if not isinstance(ref, str) or not ref.strip():
        raise EvidenceRefError("output reference must be a non-empty string")
    ref = ref.strip()
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in ref)[:80]
    safe = safe.strip("._") or "output"
    if ".." in safe or "/" in safe or "\x00" in safe:
        raise EvidenceRefError("output reference must not contain path separators")

    case_str = str(case_dir) if case_dir else _active_case_dir_str()
    if not case_str:
        raise EvidenceRefError(
            "No active case: an output reference can only be resolved with an "
            "active case."
        )
    case_resolved = Path(case_str).resolve()
    target = case_resolved / "agent" / "run_commands" / safe
    allowed_subdirs = _case_writable_dirs(case_resolved)
    if not any(target == subdir or target.is_relative_to(subdir) for subdir in allowed_subdirs):
        raise EvidenceRefError("output reference resolved outside the case write jail")
    return str(target)


_SENSITIVE_PATH_PREFIXES = (
    "/cases",
    "/evidence",
    "/mnt",
    "/media",
    "/var/lib/sift",
    "/dev",
)


# A path-like token: an absolute POSIX path. The negative lookbehind ensures the
# leading '/' is not preceded by a path/word character, so a *relative* path like
# ``agent/run_commands/out`` is not mistaken for an absolute one (its inner '/'
# follows a word char). Used to scrub embedded absolute paths inside free-text
# tool output (stdout/stderr) without nuking the whole blob.
_ABS_PATH_TOKEN_RE = re.compile(r"(?<![\w./])/[A-Za-z0-9._\-/]+")


def _sensitive_prefixes() -> tuple[str, ...]:
    """Static sensitive mounts plus the operator-configured cases/state roots."""
    prefixes = list(_SENSITIVE_PATH_PREFIXES)
    try:
        prefixes.append(str(cases_root().resolve()))
    except Exception:  # pragma: no cover - defensive
        pass
    state = os.environ.get("SIFT_STATE_DIR")
    if state:
        prefixes.append(str(Path(state).resolve()))
    return tuple(prefixes)


def _redact_abs_token(
    token: str, case_resolved: Path | None, sensitive: tuple[str, ...]
) -> str:
    if case_resolved is not None:
        try:
            candidate = Path(token).resolve()
            if candidate == case_resolved or candidate.is_relative_to(case_resolved):
                return str(candidate.relative_to(case_resolved))
        except (OSError, ValueError):
            pass
        # An in-case path may not exist on disk (e.g. a planned output ref);
        # fall back to a textual relative-prefix check before redacting.
        case_prefix = str(case_resolved) + "/"
        if token == str(case_resolved):
            return "."
        if token.startswith(case_prefix):
            return token[len(case_prefix):]
    # Only redact paths that could leak case/evidence/mount/device/state
    # geography. Benign system locations (resolved tool binaries under /usr,
    # /bin, etc.) are left intact so provenance/command echoes stay readable.
    if any(token == p or token.startswith(p + "/") for p in sensitive):
        return "[REDACTED:absolute_path]"
    return token


def sanitize_path_value(value: str, *, case_dir: str | Path | None = None) -> str:
    """Collapse absolute, path-like content to an agent-safe form.

    In-case absolute paths become case-relative display paths; any other
    absolute path that looks like a host/case/evidence/mount location becomes
    ``[REDACTED:absolute_path]``. For a value that is exactly one absolute path
    the whole value is rewritten; for free text (stdout/stderr) every embedded
    absolute-path token is rewritten in place so the surrounding text survives.

    This mirrors the Gateway MCP choke-point redaction (BATCH-B1) but runs at
    the tool boundary so a path never even reaches the transport in the clear.
    """
    if not isinstance(value, str) or "/" not in value:
        return value
    case_str = str(case_dir) if case_dir else _active_case_dir_str()
    case_resolved: Path | None = None
    if case_str:
        try:
            case_resolved = Path(case_str).resolve()
        except (OSError, ValueError):
            case_resolved = None

    sensitive = _sensitive_prefixes()
    stripped = value.strip()
    # Exact single-token absolute path (the common case for path fields).
    if stripped.startswith("/") and stripped == value and " " not in value and "\n" not in value:
        return _redact_abs_token(value, case_resolved, sensitive)

    # Free text: rewrite each embedded absolute-path token in place.
    return _ABS_PATH_TOKEN_RE.sub(
        lambda m: _redact_abs_token(m.group(0), case_resolved, sensitive), value
    )


def sanitize_paths_deep(obj: Any, *, case_dir: str | Path | None = None) -> Any:
    """Recursively sanitize every path-like string in a response structure."""
    if isinstance(obj, str):
        return sanitize_path_value(obj, case_dir=case_dir)
    if isinstance(obj, dict):
        return {k: sanitize_paths_deep(v, case_dir=case_dir) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        sanitized = [sanitize_paths_deep(v, case_dir=case_dir) for v in obj]
        return type(obj)(sanitized) if isinstance(obj, tuple) else sanitized
    return obj
