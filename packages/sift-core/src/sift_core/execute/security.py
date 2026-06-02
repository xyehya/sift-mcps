"""Security utilities — argument sanitization, binary validation, path validation."""

from __future__ import annotations

import logging
import os
import re
import shlex
import unicodedata
from pathlib import Path

from sift_core.case_io import cases_root
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

    # The null device is always an allowed sink: '> /dev/null' and
    # '2> /dev/null' are ubiquitous, benign idioms for discarding output.
    if resolved == "/dev/null":
        return resolved

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

_DESTRUCTIVE_PATTERNS = [
    # Database destructive commands
    re.compile(r"\b(drop|truncate)\s+(table|database|schema)\b", re.IGNORECASE),
    re.compile(r"\bdelete\s+from\s+\w+[ \t]*(?:;|\"|'|\n|$)", re.IGNORECASE),
]

def _is_in_directory(path_str: str, parent: Path) -> bool:
    try:
        p = Path(path_str).absolute()
        par = parent.absolute()
        return p == par or p.is_relative_to(par)
    except Exception:
        return False


def split_command_by_operators(cmd_str: str) -> list[tuple[str, str]]:
    """Splits a command string by shell operators (&&, ||, |, ;).
    
    Returns a list of tuples: (subcommand_str, operator)
    """
    subcommands = []
    current = []
    state = "NORMAL"  # NORMAL, SINGLE, DOUBLE, ESCAPE
    i = 0
    n = len(cmd_str)
    
    while i < n:
        char = cmd_str[i]
        
        if state == "ESCAPE":
            current.append(char)
            state = "NORMAL"
            i += 1
            continue
            
        if char == "\\":
            current.append(char)
            state = "ESCAPE"
            i += 1
            continue
            
        if state == "SINGLE":
            current.append(char)
            if char == "'":
                state = "NORMAL"
            i += 1
            continue
            
        if state == "DOUBLE":
            current.append(char)
            if char == '"':
                state = "NORMAL"
            i += 1
            continue
            
        # NORMAL state
        if char == "'":
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
        if char == "\\":
            processed_chars.append(char)
            state = "ESCAPE"
            i += 1
            continue
        if state == "SINGLE":
            processed_chars.append(char)
            if char == "'":
                state = "NORMAL"
            i += 1
            continue
        if state == "DOUBLE":
            processed_chars.append(char)
            if char == '"':
                state = "NORMAL"
            i += 1
            continue
            
        if char == "'":
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


def validate_shell_command(command_str: str) -> list[dict[str, Any]]:
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
        case_dir_str = resolve_case_dir()
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
        if "/" in argv[0]:
            argv[0] = resolved

        # Validate redirection targets
        for op, target in redirects:
            if op == "2>&1":
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
                validate_output_path(target)
            elif op == "<":
                validate_input_path(target)
                
        # Validate argv paths
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
                        validate_output_path(value)
                    else:
                        validate_input_path(value)
                prev_was_output_flag = False
                continue
            if arg.startswith("-") and "=" not in arg:
                prev_was_output_flag = arg in output_flags
                continue
            if arg.startswith("/") or arg.startswith("..") or "/" in arg:
                if arg.startswith("/dev/") and binary in _DEV_PATH_TOOLS:
                    pass
                elif prev_was_output_flag:
                    validate_output_path(arg)
                else:
                     validate_input_path(arg)
            prev_was_output_flag = False
            
        # Sanitize extra args
        sanitize_extra_args(argv[1:], tool_name=binary)
        
        # rm protection
        if binary == "rm":
            validate_rm_targets(argv[1:])
            
        # Privileged target checks
        if binary in _PRIVILEGED_TARGETS:
            for arg in argv:
                for char in ["*", "?", "[", "]"]:
                     if char in arg:
                         raise ValueError(f"Wildcard/glob characters ('{char}') are not permitted in command arguments.")
                         
            case_dir_str = resolve_case_dir()
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
                if not any(_is_in_directory(target, d) for d in allowed_target_dirs):
                    raise ValueError("mount target directory must be inside the case tmp/, extractions/, or agent/ directories.")
                    
                source_ok = (
                    source.startswith("/dev/") or 
                    _is_in_directory(source, Path("/dev")) or
                    (case_dir and _is_in_directory(source, case_dir)) or
                    (cases_root_dir and _is_in_directory(source, cases_root_dir))
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
                if not any(_is_in_directory(target, d) for d in allowed_target_dirs):
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
                        if arg.startswith("/dev/") or _is_in_directory(arg, Path("/dev")):
                            continue
                        file_args.append(arg)
                    for farg in file_args:
                        ok = (
                            (case_dir and _is_in_directory(farg, case_dir)) or
                            (cases_root_dir and _is_in_directory(farg, cases_root_dir))
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
                    _is_in_directory(if_val, Path("/dev")) or
                    (case_dir and _is_in_directory(if_val, case_dir)) or
                    (cases_root_dir and _is_in_directory(if_val, cases_root_dir))
                )
                if not if_ok:
                    raise ValueError(f"{binary} if= source must be under /dev/*, inside the active case, or the cases root.")
                    
                if not case_dir:
                    raise ValueError("An active case is required to execute dd.")
                allowed_of_dirs = [case_dir / "agent", case_dir / "extractions", case_dir / "tmp"]
                if not any(_is_in_directory(of_val, d) for d in allowed_of_dirs):
                    raise ValueError(f"{binary} of= target must be under case agent/, extractions/, or tmp/ directories.")
                    
            elif binary == "fdisk":
                fdisk_flags = set(argv[1:])
                has_ro_flag = any(f in fdisk_flags for f in {"-l", "--list", "-s"})
                if not has_ro_flag:
                    raise ValueError("fdisk command is restricted to read-only inspection flags (-l, --list, -s).")
                    
        validated_stages.append({
            "subcmd_str": subcmd_str,
            "operator": operator,
            "argv": argv,
            "redirects": redirects,
            "binary": binary,
            "resolved": resolved,
            "privileged": binary in _PRIVILEGED_TARGETS,
        })
        
    return validated_stages

