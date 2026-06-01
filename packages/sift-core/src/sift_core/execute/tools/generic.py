"""Generic run_command: denylist-protected execution of forensic tools."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

from sift_core.case_io import cases_root
from sift_core.execute.catalog import get_tool_def
from sift_core.execute.config import get_config, resolve_case_dir
from sift_core.execute.environment import find_binary
from sift_core.execute.exceptions import DeniedBinaryError, ExecutionError
from sift_core.execute.executor import execute
from sift_core.execute.security import (
    get_output_flags,
    is_allowed_by_mode,
    is_denied,
    sanitize_extra_args,
    validate_input_path,
    validate_output_path,
    validate_rm_targets,
)

logger = logging.getLogger(__name__)

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


@dataclass
class CommandPlan:
    original_argv: list[str]
    direct_argv: list[str]
    binary: str
    privileged_candidate: bool
    output_paths: list[str]
    input_paths: list[str]


def _is_in_directory(path_str: str, parent: Path) -> bool:
    try:
        p = Path(path_str).absolute()
        par = parent.absolute()
        return p == par or p.is_relative_to(par)
    except Exception:
        return False


def _is_permission_error(exit_code: int, stderr: str) -> bool:
    if exit_code == 13:
        return True
    if not stderr:
        return False
    lower_stderr = stderr.lower()
    keywords = [
        "permission denied",
        "operation not permitted",
        "must be root",
        "requires root",
        "not permitted",
        "only root",
        "eperm",
        "must be superuser",
        "requires superuser",
        "superuser",
        "root privilege",
    ]
    return any(kw in lower_stderr for kw in keywords)


def _redact_arg(arg: str) -> str:
    if len(arg) > 60:
        return arg[:60] + "..."
    return arg


def run_command(
    command: list[str],
    *,
    purpose: str = "",
    timeout: int | None = None,
    save_output: bool = False,
    save_dir: str | None = None,
    cwd: str | None = None,
    preview_lines: int = 0,
) -> dict:
    """Execute a command if its binary is not on the denylist.

    Args:
        command: Command as list of strings.
        purpose: Reason for running (audit trail).
        timeout: Override timeout.
        save_output: Save stdout/stderr to files.
        save_dir: Directory for saved output.
        cwd: Working directory.

    Raises:
        DeniedBinaryError: Binary is on the hard denylist.
        ExecutionError: Binary not found on system.
    """
    if not command:
        raise ValueError("Empty command")

    if cwd is None:
        cwd = os.environ.get("SIFT_CASE_DIR") or None

    # Reject agent-supplied sudo outright
    binary = command[0].split("/")[-1]
    if binary == "sudo":
        raise DeniedBinaryError("Agent-supplied sudo is blocked. Commands must be run directly.")

    # Apply policy check on the primary binary
    if is_denied(binary):
        raise DeniedBinaryError(
            f"Binary '{binary}' is blocked by security policy. "
            f"This restriction cannot be overridden."
        )
    if not is_allowed_by_mode(binary):
        raise DeniedBinaryError(
            f"Binary '{binary}' is not allowed by execute.security allowlist mode."
        )

    # Validate any arguments that look like file paths
    output_flags = get_output_flags()
    prev_was_output_flag = False
    output_paths = []
    input_paths = []

    for arg in command[1:]:
        # Check flag=value arguments for path values
        if "=" in arg and arg.startswith("-"):
            flag_part = arg.split("=", 1)[0]
            value = arg.split("=", 1)[1]
            if value and (
                value.startswith("/") or value.startswith("..") or "/" in value
            ):
                if value.startswith("/dev/") and binary in _DEV_PATH_TOOLS:
                    pass  # Device path for disk forensics
                elif flag_part in output_flags:
                    validate_output_path(value)
                    output_paths.append(value)
                else:
                    validate_input_path(value)
                    input_paths.append(value)
            prev_was_output_flag = False
            continue
        if arg.startswith("-") and "=" not in arg:
            prev_was_output_flag = arg in output_flags
            continue
        if arg.startswith("/") or arg.startswith("..") or "/" in arg:
            if arg.startswith("/dev/") and binary in _DEV_PATH_TOOLS:
                pass  # Device path for disk forensics
            elif prev_was_output_flag:
                validate_output_path(arg)
                output_paths.append(arg)
            else:
                validate_input_path(arg)
                input_paths.append(arg)
        prev_was_output_flag = False

    # Resolve binary via find_binary to prevent absolute path bypass
    resolved_binary = find_binary(binary)
    if not resolved_binary:
        raise ExecutionError(f"Binary '{binary}' not found on this system.")

    # Sanitize any args after the binary
    sanitize_extra_args(command[1:], tool_name=binary)

    # rm-specific: allow execution but protect evidence directories
    if binary == "rm":
        rm_idx = command.index("rm") if "rm" in command else -1
        if rm_idx != -1:
            validate_rm_targets(command[rm_idx + 1:])

    privileged_candidate = binary in _PRIVILEGED_TARGETS

    # Perform per-tool validator checks if privileged candidate
    if privileged_candidate:
        # Check for glob/wildcard character in any argument
        for arg in command:
            for char in ["*", "?", "[", "]"]:
                if char in arg:
                    raise ValueError(f"Wildcard/glob characters ('{char}') are not permitted in command arguments.")

        case_dir_str = resolve_case_dir()
        case_dir = Path(case_dir_str) if case_dir_str else None
        cases_root_dir = cases_root()

        # Tool specific validations
        if binary == "mount":
            positional_args = [arg for arg in command[1:] if not arg.startswith("-")]
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
            positional_args = [arg for arg in command[1:] if not arg.startswith("-")]
            if len(positional_args) < 1:
                raise ValueError("umount command requires a target argument.")
            target = positional_args[-1]

            if not case_dir:
                raise ValueError("An active case is required to execute umount.")
            allowed_target_dirs = [case_dir / "tmp", case_dir / "extractions", case_dir / "agent"]
            if not any(_is_in_directory(target, d) for d in allowed_target_dirs):
                raise ValueError("umount target must be under case controlled mount directories (tmp/, extractions/, or agent/).")

        elif binary == "losetup":
            losetup_flags = set(command[1:])
            is_list_or_detach = any(
                f in losetup_flags 
                for f in {"-a", "--all", "-l", "--list", "-j", "--associated", "-d", "--detach"}
            )
            if not is_list_or_detach:
                if not any(f in losetup_flags for f in {"-r", "--read-only"}):
                    raise ValueError("losetup loop device setup requires the read-only flag (-r or --read-only).")
                positional_args = [arg for arg in command[1:] if not arg.startswith("-")]
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
            for arg in command[1:]:
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
                raise ValueError(f"An active case is required to execute {binary}.")
            allowed_of_dirs = [case_dir / "agent", case_dir / "extractions", case_dir / "tmp"]
            if not any(_is_in_directory(of_val, d) for d in allowed_of_dirs):
                raise ValueError(f"{binary} of= target must be under case agent/, extractions/, or tmp/ directories.")

        elif binary == "fdisk":
            fdisk_flags = set(command[1:])
            has_ro_flag = any(f in fdisk_flags for f in {"-l", "--list", "-s"})
            if not has_ro_flag:
                raise ValueError("fdisk command is restricted to read-only inspection flags (-l, --list, -s).")

    # CommandPlan creation
    direct_argv = [resolved_binary] + command[1:]
    plan = CommandPlan(
        original_argv=list(command),
        direct_argv=direct_argv,
        binary=binary,
        privileged_candidate=privileged_candidate,
        output_paths=output_paths,
        input_paths=input_paths
    )

    exec_result = None
    privilege_events = []
    escalation_info = None

    try:
        exec_result = execute(
            plan.direct_argv,
            timeout=timeout,
            cwd=cwd,
            save_output=save_output,
            save_dir=save_dir,
        )
        if exec_result["exit_code"] != 0 and _is_permission_error(exec_result["exit_code"], exec_result.get("stderr", "")):
            raise PermissionError(f"Direct execution failed with permission error: {exec_result.get('stderr')}")
    except (PermissionError, ExecutionError) as exc:
        is_perm = isinstance(exc, PermissionError) or "Permission denied" in str(exc)
        if not is_perm or not plan.privileged_candidate:
            raise

        if not os.path.exists("/usr/bin/sudo"):
            logger.error("Privilege escalation required but /usr/bin/sudo is missing.")
            raise PermissionError("Privilege escalation via sudo is unavailable: /usr/bin/sudo not found.")

        # Log fallback attempt
        redacted_args = [plan.direct_argv[0]] + [_redact_arg(arg) for arg in plan.direct_argv[1:]]
        fallback_event = {
            "status": "fallback_attempt",
            "command": redacted_args,
            "reason": "Permission denied during direct execution"
        }
        privilege_events.append(fallback_event)

        # Synthesize non-interactive sudo command
        sudo_cmd = ["/usr/bin/sudo", "-n", "--", plan.direct_argv[0]] + plan.direct_argv[1:]

        # Execute via isolated worker
        exec_result = execute(
            sudo_cmd,
            timeout=timeout,
            cwd=cwd,
            save_output=save_output,
            save_dir=save_dir,
        )

        success = (exec_result["exit_code"] == 0)
        redacted_sudo_cmd = ["/usr/bin/sudo", "-n", "--", plan.direct_argv[0]] + [_redact_arg(arg) for arg in plan.direct_argv[1:]]
        outcome_event = {
            "status": "success" if success else "failed",
            "command": redacted_sudo_cmd,
            "exit_code": exec_result["exit_code"]
        }
        privilege_events.append(outcome_event)

        escalation_info = {
            "eligible": True,
            "mechanism": "sudo_fallback",
            "status": "success" if success else "failed",
            "exit_code": exec_result["exit_code"]
        }

    if plan.privileged_candidate and escalation_info is None and exec_result["exit_code"] == 0:
        success_event = {
            "status": "success",
            "command": plan.direct_argv,
            "mechanism": "direct_unprivileged"
        }
        privilege_events.append(success_event)
        escalation_info = {
            "eligible": True,
            "mechanism": "direct_unprivileged",
            "status": "success"
        }

    if escalation_info:
        exec_result["privilege_escalation"] = escalation_info
    if privilege_events:
        exec_result["privilege_events"] = privilege_events

    # Parse output based on catalog format when output exceeds byte budget
    cfg = get_config()
    stdout = exec_result.get("stdout", "")
    stdout_bytes = exec_result.get("stdout_total_bytes", len(stdout.encode("utf-8")))

    td = get_tool_def(binary)
    output_format = td.output_format if td else "text"

    # Small output — return as-is (no parsing overhead)
    if stdout_bytes <= cfg.response_byte_budget:
        exec_result["_output_format"] = output_format
        return exec_result

    # Large output — parse with byte budget
    from sift_common.parsers import csv_parser, json_parser, text_parser

    # If preview_lines requested, scale budget up (assume ~200 bytes/line)
    budget = (
        max(cfg.response_byte_budget, preview_lines * 200)
        if preview_lines
        else cfg.response_byte_budget
    )
    ml = preview_lines or 50000

    if output_format == "csv":
        csv_kwargs = {"byte_budget": budget}
        if preview_lines:
            csv_kwargs["max_rows"] = ml
        parsed = csv_parser.parse_csv(stdout, **csv_kwargs)
        exec_result["_parsed"] = parsed
        exec_result["_output_format"] = "parsed_csv"
    elif output_format == "json":
        parsed = json_parser.parse_json(stdout, byte_budget=budget)
        if parsed.get("parse_error"):
            parsed = json_parser.parse_jsonl(stdout, byte_budget=budget)
        exec_result["_parsed"] = parsed
        exec_result["_output_format"] = "parsed_json"
    else:
        parsed = text_parser.parse_text(stdout, byte_budget=budget, max_lines=ml)
        exec_result["_parsed"] = parsed
        exec_result["_output_format"] = "parsed_text"

    # Replace raw stdout with None — full output is on disk if saved
    exec_result["stdout"] = None

    return exec_result
