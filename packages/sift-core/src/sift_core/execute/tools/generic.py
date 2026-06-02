"""Generic run_command: denylist-protected execution of forensic tools."""

from __future__ import annotations

import logging
import os
import shlex
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
    validate_shell_command,
    split_command_by_operators,
    parse_subcommand_argv_and_redirects,
    _DEV_PATH_TOOLS,
    _PRIVILEGED_TARGETS,
)

logger = logging.getLogger(__name__)


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
    command: str | list[str],
    *,
    purpose: str = "",
    timeout: int | None = None,
    save_output: bool = False,
    save_dir: str | None = None,
    cwd: str | None = None,
    preview_lines: int = 0,
) -> dict:
    """Execute a shell command securely via bash.

    Args:
        command: Command string or list to execute.
        purpose: Reason for running (audit trail).
        timeout: Override timeout.
        save_output: Save stdout/stderr to files.
        save_dir: Directory for saved output.
        cwd: Working directory.

    Raises:
        DeniedBinaryError: Binary is on the hard denylist.
        ExecutionError: Binary not found on system or execution failed.
    """
    if isinstance(command, list):
        command = shlex.join(command)

    if not command:
        raise ValueError("Empty command")

    if cwd is None:
        cwd = os.environ.get("SIFT_CASE_DIR") or None

    # Run the comprehensive shell validation
    validate_shell_command(command)

    # Extract subcommands to identify first binary and check for privileged candidates
    subcmds = split_command_by_operators(command)
    first_binary = ""
    privileged_candidate = False
    
    for subcmd_str, _ in subcmds:
        if not subcmd_str.strip():
            continue
        try:
            argv, _ = parse_subcommand_argv_and_redirects(subcmd_str)
            if argv:
                binary = argv[0].split('/')[-1]
                if not first_binary:
                    first_binary = binary
                if binary in _PRIVILEGED_TARGETS:
                    privileged_candidate = True
        except Exception:
            pass

    # CommandPlan creation
    plan = CommandPlan(
        original_argv=[command],
        direct_argv=["/bin/bash", "-c", command],
        binary=first_binary or "bash",
        privileged_candidate=privileged_candidate,
        output_paths=[],
        input_paths=[]
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

    warnings = []
    agent_action = None
    stderr_lower = exec_result.get("stderr", "").lower()
    stdout_lower = exec_result.get("stdout", "").lower()
    full_output = stdout_lower + "\n" + stderr_lower
    
    warning_patterns = [
        "unrecognized command", "error processing", "skipping",
        "invalid signature", "is not an evtx file", "unrecognized argument"
    ]
    if any(wp in full_output for wp in warning_patterns):
        warnings.append("parser_partial_failure")
        agent_action = "Inspect parser stdout/stderr before relying on absence of events"

    if warnings:
        exec_result["warnings"] = warnings
        exec_result["agent_action"] = agent_action

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
