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

    # Run the comprehensive shell validation and get validated stages
    validated_stages = validate_shell_command(command)

    first_binary = ""
    privileged_candidate = False
    for stage in validated_stages:
        if not first_binary:
            first_binary = stage["binary"]
        if stage["privileged"]:
            privileged_candidate = True

    binary = first_binary or "bash"

    # CommandPlan creation
    primary_stage = validated_stages[0]
    plan = CommandPlan(
        original_argv=[command],
        direct_argv=primary_stage["argv"],
        binary=binary,
        privileged_candidate=privileged_candidate,
        output_paths=[],
        input_paths=[]
    )

    # Group validated_stages by pipeline operator '|'
    pipelines = []
    current_pipeline = []
    for stage in validated_stages:
        current_pipeline.append(stage)
        if stage["operator"] != "|":
            pipelines.append((current_pipeline, stage["operator"]))
            current_pipeline = []
    if current_pipeline:
        pipelines.append((current_pipeline, ""))

    exec_result = None
    privilege_events = []
    escalation_info = None
    last_exit_code = 0
    next_cond = None
    executed_stages_info = []

    for current_pipeline, operator in pipelines:
        # Check sequencing condition
        if next_cond == "&&" and last_exit_code != 0:
            next_cond = operator
            continue
        if next_cond == "||" and last_exit_code == 0:
            next_cond = operator
            continue

        pipeline_stages = []
        pipeline_privileged = False
        for stage in current_pipeline:
            pipeline_stages.append({
                "argv": stage["argv"],
                "redirects": stage["redirects"],
            })
            if stage["privileged"]:
                pipeline_privileged = True

        pipeline_result = None
        try:
            pipeline_result = execute(
                pipeline_stages,
                timeout=timeout,
                cwd=cwd,
                save_output=save_output,
                save_dir=save_dir,
            )
            if pipeline_result["exit_code"] != 0 and _is_permission_error(pipeline_result["exit_code"], pipeline_result.get("stderr", "")):
                raise PermissionError(f"Direct execution failed with permission error: {pipeline_result.get('stderr')}")
        except (PermissionError, ExecutionError) as exc:
            is_perm = isinstance(exc, PermissionError) or "Permission denied" in str(exc) or "only root can do that" in str(exc)
            if not is_perm or not pipeline_privileged:
                raise

            if not os.path.exists("/usr/bin/sudo"):
                logger.error("Privilege escalation required but /usr/bin/sudo is missing.")
                raise PermissionError("Privilege escalation via sudo is unavailable: /usr/bin/sudo not found.")

            # Log fallback attempt
            fallback_event = {
                "status": "fallback_attempt",
                "command": [stage["argv"] for stage in current_pipeline],
                "reason": "Permission denied during direct execution"
            }
            privilege_events.append(fallback_event)

            # Construct escalated stages
            escalated_stages = []
            for stage in current_pipeline:
                if stage["privileged"]:
                    escalated_argv = ["/usr/bin/sudo", "-n", "--", stage["resolved"]] + stage["argv"][1:]
                else:
                    escalated_argv = stage["argv"]
                escalated_stages.append({
                    "argv": escalated_argv,
                    "redirects": stage["redirects"],
                })

            # Execute escalated stages
            pipeline_result = execute(
                escalated_stages,
                timeout=timeout,
                cwd=cwd,
                save_output=save_output,
                save_dir=save_dir,
            )

            success = (pipeline_result["exit_code"] == 0)
            outcome_event = {
                "status": "success" if success else "failed",
                "command": [stage["argv"] for stage in escalated_stages],
                "exit_code": pipeline_result["exit_code"]
            }
            privilege_events.append(outcome_event)

            escalation_info = {
                "eligible": True,
                "mechanism": "sudo_fallback",
                "status": "success" if success else "failed",
                "exit_code": pipeline_result["exit_code"]
            }

        if pipeline_privileged and escalation_info is None and pipeline_result and pipeline_result["exit_code"] == 0:
            success_event = {
                "status": "success",
                "command": [stage["argv"] for stage in current_pipeline],
                "mechanism": "direct_unprivileged"
            }
            privilege_events.append(success_event)
            escalation_info = {
                "eligible": True,
                "mechanism": "direct_unprivileged",
                "status": "success"
            }

        # Track exit code for each stage in the current pipeline
        for idx, stage in enumerate(current_pipeline):
            exit_code = 0
            if pipeline_result and "stages" in pipeline_result and idx < len(pipeline_result["stages"]):
                exit_code = pipeline_result["stages"][idx]["exit_code"]
            elif pipeline_result:
                exit_code = pipeline_result["exit_code"]
            executed_stages_info.append({
                "binary": stage["binary"],
                "argv": stage["argv"],
                "exit_code": exit_code
            })

        exec_result = pipeline_result
        last_exit_code = pipeline_result["exit_code"] if pipeline_result else 1
        next_cond = operator

    if exec_result:
        exec_result["stages"] = executed_stages_info
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
