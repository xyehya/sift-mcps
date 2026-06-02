"""Subprocess executor — shell=False, timeout, output capture.

All forensic tool execution goes through this module.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import pwd
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sift_core.execute.config import get_config, resolve_case_dir
from sift_core.execute.exceptions import ExecutionError, ExecutionTimeoutError

logger = logging.getLogger(__name__)


def _run_isolated_worker(
    cmd_list: list[str] | list[dict[str, Any]],
    *,
    timeout: int,
    cwd: str | None,
    max_output_bytes: int,
    memory_limit_bytes: int,
    runtime_user: str = "",
    sudo_path: str = "",
) -> dict[str, Any]:
    payload = {
        "timeout": timeout,
        "cwd": cwd,
        "max_output_bytes": max_output_bytes,
        "memory_limit_bytes": memory_limit_bytes,
        "runtime_user": runtime_user,
        "sudo_path": sudo_path,
    }
    if cmd_list and isinstance(cmd_list[0], dict):
        payload["stages"] = cmd_list
        cmd_str = " | ".join(" ".join(stage["argv"]) for stage in cmd_list)
    else:
        payload["cmd"] = cmd_list
        cmd_str = " ".join(cmd_list)

    worker_cmd = [sys.executable, "-m", "sift_core.execute.worker"]
    logger.debug("Starting native user execution worker: %s", cmd_str)
    proc = subprocess.run(
        worker_cmd,
        input=json.dumps(payload),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout + 10,
        shell=False,
    )

    if proc.returncode != 0:
        stderr = _truncate(proc.stderr or "", 2000)
        raise ExecutionError(f"Executor worker failed with exit {proc.returncode}: {stderr}")

    try:
        result = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        stderr = _truncate(proc.stderr or "", 2000)
        raise ExecutionError(f"Executor worker returned invalid JSON: {stderr}") from exc

    error_type = result.get("error_type")
    if error_type == "timeout":
        raise ExecutionTimeoutError(
            f"Command timed out after {timeout}s: {cmd_str}"
        )
    if error_type == "not_found":
        first_binary = cmd_list[0]["argv"][0] if cmd_list and isinstance(cmd_list[0], dict) else cmd_list[0]
        raise FileNotFoundError(result.get("message") or first_binary)
    if error_type == "permission":
        first_binary = cmd_list[0]["argv"][0] if cmd_list and isinstance(cmd_list[0], dict) else cmd_list[0]
        raise PermissionError(result.get("message") or first_binary)
    if error_type:
        raise OSError(result.get("message") or f"executor worker error: {error_type}")
    return result


def _native_runtime_identity(config) -> tuple[str, str]:
    """Return (runtime_user, sudo_path), or empty strings for same-user dev mode."""
    runtime_user = str(config.execute_as_user or "").strip()
    if not runtime_user or runtime_user == "__current__":
        return "", ""

    try:
        current_user = pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        current_user = ""
    if runtime_user == current_user:
        return "", ""

    try:
        pwd.getpwnam(runtime_user)
    except KeyError as exc:
        raise ExecutionError(
            "Native run_command isolation is configured for user "
            f"'{runtime_user}', but that local account does not exist. "
            "Create it with scripts/setup-agent-runtime.sh or set "
            "execute.runtime_user to a valid restricted account."
        ) from exc

    sudo_path = shutil.which("sudo") or "/usr/bin/sudo"
    if not Path(sudo_path).exists():
        raise ExecutionError(
            "Native run_command isolation requires sudo so the gateway can "
            f"drop privileges to '{runtime_user}', but sudo was not found."
        )
    return runtime_user, sudo_path


def execute(
    cmd_list: list[str] | list[dict[str, Any]],
    *,
    timeout: int | None = None,
    cwd: str | None = None,
    save_output: bool = False,
    save_dir: str | None = None,
) -> dict[str, Any]:
    """Execute a command as a subprocess (shell=False).

    Uses Popen with incremental pipe reading to enforce max_output_bytes
    at capture time, preventing OOM from runaway processes.

    Args:
        cmd_list: Command and arguments as a list.
        timeout: Seconds before timeout. Defaults to config value.
        cwd: Working directory.
        save_output: If True, write stdout/stderr to files with SHA-256 hashes.
        save_dir: Directory for saved output (defaults to cwd/extracted/).

    Returns:
        Dict with exit_code, stdout, stderr, elapsed_seconds, and optional saved file info.
    """
    config = get_config()
    timeout = timeout or config.default_timeout
    max_bytes = config.max_output_bytes
    runtime_user, sudo_path = _native_runtime_identity(config)

    start = time.monotonic()
    try:
        worker_result = _run_isolated_worker(
            cmd_list,
            timeout=timeout,
            cwd=cwd,
            max_output_bytes=max_bytes,
            memory_limit_bytes=config.execute_memory_limit_bytes,
            runtime_user=runtime_user,
            sudo_path=sudo_path,
        )
        elapsed = time.monotonic() - start

        stdout = str(worker_result.get("stdout", ""))
        stderr = str(worker_result.get("stderr", ""))
        stdout_byte_count = int(
            worker_result.get("stdout_total_bytes", len(stdout.encode("utf-8")))
        )

        response: dict[str, Any] = {
            "exit_code": int(worker_result["exit_code"]),
            "stdout": stdout,
            "stderr": _truncate(stderr, config.max_output_bytes // 10),
            "elapsed_seconds": round(elapsed, 2),
            "command": cmd_list,
            "stdout_total_bytes": stdout_byte_count,
            "executor": "native_user_worker" if runtime_user else "direct_worker",
        }
        if runtime_user:
            response["runtime_user"] = runtime_user
        if worker_result.get("truncated"):
            response["truncated"] = True
        if worker_result.get("stages"):
            response["stages"] = worker_result["stages"]

        # Threshold-based save: auto-save when output exceeds response budget
        case_dir = resolve_case_dir()
        exceeds_budget = stdout_byte_count > config.response_byte_budget

        if exceeds_budget and case_dir:
            _save_output(
                cmd_list,
                stdout,
                stderr,
                save_dir or str(_next_run_command_output_dir(Path(case_dir))),
                response,
            )
        elif save_output and (stdout or stderr):
            default_save_dir = None
            if case_dir:
                default_save_dir = str(_next_run_command_output_dir(Path(case_dir)))
            elif cwd:
                default_save_dir = str(Path(cwd) / "extracted")
            _save_output(
                cmd_list,
                stdout,
                stderr,
                save_dir or default_save_dir,
                response,
            )

        return response

    except subprocess.TimeoutExpired as exc:
        raise ExecutionTimeoutError(
            f"Command timed out after {timeout}s: {_format_command(cmd_list)}"
        ) from exc
    except FileNotFoundError as exc:
        msg = str(exc)
        if msg.startswith("Redirection target not found:"):
            raise ExecutionError(msg) from exc
        raise ExecutionError(f"Binary not found: {_first_command_name(cmd_list)}") from exc
    except PermissionError as exc:
        msg = str(exc)
        if msg.startswith("Permission denied on redirection target:"):
            raise ExecutionError(msg) from exc
        raise ExecutionError(f"Permission denied: {_first_command_name(cmd_list)}") from exc
    except OSError as e:
        raise ExecutionError(f"OS error executing {_first_command_name(cmd_list)}: {e}") from e


def _first_command_name(cmd_list: list[str] | list[dict[str, Any]]) -> str:
    if not cmd_list:
        return ""
    first = cmd_list[0]
    if isinstance(first, dict):
        argv = first.get("argv") or []
        return str(argv[0]) if argv else ""
    return str(first)


def _format_command(cmd_list: list[str] | list[dict[str, Any]]) -> str:
    if cmd_list and isinstance(cmd_list[0], dict):
        return " | ".join(" ".join(str(part) for part in stage.get("argv", [])) for stage in cmd_list)
    return " ".join(str(part) for part in cmd_list)


def _truncate(text: str, max_chars: int) -> str:
    """Truncate text to max_chars."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n... [truncated at {max_chars} chars]"


def _next_run_command_output_dir(case_dir: Path) -> Path:
    return case_dir / "agent" / "outputs"



def _save_output(
    cmd_list: list[str],
    stdout: str,
    stderr: str,
    save_dir: str | None,
    response: dict,
) -> None:
    """Save stdout/stderr to files with SHA-256 hashes."""
    if not save_dir:
        return

    try:
        out_dir = Path(save_dir).resolve()
    except OSError as e:
        logger.warning("Cannot resolve save_dir path %s: %s", save_dir, e)
        return

    # Block writes to system directories
    _blocked_prefixes = (
        "/etc",
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/boot",
        "/proc",
        "/sys",
        "/dev",
    )
    if any(
        str(out_dir) == p or str(out_dir).startswith(p + "/") for p in _blocked_prefixes
    ):
        raise ExecutionError(f"Refusing to write output to system directory: {out_dir}")

    # When case dir is known, restrict save_dir to agent, extractions, or tmp.
    case_dir = resolve_case_dir() or None
    if case_dir:
        try:
            case_resolved = Path(case_dir).resolve()
            allowed_subdirs = [
                case_resolved / "agent",
                case_resolved / "extractions",
                case_resolved / "tmp",
            ]
            is_allowed = False
            for subdir in allowed_subdirs:
                if out_dir == subdir or out_dir.is_relative_to(subdir):
                    is_allowed = True
                    break
            if not is_allowed:
                raise ExecutionError(
                    f"save_dir '{out_dir}' must be inside case agent, extractions, or tmp directory: "
                    f"'{case_resolved}/agent/', '{case_resolved}/extractions/' or '{case_resolved}/tmp/'"
                )
        except ValueError as exc:
            raise ExecutionError(
                f"save_dir '{out_dir}' is outside the case directory '{case_resolved}'"
            ) from exc

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.warning("Cannot create output directory %s: %s", out_dir, e)
        return

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    first_cmd = Path(_first_command_name(cmd_list)).name or "command"
    safe_cmd = "".join(c if c.isalnum() or c in "-_" else "_" for c in first_cmd)[:40]
    prefix = f"{ts}_{safe_cmd}"

    if stdout:
        try:
            stdout_path = out_dir / f"{prefix}_stdout.txt"
            stdout_bytes = stdout.encode("utf-8", errors="replace")
            with open(stdout_path, "wb") as f:
                f.write(stdout_bytes)
                f.flush()
                os.fsync(f.fileno())
            response["output_file"] = str(stdout_path)
            response["output_sha256"] = hashlib.sha256(stdout_bytes).hexdigest()
        except OSError as e:
            logger.warning("Failed to save stdout to %s: %s", stdout_path, e)

    if stderr:
        try:
            stderr_path = out_dir / f"{prefix}_stderr.txt"
            stderr_bytes = stderr.encode("utf-8", errors="replace")
            with open(stderr_path, "wb") as f:
                f.write(stderr_bytes)
                f.flush()
                os.fsync(f.fileno())
            response["stderr_file"] = str(stderr_path)
            response["stderr_sha256"] = hashlib.sha256(stderr_bytes).hexdigest()
        except OSError as e:
            logger.warning("Failed to save stderr to %s: %s", stderr_path, e)
