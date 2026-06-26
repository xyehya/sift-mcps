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
from sift_core.execute.runtime_acl import build_sandbox_env, is_authority_path

logger = logging.getLogger(__name__)

DEFAULT_SYSTEMD_SCOPE_HELPER = "/usr/local/sbin/sift-run-command-systemd-scope"


def _active_or_env_case_dir() -> str:
    try:
        from sift_core.active_case_context import current_active_case

        ctx = current_active_case()
        if ctx and ctx.case_dir is not None:
            return str(ctx.case_dir)
    except ImportError:  # pragma: no cover - defensive for unusual packaging
        pass
    return resolve_case_dir()


def _env_flag(name: str, *, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _systemd_scope_mode() -> str:
    raw = os.environ.get("SIFT_EXECUTE_SYSTEMD_SCOPE")
    if raw is None:
        return "required" if _env_flag("SIFT_EXECUTE_REQUIRE_RUNTIME_USER") else "off"
    value = raw.strip().lower()
    if value in {"", "0", "false", "no", "off"}:
        return "off"
    # SEC-11: the legacy "auto" mode silently fell back to the *direct* worker
    # (no IPAddressDeny=any, no cgroup caps) when systemd-run was missing — a
    # silent isolation downgrade. It is removed: any non-off value now means the
    # cgroup scope is REQUIRED and a missing systemd-run fails closed
    # (ExecutionError in _systemd_scope_command). Local dev that genuinely cannot
    # run systemd-run must opt out explicitly with SIFT_EXECUTE_SYSTEMD_SCOPE=0.
    return "required"


def _systemd_memory_props(memory_limit_bytes: int) -> tuple[str, str]:
    memory_max = os.environ.get("SIFT_EXECUTE_SYSTEMD_MEMORY_MAX", "").strip()
    memory_high = os.environ.get("SIFT_EXECUTE_SYSTEMD_MEMORY_HIGH", "").strip()
    if memory_limit_bytes > 0:
        memory_max = memory_max or str(int(memory_limit_bytes))
        memory_high = memory_high or str(max(1, int(memory_limit_bytes * 0.75)))
    else:
        memory_high = memory_high or "3G"
        memory_max = memory_max or "4G"
    return memory_high, memory_max


def _systemd_scope_helper_path() -> str:
    raw = os.environ.get("SIFT_EXECUTE_SYSTEMD_SCOPE_HELPER")
    if raw is not None:
        value = raw.strip()
        if value.lower() in {"", "0", "false", "no", "off"}:
            return ""
        if not Path(value).exists():
            raise ExecutionError(
                "SIFT_EXECUTE_SYSTEMD_SCOPE_HELPER points to a missing helper: "
                f"{value}"
            )
        return value
    if Path(DEFAULT_SYSTEMD_SCOPE_HELPER).exists():
        return DEFAULT_SYSTEMD_SCOPE_HELPER
    return ""


def _systemd_scope_command(
    worker_cmd: list[str],
    *,
    timeout: int,
    memory_limit_bytes: int,
    runtime_user: str = "",
) -> tuple[list[str], bool, bool]:
    """Wrap ``worker_cmd`` in a transient systemd cgroup scope when requested.

    Returns ``(cmd, runtime_user_already_applied, scope_applied)``. ``scope_applied``
    is True only when the worker is actually wrapped in a cgroup scope (or the
    privileged helper) — never on the silent-downgrade paths, which no longer
    exist for a Linux deployment (SEC-11: a missing systemd-run fails closed).
    """
    mode = _systemd_scope_mode()
    if mode == "off" or os.name != "posix":
        return worker_cmd, False, False

    systemd_run = shutil.which("systemd-run")
    if not systemd_run:
        candidate = Path("/usr/bin/systemd-run")
        if candidate.exists():
            systemd_run = str(candidate)
    if not systemd_run:
        # SEC-11: fail closed — never silently run the direct worker without
        # IPAddressDeny=any / cgroup caps. Local dev opts out with SCOPE=0.
        raise ExecutionError(
            "SIFT run_command cgroup isolation was requested, but systemd-run "
            "was not found. Install systemd-run or disable only for local dev "
            "with SIFT_EXECUTE_SYSTEMD_SCOPE=0."
        )

    memory_high, memory_max = _systemd_memory_props(memory_limit_bytes)
    props = [
        f"MemoryHigh={memory_high}",
        f"MemoryMax={memory_max}",
        f"CPUQuota={os.environ.get('SIFT_EXECUTE_SYSTEMD_CPU_QUOTA', '200%')}",
        f"TasksMax={os.environ.get('SIFT_EXECUTE_SYSTEMD_TASKS_MAX', '64')}",
        f"RuntimeMaxSec={max(1, int(timeout) + 5)}",
        "OOMPolicy=kill",
        "IPAddressDeny=any",
        "IOAccounting=yes",
        "IPAccounting=yes",
    ]
    unit_name = f"sift-run-command-{os.getpid()}-{time.monotonic_ns()}.scope"
    helper = _systemd_scope_helper_path()
    if helper and runtime_user:
        sudo_path = shutil.which("sudo") or "/usr/bin/sudo"
        if not Path(sudo_path).exists():
            raise ExecutionError(
                "SIFT run_command systemd scope helper requires sudo, but sudo "
                "was not found."
            )
        helper_cmd = [
            sudo_path,
            "-n",
            helper,
            "--unit",
            unit_name,
            "--runtime-user",
            runtime_user,
            "--memory-high",
            memory_high,
            "--memory-max",
            memory_max,
            "--cpu-quota",
            os.environ.get("SIFT_EXECUTE_SYSTEMD_CPU_QUOTA", "200%"),
            "--tasks-max",
            os.environ.get("SIFT_EXECUTE_SYSTEMD_TASKS_MAX", "64"),
            "--runtime-max-sec",
            str(max(1, int(timeout) + 5)),
            "--",
            *worker_cmd,
        ]
        return helper_cmd, True, True

    scope_cmd = [
        systemd_run,
        "--scope",
        "--quiet",
        "--collect",
        f"--unit={unit_name}",
    ]
    runtime_user_applied = False
    if runtime_user:
        scope_cmd.extend(["--uid", runtime_user])
        try:
            scope_cmd.extend(["--gid", str(pwd.getpwnam(runtime_user).pw_gid)])
        except KeyError:
            pass
        runtime_user_applied = True
    for prop in props:
        scope_cmd.extend(["-p", prop])
    return [*scope_cmd, "--", *worker_cmd], runtime_user_applied, True


def _launcher_requested(runtime_user: str) -> bool:
    return bool(runtime_user) or _env_flag("SIFT_EXECUTE_LAUNCHER") or _env_flag(
        "SIFT_EXECUTE_REQUIRE_LANDLOCK"
    )


def _seccomp_mode() -> str:
    mode = os.environ.get("SIFT_EXECUTE_SECCOMP_MODE", "log").strip().lower()
    return "kill" if mode in {"kill", "enforce", "enforced"} else "log"


def _run_isolated_worker(
    cmd_list: list[str] | list[dict[str, Any]],
    *,
    timeout: int,
    cwd: str | None,
    max_output_bytes: int,
    memory_limit_bytes: int,
    runtime_user: str = "",
    sudo_path: str = "",
    cache_dir: str = "",
) -> dict[str, Any]:
    case_dir = _active_or_env_case_dir()
    payload = {
        "timeout": timeout,
        "cwd": cwd,
        "case_dir": case_dir,
        "max_output_bytes": max_output_bytes,
        "memory_limit_bytes": memory_limit_bytes,
        "runtime_user": runtime_user,
        "sudo_path": sudo_path,
        "cache_dir": cache_dir,
        "launcher_enabled": _launcher_requested(runtime_user),
        "launcher_required": _env_flag("SIFT_EXECUTE_REQUIRE_LANDLOCK")
        or _env_flag("SIFT_EXECUTE_LAUNCHER"),
        "require_landlock": _env_flag("SIFT_EXECUTE_REQUIRE_LANDLOCK"),
        "seccomp_mode": _seccomp_mode(),
        "service_uid": os.getuid() if hasattr(os, "getuid") else None,
        "service_gid": os.getgid() if hasattr(os, "getgid") else None,
    }
    if cmd_list and isinstance(cmd_list[0], dict):
        payload["stages"] = cmd_list
        cmd_str = " | ".join(" ".join(stage["argv"]) for stage in cmd_list)
    else:
        payload["cmd"] = cmd_list
        cmd_str = " ".join(cmd_list)

    worker_cmd, runtime_user_already_applied, systemd_scope_applied = _systemd_scope_command(
        [sys.executable, "-m", "sift_core.execute.worker"],
        timeout=timeout,
        memory_limit_bytes=memory_limit_bytes,
        runtime_user=runtime_user,
    )
    payload["runtime_user_already_applied"] = runtime_user_already_applied
    logger.debug("Starting native user execution worker: %s", cmd_str)
    # K5 authority isolation: the worker subprocess (and, downstream, the
    # forensic tool it launches) must not inherit DB DSNs, Supabase/service-role
    # keys, OpenSearch credentials, or other VM secrets that live in the
    # Gateway/worker environment. Spawn the short-lived worker with a scrubbed
    # env so secrets never reach it; the worker scrubs again before the tool as
    # defense in depth.
    worker_env = build_sandbox_env()
    proc = subprocess.run(
        worker_cmd,
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=timeout + 3,
        shell=False,
        env=worker_env,
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
        msg = result.get("message") or "Permission denied (check redirect target path and binary permissions)"
        raise PermissionError(msg)
    if error_type:
        raise OSError(result.get("message") or f"executor worker error: {error_type}")

    # SEC-11: surface the ACTUAL applied isolation posture. The worker reports
    # the per-tool launcher/seccomp/landlock/runtime-user facts (it builds the
    # stage argv); the systemd cgroup scope is decided here, so merge it in. This
    # rides the agent-facing surface via execute() -> run_command response.
    isolation = result.get("isolation")
    isolation = dict(isolation) if isinstance(isolation, dict) else {}
    isolation["systemd_scope_applied"] = systemd_scope_applied
    isolation["systemd_scope_mode"] = _systemd_scope_mode()
    result["isolation"] = isolation
    return result


def _native_runtime_identity(config) -> tuple[str, str]:
    """Return (runtime_user, sudo_path), or empty strings for same-user dev mode."""
    runtime_user = str(config.execute_as_user or "").strip()
    require_runtime_user = _env_flag("SIFT_EXECUTE_REQUIRE_RUNTIME_USER")
    if not runtime_user or runtime_user == "__current__":
        if require_runtime_user:
            raise ExecutionError(
                "SIFT_EXECUTE_REQUIRE_RUNTIME_USER=1 requires execute.runtime_user "
                "to name a distinct restricted local account."
            )
        return "", ""

    try:
        current_user = pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        current_user = ""
    if runtime_user == current_user:
        if require_runtime_user:
            raise ExecutionError(
                "SIFT_EXECUTE_REQUIRE_RUNTIME_USER=1 requires execute.runtime_user "
                "to be distinct from the service user."
            )
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

    if _systemd_scope_mode() != "off":
        return runtime_user, ""

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
    case_dir = _active_or_env_case_dir()
    # AUT2-B4: writable tool cache inside the case write-jail so cache-hungry
    # tools (volatility3 symbol cache) survive the restricted runtime user.
    cache_dir = str(Path(case_dir) / "tmp" / "cache") if case_dir else ""
    try:
        worker_result = _run_isolated_worker(
            cmd_list,
            timeout=timeout,
            cwd=cwd,
            max_output_bytes=max_bytes,
            memory_limit_bytes=config.execute_memory_limit_bytes,
            runtime_user=runtime_user,
            sudo_path=sudo_path,
            cache_dir=cache_dir,
        )
        elapsed = time.monotonic() - start

        stdout = str(worker_result.get("stdout", ""))
        stderr = str(worker_result.get("stderr", ""))

        # Collapse \r progress meters (vol3/tqdm) BEFORE counting/saving so the
        # flood can neither blow context nor bloat the saved file. Both streams
        # are cleaned (vol3 emits Progress: to stderr even under 2>&1).
        stdout, _so_progress = _strip_cr_progress(stdout)
        stderr, _se_progress = _strip_cr_progress(stderr)
        _progress_frames_removed = _so_progress + _se_progress

        # Recompute byte count from the cleaned stream — the original
        # stdout_total_bytes counted the progress flood we just discarded.
        stdout_byte_count = len(stdout.encode("utf-8"))

        response: dict[str, Any] = {
            "exit_code": int(worker_result["exit_code"]),
            "stdout": stdout,
            # Inline stderr stays a short diagnostic; the full stream is saved
            # alongside stdout when output is persisted (context efficiency).
            "stderr": _truncate(stderr, min(config.max_output_bytes // 10, 4000)),
            "elapsed_seconds": round(elapsed, 2),
            "command": cmd_list,
            "stdout_total_bytes": stdout_byte_count,
            "executor": "native_user_worker" if runtime_user else "direct_worker",
        }
        if runtime_user:
            response["runtime_user"] = runtime_user
        if _progress_frames_removed:
            response["progress_frames_removed"] = _progress_frames_removed
        if worker_result.get("truncated"):
            response["truncated"] = True
        if worker_result.get("stages"):
            response["stages"] = worker_result["stages"]
        # SEC-11: carry the applied isolation posture up the surfacing chain
        # (run_command response root + DB audit detail).
        isolation = worker_result.get("isolation")
        if isinstance(isolation, dict):
            response["isolation"] = isolation

        # AUT2-B7: binary stdout is useless (and costly) inline — switch to a
        # saved-file-first default: persist the bytes, suppress the inline blob.
        binary_output = _looks_binary(stdout)

        # Threshold-based save: auto-save when output exceeds the response
        # budget, when stdout looks binary, or when save_output is explicitly
        # requested. Resolve (and create) the numbered output dir lazily — only
        # when we are actually going to save — so unsaved commands don't litter
        # agent/run_commands/ with empty outputN/ directories.
        exceeds_budget = stdout_byte_count > config.response_byte_budget

        if (exceeds_budget and case_dir) or save_output or (binary_output and case_dir):
            if save_dir:
                out_dir = save_dir
            elif case_dir:
                out_dir = str(_next_run_command_output_dir(Path(case_dir)))
            elif cwd:
                out_dir = str(Path(cwd) / "extracted")
            else:
                out_dir = None
            _save_output(cmd_list, stdout, stderr, out_dir, response)

        if binary_output:
            response["binary_output"] = True
            if response.get("output_file"):
                response["stdout"] = ""
                response["stdout_note"] = (
                    "Binary output detected: inline preview suppressed; full "
                    "bytes saved to the referenced output file. Use targeted "
                    "tools (strings, xxd, grep) against the saved file."
                )
            else:
                response["stdout"] = stdout[:200]
                response["stdout_note"] = (
                    "Binary output detected and truncated inline; re-run with "
                    "save_output=true or redirect to a file for full bytes."
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
        if msg.startswith("Redirection target directory not found:"):
            raise ExecutionError(msg) from exc
        raise ExecutionError(
            f"File not found: {msg}. Command: {_format_command(cmd_list)}"
        ) from exc
    except PermissionError as exc:
        msg = str(exc)
        if msg.startswith("Permission denied on redirection target:"):
            raise ExecutionError(msg) from exc
        raise ExecutionError(
            f"Permission denied: {msg}. Command: {_format_command(cmd_list)}"
        ) from exc
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


import re as _re

# Carriage-return progress meters (Volatility 3 "Progress:  NN.NN ..." emitted
# with \r to overwrite one line, plus tqdm-style bars) flood the stream with
# tens of thousands of duplicate frames — a single vol3 windows.info produced
# ~139k lines / 9.4 MB of pure progress. We collapse them BEFORE byte-counting
# and saving so they can neither blow the agent context nor bloat the saved
# output file. Real tool output is preserved.
_CR_PROGRESS_RE = _re.compile(r"^\s*Progress:\s", _re.IGNORECASE)


def _strip_cr_progress(text: str) -> tuple[str, int]:
    """Collapse \\r progress frames and drop vol3/tqdm progress lines.

    Returns (cleaned_text, frames_removed). For each \\n-delimited line that
    contains \\r (a meter overwriting itself in place), only the final segment
    after the last \\r is kept (the last frame the terminal would show); that
    final segment is then dropped entirely if it is a Progress: meter line.
    Lines without \\r are passed through untouched, except standalone Progress:
    lines which are dropped.
    """
    if "\r" not in text and "Progress:" not in text:
        return text, 0
    removed = 0
    out_lines: list[str] = []
    for line in text.split("\n"):
        if "\r" in line:
            frames = line.split("\r")
            removed += sum(1 for f in frames[:-1] if f.strip())
            line = frames[-1]
        if _CR_PROGRESS_RE.match(line):
            removed += 1
            continue
        out_lines.append(line)
    return "\n".join(out_lines), removed


def _looks_binary(stdout: str) -> bool:
    """Heuristic binary detection on decoded tool stdout (AUT2-B7).

    The worker decodes with errors="replace", so raw binary shows up as NUL
    bytes and a high density of U+FFFD replacement characters in the head.
    """
    if not stdout:
        return False
    head = stdout[:8192]
    if "\x00" in head:
        return True
    if len(head) >= 64 and head.count("�") / len(head) > 0.05:
        return True
    return False


def _truncate(text: str, max_chars: int) -> str:
    """Truncate text to max_chars."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n... [truncated at {max_chars} chars]"


def _next_run_command_output_dir(case_dir: Path) -> Path:
    base = case_dir / "agent" / "run_commands"
    try:
        base.mkdir(parents=True, exist_ok=True)
        nums = []
        for d in base.iterdir():
            if d.is_dir() and d.name.startswith("output"):
                try:
                    nums.append(int(d.name[6:]))
                except ValueError:
                    pass
        n = max(nums, default=0) + 1
        out = base / f"output{n}"
        out.mkdir(exist_ok=True)
        return out
    except OSError:
        return base / "output1"



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

    # K5: refuse output directories that target authority/proof artifacts.
    if is_authority_path(str(out_dir)):
        raise ExecutionError(f"Refusing to write output to authority artifact: {out_dir}")

    # When case dir is known, restrict save_dir to agent, extractions, or tmp.
    case_dir = _active_or_env_case_dir() or None
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
        stdout_path = out_dir / f"{prefix}_stdout.txt"
        try:
            stdout_bytes = stdout.encode("utf-8", errors="replace")
            with open(stdout_path, "wb") as f:
                f.write(stdout_bytes)
                f.flush()
                os.fsync(f.fileno())
            response["output_file"] = str(stdout_path)
            response["output_sha256"] = hashlib.sha256(stdout_bytes).hexdigest()
        except OSError as e:
            logger.warning("Failed to save stdout to %s: %s", stdout_path, e)
            response.setdefault("warnings", []).append(
                f"save_output failed — could not write to {stdout_path}: {e}. "
                "Full output not persisted; use redirect '>' to a writable path instead."
            )

    if stderr:
        stderr_path = out_dir / f"{prefix}_stderr.txt"
        try:
            stderr_bytes = stderr.encode("utf-8", errors="replace")
            with open(stderr_path, "wb") as f:
                f.write(stderr_bytes)
                f.flush()
                os.fsync(f.fileno())
            response["stderr_file"] = str(stderr_path)
            response["stderr_sha256"] = hashlib.sha256(stderr_bytes).hexdigest()
        except OSError as e:
            logger.warning("Failed to save stderr to %s: %s", stderr_path, e)
