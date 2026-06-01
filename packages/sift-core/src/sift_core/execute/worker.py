"""Isolated argv-only worker for ``run_command`` execution.

The gateway process launches this module as a short-lived subprocess. This
worker then launches the requested forensic tool with ``shell=False`` and
returns a JSON result to the parent.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
from typing import Any


def _read_pipe(pipe, chunks: list[bytes], limit: int, total: list[int]) -> None:
    while True:
        remaining = limit - total[0]
        if remaining <= 0:
            break
        data = pipe.read(min(65536, remaining))
        if not data:
            break
        chunks.append(data)
        total[0] += len(data)


def _resource_preexec(timeout: int, memory_limit_bytes: int) -> None:
    try:
        import resource
    except ImportError:
        return

    if timeout > 0:
        cpu_limit = max(1, int(timeout) + 1)
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_limit, cpu_limit + 1))
    if memory_limit_bytes > 0 and hasattr(resource, "RLIMIT_AS"):
        resource.setrlimit(
            resource.RLIMIT_AS, (int(memory_limit_bytes), int(memory_limit_bytes))
        )


def _kill_process_tree(proc: subprocess.Popen[bytes]) -> None:
    if os.name == "posix":
        try:
            os.killpg(proc.pid, signal.SIGKILL)
            return
        except ProcessLookupError:
            return
        except OSError:
            pass
    proc.kill()


def _execute_payload(payload: dict[str, Any]) -> dict[str, Any]:
    cmd_list = payload["cmd"]
    timeout = int(payload["timeout"])
    max_bytes = int(payload["max_output_bytes"])
    cwd = payload.get("cwd") or None
    memory_limit_bytes = int(payload.get("memory_limit_bytes") or 0)

    start = time.monotonic()
    truncated = False
    preexec_fn = None
    if os.name == "posix":
        preexec_fn = lambda: _resource_preexec(timeout, memory_limit_bytes)

    proc = subprocess.Popen(
        cmd_list,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        shell=False,
        start_new_session=(os.name == "posix"),
        preexec_fn=preexec_fn,
    )

    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    total = [0]

    stdout_thread = threading.Thread(
        target=_read_pipe,
        args=(proc.stdout, stdout_chunks, max_bytes, total),
    )
    stderr_thread = threading.Thread(
        target=_read_pipe,
        args=(proc.stderr, stderr_chunks, max_bytes, total),
    )
    stdout_thread.start()
    stderr_thread.start()

    deadline = start + timeout
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _kill_process_tree(proc)
                proc.wait(timeout=5)
                return {
                    "error_type": "timeout",
                    "message": f"Command timed out after {timeout}s",
                    "elapsed_seconds": round(time.monotonic() - start, 2),
                }
            if total[0] >= max_bytes:
                truncated = True
                _kill_process_tree(proc)
                proc.wait(timeout=5)
                break
            try:
                proc.wait(timeout=min(0.1, remaining))
                break
            except subprocess.TimeoutExpired:
                continue
    finally:
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)

    if total[0] >= max_bytes:
        truncated = True

    stdout_raw = b"".join(stdout_chunks)
    stderr_raw = b"".join(stderr_chunks)
    result: dict[str, Any] = {
        "exit_code": proc.returncode,
        "stdout": stdout_raw.decode("utf-8", errors="replace"),
        "stderr": stderr_raw.decode("utf-8", errors="replace"),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "stdout_total_bytes": len(stdout_raw),
    }
    if truncated:
        result["truncated"] = True
    return result


def main() -> int:
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8"))
        result = _execute_payload(payload)
        sys.stdout.write(json.dumps(result, separators=(",", ":")))
        sys.stdout.flush()
        return 0
    except FileNotFoundError as exc:
        result = {"error_type": "not_found", "message": str(exc)}
    except PermissionError as exc:
        result = {"error_type": "permission", "message": str(exc)}
    except OSError as exc:
        result = {"error_type": "os_error", "message": str(exc)}
    except Exception as exc:
        result = {"error_type": "worker_error", "message": str(exc)}
    sys.stdout.write(json.dumps(result, separators=(",", ":")))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
