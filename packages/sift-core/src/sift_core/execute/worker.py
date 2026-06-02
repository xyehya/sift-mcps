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


_pipe_lock = threading.Lock()

def _read_pipe(pipe, chunks: list[bytes], limit: int, total: list[int]) -> None:
    while True:
        with _pipe_lock:
            remaining = limit - total[0]
        if remaining <= 0:
            break
        data = pipe.read(min(65536, remaining))
        if not data:
            break
        with _pipe_lock:
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
    stages = payload.get("stages")
    if not stages:
        cmd_list = payload.get("cmd")
        if cmd_list:
            stages = [{"argv": cmd_list, "redirects": []}]
        else:
            raise ValueError("No command or stages specified in payload")

    timeout = int(payload["timeout"])
    max_bytes = int(payload["max_output_bytes"])
    cwd = payload.get("cwd") or None
    memory_limit_bytes = int(payload.get("memory_limit_bytes") or 0)

    start = time.monotonic()
    truncated = False
    preexec_fn = None
    if os.name == "posix":
        preexec_fn = lambda: _resource_preexec(timeout, memory_limit_bytes)

    processes = []
    prev_stdout = None
    
    try:
        for i, stage in enumerate(stages):
            argv = stage["argv"]
            redirects = stage["redirects"]
            
            stage_stdin = prev_stdout if prev_stdout is not None else subprocess.PIPE
            stage_stdout = subprocess.PIPE
            
            opened_files = []
            merge_stderr = False
            stage_stderr = subprocess.PIPE
            for op, target in redirects:
                if op == "2>&1":
                    merge_stderr = True
                    continue
                if op == ">":
                    f = open(target, "wb")
                    stage_stdout = f
                    opened_files.append(f)
                elif op == ">>":
                    f = open(target, "ab")
                    stage_stdout = f
                    opened_files.append(f)
                elif op == "<":
                    f = open(target, "rb")
                    stage_stdin = f
                    opened_files.append(f)
                    if prev_stdout is not None:
                        prev_stdout.close()
                        prev_stdout = None
                elif op in ("2>", "2>>"):
                    f = open(target, "ab" if op == "2>>" else "wb")
                    stage_stderr = f
                    opened_files.append(f)
                elif op in ("&>", "&>>"):
                    f = open(target, "ab" if op == "&>>" else "wb")
                    stage_stdout = f
                    stage_stderr = f
                    opened_files.append(f)

            # '2>&1' wins if combined with an explicit stderr file: merge means
            # stderr follows stdout's destination.
            if merge_stderr:
                stage_stderr = subprocess.STDOUT

            proc = subprocess.Popen(
                argv,
                stdin=stage_stdin,
                stdout=stage_stdout,
                stderr=stage_stderr,
                cwd=cwd,
                shell=False,
                start_new_session=(os.name == "posix"),
                preexec_fn=preexec_fn,
            )
            processes.append((proc, opened_files))
            
            if prev_stdout is not None:
                prev_stdout.close()
                
            if stage_stdout == subprocess.PIPE:
                prev_stdout = proc.stdout
            else:
                prev_stdout = None
                
    except Exception as exc:
        for proc, opened_files in processes:
            try:
                _kill_process_tree(proc)
            except Exception:
                pass
            for f in opened_files:
                try:
                    f.close()
                except Exception:
                    pass
        raise exc

    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    total = [0]
    threads = []

    # Read final stage stdout
    if prev_stdout is not None:
        t = threading.Thread(
            target=_read_pipe,
            args=(prev_stdout, stdout_chunks, max_bytes, total),
        )
        t.start()
        threads.append(t)

    # Read stderr from all stages (skipped for stages that merged stderr into
    # stdout via 2>&1, where proc.stderr is None).
    for proc, _ in processes:
        if proc.stderr is None:
            continue
        t = threading.Thread(
            target=_read_pipe,
            args=(proc.stderr, stderr_chunks, max_bytes, total),
        )
        t.start()
        threads.append(t)

    deadline = start + timeout
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                for proc, _ in processes:
                    _kill_process_tree(proc)
                for proc, _ in processes:
                    proc.wait(timeout=5)
                return {
                    "error_type": "timeout",
                    "message": f"Command timed out after {timeout}s",
                    "elapsed_seconds": round(time.monotonic() - start, 2),
                }
            if total[0] >= max_bytes:
                truncated = True
                for proc, _ in processes:
                    _kill_process_tree(proc)
                for proc, _ in processes:
                    proc.wait(timeout=5)
                break
                
            # Check if all processes have finished
            all_done = True
            for proc, _ in processes:
                if proc.poll() is None:
                    all_done = False
                    break
            if all_done:
                break
                
            time.sleep(0.05)
    finally:
        for t in threads:
            t.join(timeout=2)
        for _, opened_files in processes:
            for f in opened_files:
                try:
                    f.close()
                except Exception:
                    pass

    # exit code of last command in pipeline
    last_proc = processes[-1][0]
    
    if total[0] >= max_bytes:
        truncated = True

    stdout_raw = b"".join(stdout_chunks)
    stderr_raw = b"".join(stderr_chunks)
    result: dict[str, Any] = {
        "exit_code": last_proc.returncode,
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
