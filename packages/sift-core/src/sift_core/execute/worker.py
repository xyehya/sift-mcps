"""Isolated argv-only worker for ``run_command`` execution.

The gateway process launches this module as a short-lived subprocess. This
worker then launches the requested forensic tool with ``shell=False`` and
returns a JSON result to the parent.
"""

from __future__ import annotations

import json
import os
import pwd
import signal
import subprocess
import sys
import threading
import time
from typing import Any

from sift_core.execute.dfir_exec_launcher import (
    encode_policy as _encode_launcher_policy,
)
from sift_core.execute.runtime_acl import (
    assert_no_authority_write_target as _assert_no_authority_write_target,
)
from sift_core.execute.runtime_acl import (
    build_sandbox_env,
)

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
    # Artifact-handoff (P1): forensic pipelines extract a file with one tool
    # (e.g. `icat > extractions/hive`) and parse it with the next call/stage
    # (rip.pl, EvtxECmd). When stages run as the low-priv runtime user a
    # restrictive inherited umask produced 0600 files that the next stage and
    # the gateway (response-guard / saved-output reads) could not read. Set a
    # 0027 umask so artifacts under the case jail are group-readable (mode 0640,
    # group `sift` — shared by the runtime user and the service user) while
    # staying non-world-readable. Strictly inside the case write-jail; this only
    # affects the bits on files the tool creates, never which paths are writable.
    try:
        os.umask(0o027)
    except OSError:  # pragma: no cover - defensive
        pass

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
    case_dir = str(payload.get("case_dir") or cwd or os.environ.get("SIFT_CASE_DIR") or "").strip()
    memory_limit_bytes = int(payload.get("memory_limit_bytes") or 0)
    runtime_user = str(payload.get("runtime_user") or "").strip()
    sudo_path = str(payload.get("sudo_path") or "/usr/bin/sudo").strip()
    runtime_user_already_applied = bool(payload.get("runtime_user_already_applied"))
    launcher_enabled = bool(payload.get("launcher_enabled", bool(runtime_user)))
    launcher_required = bool(payload.get("launcher_required"))
    require_landlock = bool(payload.get("require_landlock"))
    seccomp_mode = str(payload.get("seccomp_mode") or "log").strip().lower()
    if seccomp_mode not in {"log", "kill"}:
        seccomp_mode = "log"
    service_uid = payload.get("service_uid")
    service_gid = payload.get("service_gid")

    start = time.monotonic()
    truncated = False
    preexec_fn = None
    if os.name == "posix":
        def preexec_fn() -> None:
            _resource_preexec(timeout, memory_limit_bytes)

    # K5 authority isolation: scrub the environment the forensic tool runs with.
    # The worker process itself was already spawned with a scrubbed env, but we
    # rebuild here so the guarantee holds even when the worker is invoked
    # directly (tests, alternate entrypoints) and so secrets never leak through
    # a stray inherited variable. We keep PATH so binaries still resolve.
    tool_env = build_sandbox_env()

    # AUT2-B4 (+ follow-up): forensic tools run as the restricted runtime user,
    # whose real HOME and the tools' read-only install dirs are not writable. Any
    # tool that persists under ~/.cache, ~/.config, ~/.local, or a tool data/
    # symbol store would fail with PermissionError before analysis starts (B4 saw
    # this for volatility3's symbol cache; it is NOT vol-specific). Give them a
    # writable HOME + XDG base dirs and a writable Volatility symbol store, all
    # INSIDE the case tmp/ write-jail — no root, nothing escapes the jail. This is
    # the right answer for "tool needs to write somewhere"; a tool that needs
    # actual kernel/device privilege is a separate, allow-listed path, never a
    # blanket sudo. Best-effort per dir: one that cannot be created is omitted.
    cache_dir = str(payload.get("cache_dir") or "").strip()
    env_overrides: dict[str, str] = {}
    vol_symbols_dir = ""
    if cache_dir:
        try:
            os.makedirs(cache_dir, exist_ok=True)
        except OSError:
            cache_dir = ""
    if cache_dir:
        env_overrides["XDG_CACHE_HOME"] = cache_dir
        jail = os.path.dirname(cache_dir)  # the case tmp/ write-jail
        home_dir = os.path.join(jail, "home")
        for key, path in (
            ("HOME", home_dir),
            ("XDG_CONFIG_HOME", os.path.join(home_dir, ".config")),
            ("XDG_DATA_HOME", os.path.join(home_dir, ".local", "share")),
            ("XDG_STATE_HOME", os.path.join(home_dir, ".local", "state")),
        ):
            try:
                os.makedirs(path, exist_ok=True)
            except OSError:
                continue
            env_overrides[key] = path
        # vol3 writes generated ISF symbols into its read-only install symbol
        # store, not into HOME/XDG, so it needs an explicit writable --symbol-dirs
        # (injected per-stage below). PREFER the shared, group-writable symbol
        # cache when SIFT_VOL_SYMBOLS points at a writable dir — that lets the
        # service user and the agent_runtime sandbox user share generated symbols
        # instead of re-deriving them per case. Otherwise fall back to the
        # per-case write-jail dir so K5 isolation still holds with no shared cache.
        shared_sym = str(os.environ.get("SIFT_VOL_SYMBOLS") or "").strip()
        vol_symbols_dir = ""
        if shared_sym:
            try:
                os.makedirs(shared_sym, exist_ok=True)
                if os.access(shared_sym, os.W_OK):
                    vol_symbols_dir = shared_sym
            except OSError:
                vol_symbols_dir = ""
        if not vol_symbols_dir:
            sym = os.path.join(jail, "vol-symbols")
            try:
                os.makedirs(sym, exist_ok=True)
                vol_symbols_dir = sym
            except OSError:
                vol_symbols_dir = ""
        tool_env.update(env_overrides)

    processes = []
    prev_stdout = None
    
    try:
        for _i, stage in enumerate(stages):
            original_argv = list(stage["argv"])
            if vol_symbols_dir:
                original_argv = _inject_vol_symbol_dir(original_argv, vol_symbols_dir)
            stage_runtime_user = str(stage.get("runtime_user", runtime_user) or "").strip()
            stage_user_already_applied = (
                runtime_user_already_applied and stage_runtime_user == runtime_user
            )
            launch_argv = _argv_for_launcher(
                original_argv,
                runtime_user=stage_runtime_user,
                launcher_enabled=launcher_enabled,
                launcher_required=launcher_required,
                require_landlock=require_landlock,
                seccomp_mode=seccomp_mode,
                timeout=timeout,
                cwd=cwd,
                case_dir=case_dir,
                memory_limit_bytes=memory_limit_bytes,
                max_output_bytes=max_bytes,
                service_uid=service_uid,
                service_gid=service_gid,
                vol_symbols_dir=vol_symbols_dir,
            )
            argv = _argv_for_runtime_user(
                launch_argv,
                "" if stage_user_already_applied else stage_runtime_user,
                sudo_path,
                env_overrides=env_overrides,
            )
            redirects = stage["redirects"]
            
            stage_stdin = prev_stdout if prev_stdout is not None else subprocess.DEVNULL
            stage_stdout = subprocess.PIPE
            
            opened_files = []
            merge_stderr = False
            stage_stderr = subprocess.PIPE
            for op, target in redirects:
                if op == "2>&1":
                    merge_stderr = True
                    continue
                # Verify parent directory exists for write redirects
                if op in (">", ">>", "2>", "2>>", "&>", "&>>"):
                    # K5: never let a redirect overwrite an authority/proof
                    # artifact, even inside the case write-jail.
                    _assert_no_authority_write_target([target])
                    parent = os.path.dirname(target)
                    if parent and not os.path.isdir(parent):
                        raise FileNotFoundError(
                            f"Redirection target directory not found: '{parent}'. "
                            f"Create the directory first before redirecting to '{target}'."
                        )
                try:
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
                except FileNotFoundError as exc:
                    raise FileNotFoundError(f"Redirection target not found: {target}") from exc
                except PermissionError as exc:
                    raise PermissionError(f"Permission denied on redirection target: {target}") from exc

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
                env=tool_env,
            )
            processes.append((proc, opened_files, original_argv))
            
            if prev_stdout is not None:
                prev_stdout.close()
                
            if stage_stdout == subprocess.PIPE:
                prev_stdout = proc.stdout
            else:
                prev_stdout = None
                
    except Exception as exc:
        for proc, opened_files, _ in processes:
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
    # stdout via 2>&1, where proc.stderr is None). AUT2-B5: capture stderr
    # PER STAGE so a failing upstream stage's diagnostics survive instead of
    # being lost in one aggregated blob masked by a succeeding final stage.
    stage_stderr_chunks: dict[int, list[bytes]] = {}
    for idx, (proc, _, _) in enumerate(processes):
        if proc.stderr is None:
            continue
        chunks: list[bytes] = []
        stage_stderr_chunks[idx] = chunks
        t = threading.Thread(
            target=_read_pipe,
            args=(proc.stderr, chunks, max_bytes, total),
        )
        t.start()
        threads.append(t)

    deadline = start + timeout
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                for proc, _, _ in processes:
                    _kill_process_tree(proc)
                for proc, _, _ in processes:
                    proc.wait(timeout=1)
                return {
                    "error_type": "timeout",
                    "message": f"Command timed out after {timeout}s",
                    "elapsed_seconds": round(time.monotonic() - start, 2),
                }
            if total[0] >= max_bytes:
                truncated = True
                for proc, _, _ in processes:
                    _kill_process_tree(proc)
                for proc, _, _ in processes:
                    proc.wait(timeout=1)
                break
                
            # Check if all processes have finished
            all_done = True
            for proc, _, _ in processes:
                if proc.poll() is None:
                    all_done = False
                    break
            if all_done:
                break
                
            time.sleep(0.05)
    finally:
        for t in threads:
            t.join(timeout=2)
        for proc, opened_files, _ in processes:
            try:
                proc.wait(timeout=0)
            except subprocess.TimeoutExpired:
                pass
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
    stderr_raw = b"".join(
        b"".join(stage_stderr_chunks.get(idx, []))
        for idx in range(len(processes))
    ) + b"".join(stderr_chunks)

    stages_out: list[dict[str, Any]] = []
    for idx, (proc, _, original_argv) in enumerate(processes):
        entry: dict[str, Any] = {
            "argv": original_argv,
            "exit_code": proc.returncode,
        }
        raw = b"".join(stage_stderr_chunks.get(idx, []))
        if raw:
            # Short tail only: enough to diagnose a failed stage without bloat.
            entry["stderr_tail"] = raw[-2000:].decode("utf-8", errors="replace")[-400:]
        stages_out.append(entry)

    result: dict[str, Any] = {
        "exit_code": last_proc.returncode,
        "stdout": stdout_raw.decode("utf-8", errors="replace"),
        "stderr": stderr_raw.decode("utf-8", errors="replace"),
        "elapsed_seconds": round(time.monotonic() - start, 2),
        "stdout_total_bytes": len(stdout_raw),
        "stages": stages_out,
    }
    if runtime_user:
        result["runtime_user"] = runtime_user
    if truncated:
        result["truncated"] = True
    return result


_VOL_BINARIES = frozenset({"vol", "vol.py", "vol3", "volatility", "volatility3"})


def _inject_vol_symbol_dir(argv: list[str], symbols_dir: str) -> list[str]:
    """Prepend a writable ``--symbol-dirs`` to a Volatility 3 invocation.

    vol3 writes generated ISF symbol files into one of the read-only
    ``volatility3.symbols`` package paths (its install dir). Under the restricted
    runtime user none of those are writable, so symbol generation fails even
    though the image is valid (there is no symbol-dir env var — only this CLI
    flag prepends a path that vol also writes to first). A writable jail dir lets
    vol generate symbols for any image WITHOUT root. Non-vol commands, and vol
    invocations that already carry a symbol-dir flag, are returned unchanged.
    """
    if not argv or os.path.basename(argv[0]) not in _VOL_BINARIES:
        return argv
    if any(a in ("-s", "--symbol-dirs") for a in argv[1:]):
        return argv
    return [argv[0], "--symbol-dirs", symbols_dir, *argv[1:]]


def _runtime_ids(runtime_user: str) -> tuple[int | None, int | None]:
    if not runtime_user:
        return None, None
    try:
        pw = pwd.getpwnam(runtime_user)
    except KeyError:
        return None, None
    return int(pw.pw_uid), int(pw.pw_gid)


def _argv_for_launcher(
    argv: list[str],
    *,
    runtime_user: str,
    launcher_enabled: bool,
    launcher_required: bool,
    require_landlock: bool,
    seccomp_mode: str,
    timeout: int,
    cwd: str | None,
    case_dir: str,
    memory_limit_bytes: int,
    max_output_bytes: int,
    service_uid: int | None,
    service_gid: int | None,
    vol_symbols_dir: str,
) -> list[str]:
    if not launcher_enabled:
        return argv
    if not runtime_user and not launcher_required:
        return argv

    runtime_uid, runtime_gid = _runtime_ids(runtime_user)
    policy = {
        "case_dir": case_dir,
        "cwd": cwd or case_dir,
        "timeout": timeout,
        "memory_limit_bytes": memory_limit_bytes,
        "max_output_bytes": max_output_bytes,
        "runtime_user": runtime_user,
        "runtime_uid": runtime_uid,
        "runtime_gid": runtime_gid,
        "service_uid": service_uid,
        "service_gid": service_gid,
        "require_landlock": require_landlock,
        "seccomp_mode": seccomp_mode,
        "vol_symbols_dir": vol_symbols_dir,
    }
    return [
        sys.executable,
        "-m",
        "sift_core.execute.dfir_exec_launcher",
        "--policy",
        _encode_launcher_policy(policy),
        "--",
        *argv,
    ]


def _argv_for_runtime_user(
    argv: list[str],
    runtime_user: str,
    sudo_path: str,
    env_overrides: dict[str, str] | None = None,
) -> list[str]:
    if not runtime_user:
        return argv
    try:
        current_user = pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        current_user = ""
    if runtime_user == current_user:
        return argv
    wrapped = [sudo_path, "-n", "-u", runtime_user, "--"]
    if env_overrides:
        # sudo resets the environment for the target user; re-apply the
        # sandbox cache overrides via /usr/bin/env so tools like volatility3
        # see XDG_CACHE_HOME without requiring sudoers SETENV grants.
        wrapped += ["/usr/bin/env", *[f"{k}={v}" for k, v in env_overrides.items()]]
    return wrapped + argv


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
