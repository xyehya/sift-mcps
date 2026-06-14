"""Tiny launcher for kernel-constrained ``run_command`` tool execution.

The worker invokes this module as an argv wrapper after the runtime-user
transition has already happened, normally through the transient systemd scope
and with sudo kept only as a non-scoped fallback. The launcher then closes inherited file
descriptors, applies local process limits, asserts it is not running as root or
the service uid, enables no-new-privs, installs Landlock/seccomp, and execs the
real forensic tool.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import errno
import json
import os
import platform
import resource
import sys
from pathlib import Path
from typing import Any

from sift_core.execute.runtime_acl import build_sandbox_env


class LauncherError(RuntimeError):
    """Raised when the launcher cannot safely exec the requested tool."""


PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2

SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_LOG = 0x7FFC0000
SECCOMP_RET_ALLOW = 0x7FFF0000

BPF_LD = 0x00
BPF_W = 0x00
BPF_ABS = 0x20
BPF_JMP = 0x05
BPF_JEQ = 0x10
BPF_K = 0x00
BPF_RET = 0x06

LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_RULE_PATH_BENEATH = 1

LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
LANDLOCK_ACCESS_FS_REFER = 1 << 13
LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14

LANDLOCK_ACCESS_NET_BIND_TCP = 1 << 0
LANDLOCK_ACCESS_NET_CONNECT_TCP = 1 << 1

FS_READ = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR
FS_RX = FS_READ | LANDLOCK_ACCESS_FS_EXECUTE
FS_WRITE = (
    LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM
)

_LIBC = ctypes.CDLL(None, use_errno=True)


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
    ]


class _LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.POINTER(_SockFilter)),
    ]


def encode_policy(policy: dict[str, Any]) -> str:
    raw = json.dumps(policy, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def decode_policy(encoded: str) -> dict[str, Any]:
    try:
        padded = encoded + "=" * (-len(encoded) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        policy = json.loads(raw.decode("utf-8"))
    except Exception as exc:  # pragma: no cover - exact parser failure unimportant
        raise LauncherError("invalid launcher policy") from exc
    if not isinstance(policy, dict):
        raise LauncherError("launcher policy must be a JSON object")
    return policy


def _syscall_number(name: str) -> int | None:
    machine = platform.machine().lower()
    table = {
        "x86_64": {
            "landlock_create_ruleset": 444,
            "landlock_add_rule": 445,
            "landlock_restrict_self": 446,
        },
        "amd64": {
            "landlock_create_ruleset": 444,
            "landlock_add_rule": 445,
            "landlock_restrict_self": 446,
        },
        "aarch64": {
            "landlock_create_ruleset": 444,
            "landlock_add_rule": 445,
            "landlock_restrict_self": 446,
        },
    }
    return table.get(machine, {}).get(name)


def _syscall(name: str, *args: object) -> int:
    nr = _syscall_number(name)
    if nr is None:
        raise OSError(errno.ENOSYS, f"syscall {name} unsupported on this architecture")
    result = _LIBC.syscall(ctypes.c_long(nr), *args)
    if result < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return int(result)


def _prctl(option: int, arg2: int = 0, arg3: int = 0, arg4: int = 0, arg5: int = 0) -> None:
    result = _LIBC.prctl(
        ctypes.c_int(option),
        ctypes.c_ulong(arg2),
        ctypes.c_ulong(arg3),
        ctypes.c_ulong(arg4),
        ctypes.c_ulong(arg5),
    )
    if result != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def _close_inherited_fds() -> None:
    try:
        fds = [int(name) for name in os.listdir("/proc/self/fd") if name.isdigit()]
    except OSError:
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        max_fd = 1024 if soft == resource.RLIM_INFINITY else int(soft)
        os.closerange(3, max_fd)
        return
    for fd in fds:
        if fd <= 2:
            continue
        try:
            os.close(fd)
        except OSError:
            pass


def _set_limits(policy: dict[str, Any]) -> None:
    timeout = int(policy.get("timeout") or 0)
    memory_limit = int(policy.get("memory_limit_bytes") or 0)
    file_size_limit = int(policy.get("file_size_limit_bytes") or 1_073_741_824)

    def lower_limit(kind: int, soft_value: int, hard_value: int | None = None) -> None:
        _soft, current_hard = resource.getrlimit(kind)
        hard_target = soft_value if hard_value is None else hard_value
        if current_hard != resource.RLIM_INFINITY:
            soft_value = min(soft_value, int(current_hard))
            hard_target = min(hard_target, int(current_hard))
        resource.setrlimit(kind, (soft_value, hard_target))

    if timeout > 0:
        cpu_limit = max(1, timeout + 1)
        lower_limit(resource.RLIMIT_CPU, cpu_limit, cpu_limit + 1)
    if memory_limit > 0 and hasattr(resource, "RLIMIT_AS"):
        lower_limit(resource.RLIMIT_AS, memory_limit)
    if hasattr(resource, "RLIMIT_FSIZE"):
        lower_limit(resource.RLIMIT_FSIZE, file_size_limit)
    if hasattr(resource, "RLIMIT_NOFILE"):
        lower_limit(resource.RLIMIT_NOFILE, 256)
    if hasattr(resource, "RLIMIT_NPROC"):
        lower_limit(resource.RLIMIT_NPROC, 64)
    if hasattr(resource, "RLIMIT_CORE"):
        lower_limit(resource.RLIMIT_CORE, 0)


def _assert_runtime_identity(policy: dict[str, Any]) -> None:
    if not hasattr(os, "getuid"):
        return
    uid = os.getuid()
    if uid == 0:
        raise LauncherError("dfir-exec-launcher refuses to run as uid 0")

    service_uid = policy.get("service_uid")
    if service_uid is not None and uid == int(service_uid):
        raise LauncherError("dfir-exec-launcher refuses to run as the service uid")

    runtime_uid = policy.get("runtime_uid")
    if runtime_uid is not None and uid != int(runtime_uid):
        raise LauncherError(
            f"dfir-exec-launcher expected runtime uid {runtime_uid}, got {uid}"
        )


def _set_no_new_privs() -> None:
    _prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)


def _landlock_abi() -> int:
    try:
        return _syscall(
            "landlock_create_ruleset",
            ctypes.c_void_p(0),
            ctypes.c_size_t(0),
            ctypes.c_uint32(LANDLOCK_CREATE_RULESET_VERSION),
        )
    except OSError as exc:
        if exc.errno in {errno.ENOSYS, errno.EOPNOTSUPP, errno.EINVAL}:
            return 0
        raise


def _fs_handled_access(abi: int) -> int:
    handled = FS_RX | FS_WRITE
    if abi >= 2:
        handled |= LANDLOCK_ACCESS_FS_REFER
    if abi >= 3:
        handled |= LANDLOCK_ACCESS_FS_TRUNCATE
    return handled


def _add_path_rule(ruleset_fd: int, path: str, access: int) -> None:
    if not path:
        return
    try:
        if not Path(path).is_dir():
            access &= ~LANDLOCK_ACCESS_FS_READ_DIR
    except OSError:
        return
    if access == 0:
        return
    try:
        fd = os.open(path, getattr(os, "O_PATH", os.O_RDONLY) | os.O_CLOEXEC)
    except OSError:
        return
    try:
        attr = _LandlockPathBeneathAttr(access, fd)
        _syscall(
            "landlock_add_rule",
            ctypes.c_int(ruleset_fd),
            ctypes.c_int(LANDLOCK_RULE_PATH_BENEATH),
            ctypes.byref(attr),
            ctypes.c_uint32(0),
        )
    finally:
        os.close(fd)


def _existing_paths(paths: list[str]) -> list[str]:
    out: list[str] = []
    for path in paths:
        if path and Path(path).exists():
            out.append(path)
    return out


def _install_landlock(policy: dict[str, Any]) -> int:
    require_landlock = bool(policy.get("require_landlock"))
    abi = _landlock_abi()
    if abi <= 0:
        if require_landlock:
            raise LauncherError("Landlock unavailable while fail-closed mode is required")
        return 0

    handled_fs = _fs_handled_access(abi)
    handled_net = (
        LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP
        if abi >= 4
        else 0
    )
    attr = _LandlockRulesetAttr(handled_fs, handled_net)
    ruleset_fd = _syscall(
        "landlock_create_ruleset",
        ctypes.byref(attr),
        ctypes.sizeof(attr),
        ctypes.c_uint32(0),
    )
    try:
        rx_paths = _existing_paths(
            [
                "/usr",
                "/bin",
                "/sbin",
                "/lib",
                "/lib64",
                "/usr/local/bin",
                "/opt/sift-mcps",
                "/opt/zimmermantools",
                "/opt/volatility3",
                "/opt/hayabusa",
                "/proc/self",
                "/etc/ld.so.cache",
                "/etc/ld.so.conf",
                "/etc/ld.so.conf.d",
                "/etc/alternatives",
                "/etc/localtime",
                "/etc/ssl/certs",
                "/etc/nsswitch.conf",
                "/usr/share",
            ]
        )
        for path in rx_paths:
            _add_path_rule(ruleset_fd, path, FS_RX & handled_fs)

        case_dir = str(policy.get("case_dir") or "").strip()
        if case_dir:
            for rel in ("evidence", "mounts_ro"):
                _add_path_rule(ruleset_fd, str(Path(case_dir) / rel), FS_READ & handled_fs)
            rw_access = (FS_READ | FS_WRITE) & handled_fs
            for rel in ("agent", "extractions", "tmp"):
                _add_path_rule(ruleset_fd, str(Path(case_dir) / rel), rw_access)

        vol_symbols_dir = str(policy.get("vol_symbols_dir") or "").strip()
        if vol_symbols_dir:
            access = (FS_READ | FS_WRITE) if os.access(vol_symbols_dir, os.W_OK) else FS_READ
            _add_path_rule(ruleset_fd, vol_symbols_dir, access & handled_fs)

        for dev_path, access in (
            ("/dev/null", FS_READ | LANDLOCK_ACCESS_FS_WRITE_FILE),
            ("/dev/zero", FS_READ),
            ("/dev/urandom", FS_READ),
            ("/dev/random", FS_READ),
        ):
            _add_path_rule(ruleset_fd, dev_path, access & handled_fs)

        _syscall(
            "landlock_restrict_self",
            ctypes.c_int(ruleset_fd),
            ctypes.c_uint32(0),
        )
        return abi
    finally:
        os.close(ruleset_fd)


_X86_64_LOG_SYSCALLS = {
    41,  # socket; LOG all socket use in Wave 1, enforce AF-specific in Wave 2.
    101,  # ptrace
    155,  # pivot_root
    161,  # chroot
    165,  # mount
    166,  # umount2
    167,  # swapon
    168,  # swapoff
    169,  # reboot
    175,  # init_module
    176,  # delete_module
    179,  # quotactl
    246,  # kexec_load
    248,  # add_key
    249,  # request_key
    250,  # keyctl
    272,  # unshare
    298,  # perf_event_open
    308,  # setns
    310,  # process_vm_readv
    311,  # process_vm_writev
    313,  # finit_module
    321,  # bpf
    425,  # io_uring_setup
    426,  # io_uring_enter
    427,  # io_uring_register
    428,  # open_tree
    429,  # move_mount
    430,  # fsopen
    432,  # fsmount
    435,  # clone3
    442,  # mount_setattr
}


def _seccomp_action(policy: dict[str, Any]) -> int:
    mode = str(policy.get("seccomp_mode") or os.environ.get("SIFT_EXECUTE_SECCOMP_MODE") or "log")
    return SECCOMP_RET_KILL_PROCESS if mode.strip().lower() == "kill" else SECCOMP_RET_LOG


def _install_seccomp(policy: dict[str, Any]) -> None:
    machine = platform.machine().lower()
    if machine not in {"x86_64", "amd64"}:
        if policy.get("require_seccomp"):
            raise LauncherError(f"seccomp syscall table is not defined for {machine}")
        return

    action = _seccomp_action(policy)
    filters: list[_SockFilter] = [_SockFilter(BPF_LD | BPF_W | BPF_ABS, 0, 0, 0)]
    for syscall_nr in sorted(_X86_64_LOG_SYSCALLS):
        filters.append(_SockFilter(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, syscall_nr))
        filters.append(_SockFilter(BPF_RET | BPF_K, 0, 0, action))
    filters.append(_SockFilter(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW))

    filter_array = (_SockFilter * len(filters))(*filters)
    program = _SockFprog(len=len(filters), filter=filter_array)
    _prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.addressof(program), 0, 0)


def _prepare_and_exec(policy: dict[str, Any], real_argv: list[str]) -> None:
    if not real_argv:
        raise LauncherError("missing real tool argv")

    _close_inherited_fds()

    cwd = str(policy.get("cwd") or policy.get("case_dir") or "").strip()
    if cwd:
        os.chdir(cwd)

    _set_limits(policy)
    _assert_runtime_identity(policy)
    _set_no_new_privs()
    _install_landlock(policy)
    _install_seccomp(policy)

    env = build_sandbox_env(base_env=dict(os.environ))
    os.execvpe(real_argv[0], real_argv, env)


def _read_policy_from_fd(fd_text: str) -> dict[str, Any]:
    try:
        fd = int(fd_text)
    except ValueError as exc:
        raise LauncherError("--policy-fd must be an integer") from exc
    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        policy = json.load(handle)
    if not isinstance(policy, dict):
        raise LauncherError("launcher policy must be a JSON object")
    return policy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dfir-exec-launcher")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--policy")
    group.add_argument("--policy-fd")
    parser.add_argument("real_argv", nargs=argparse.REMAINDER)
    ns = parser.parse_args(argv)

    real_argv = list(ns.real_argv)
    if real_argv and real_argv[0] == "--":
        real_argv = real_argv[1:]

    try:
        policy = decode_policy(ns.policy) if ns.policy else _read_policy_from_fd(ns.policy_fd)
        _prepare_and_exec(policy, real_argv)
    except Exception as exc:
        sys.stderr.write(f"dfir-exec-launcher: {exc}\n")
        sys.stderr.flush()
        return 126
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
