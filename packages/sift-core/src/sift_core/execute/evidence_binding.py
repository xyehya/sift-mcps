"""Final-open binding for Gateway-authorized evidence versions."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

from sift_core.evidence_chain import get_immutable_flag_fd


def validate_binding_fd(fd: int, binding: dict[str, Any]) -> os.stat_result:
    """Validate a pinned descriptor against the Gateway admission fingerprint."""
    current = os.fstat(fd)
    if not stat.S_ISREG(current.st_mode) or current.st_nlink != 1:
        raise ValueError("admitted evidence has unsafe file identity")
    expected = (
        int(binding.get("st_dev", -1)),
        int(binding.get("st_ino", -1)),
        int(binding.get("bytes", -1)),
        int(binding.get("st_mtime_ns", -1)),
        int(binding.get("st_ctime_ns", -1)),
    )
    actual = (
        current.st_dev,
        current.st_ino,
        current.st_size,
        current.st_mtime_ns,
        current.st_ctime_ns,
    )
    if expected != actual:
        raise ValueError("admitted evidence identity changed")
    if binding.get("immutable_required") and get_immutable_flag_fd(fd) is not True:
        raise ValueError("admitted evidence immutable posture changed")
    return current


def open_bound_evidence(bindings: list[dict[str, Any]]) -> dict[str, int]:
    """Open and validate every admitted path without following symlinks."""
    opened: dict[str, int] = {}
    try:
        for binding in bindings:
            path = str(binding.get("path") or "")
            lexical_path = os.path.abspath(os.path.normpath(path)) if path else ""
            if not lexical_path or lexical_path in opened:
                raise ValueError("admitted evidence binding is invalid")
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(lexical_path, flags)
            try:
                validate_binding_fd(fd, binding)
            except Exception:
                os.close(fd)
                raise
            os.set_inheritable(fd, True)
            opened[lexical_path] = fd
        return opened
    except Exception:
        close_bound_evidence(opened)
        raise


def rewrite_bound_operands(
    argv: list[str],
    redirects: list[tuple[str, str]],
    opened: dict[str, int],
    *,
    cwd: str | None,
) -> tuple[list[str], list[tuple[str, str]]]:
    """Replace exact admitted input operands with stable proc-fd references."""
    base = os.path.abspath(os.path.normpath(cwd or os.getcwd()))

    def rewrite(value: str) -> str:
        prefix = ""
        candidate_text = value
        if value.startswith("-") and "=" in value:
            prefix, candidate_text = value.split("=", 1)
            prefix += "="
        candidate = (
            candidate_text
            if os.path.isabs(candidate_text)
            else os.path.join(base, candidate_text)
        )
        lexical_path = os.path.abspath(os.path.normpath(candidate))
        fd = opened.get(lexical_path)
        if fd is None:
            return value
        fd_root = "/proc/self/fd" if Path("/proc/self/fd").is_dir() else "/dev/fd"
        return f"{prefix}{fd_root}/{fd}"

    rewritten_argv = [argv[0], *(rewrite(item) for item in argv[1:])]
    rewritten_redirects = [
        (op, rewrite(target) if op == "<" else target) for op, target in redirects
    ]
    return rewritten_argv, rewritten_redirects


def close_bound_evidence(opened: dict[str, int]) -> None:
    for fd in opened.values():
        try:
            os.close(fd)
        except OSError:
            pass
