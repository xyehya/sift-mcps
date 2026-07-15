"""Generic local evidence filesystem posture utilities.

These helpers deliberately do not register, seal, inventory, or verify custody.
Postgres custody records are the sole authority for those decisions.
"""
from __future__ import annotations

import ctypes
import fcntl
import pwd
from pathlib import Path

DEFAULT_SERVICE_USER = "sift-service"
_FS_IOC_GETFLAGS = 0x80086601
_FS_IOC_SETFLAGS = 0x40086602
_FS_IMMUTABLE_FL = 0x00000010


class EvidenceHardeningError(RuntimeError):
    """A required local evidence posture could not be established."""


def _set_immutable(path: Path, immutable: bool) -> bool:
    try:
        flags = ctypes.c_int(0)
        with path.open("rb") as handle:
            fcntl.ioctl(handle.fileno(), _FS_IOC_GETFLAGS, flags)
            flags.value = (flags.value | _FS_IMMUTABLE_FL) if immutable else (flags.value & ~_FS_IMMUTABLE_FL)
            fcntl.ioctl(handle.fileno(), _FS_IOC_SETFLAGS, flags)
        return True
    except (OSError, AttributeError):
        return False


def get_immutable_flag(path: Path) -> bool | None:
    try:
        flags = ctypes.c_int(0)
        with path.open("rb") as handle:
            fcntl.ioctl(handle.fileno(), _FS_IOC_GETFLAGS, flags)
        return bool(flags.value & _FS_IMMUTABLE_FL)
    except (OSError, AttributeError):
        return None


def get_immutable_flag_fd(fd: int) -> bool | None:
    try:
        flags = ctypes.c_int(0)
        fcntl.ioctl(fd, _FS_IOC_GETFLAGS, flags)
        return bool(flags.value & _FS_IMMUTABLE_FL)
    except (OSError, AttributeError):
        return None


def set_immutable_flag_fd(fd: int, immutable: bool) -> bool:
    try:
        flags = ctypes.c_int(0)
        fcntl.ioctl(fd, _FS_IOC_GETFLAGS, flags)
        flags.value = (flags.value | _FS_IMMUTABLE_FL) if immutable else (flags.value & ~_FS_IMMUTABLE_FL)
        fcntl.ioctl(fd, _FS_IOC_SETFLAGS, flags)
        return True
    except (OSError, AttributeError):
        return False


def _resolve_sealed_target(case_dir: Path, rel_path: str) -> Path:
    """Resolve a hostile relative evidence path without following symlinks."""
    if not rel_path or "\x00" in rel_path:
        raise EvidenceHardeningError("Evidence path is empty or invalid")
    relative = Path(rel_path)
    if relative.is_absolute() or relative.parts[:1] != ("evidence",) or ".." in relative.parts:
        raise EvidenceHardeningError(f"Evidence path escapes evidence directory: {rel_path!r}")
    root = (case_dir / "evidence").resolve()
    literal = case_dir / relative
    if literal.is_symlink():
        raise EvidenceHardeningError(f"Refusing to harden a symlink: {rel_path!r}")
    try:
        target = literal.resolve(strict=True)
        target.relative_to(root)
    except (OSError, ValueError):
        raise EvidenceHardeningError(f"Evidence path is outside evidence directory: {rel_path!r}") from None
    if not target.is_file() or target.stat().st_nlink != 1:
        raise EvidenceHardeningError(f"Evidence target is not a singly-linked regular file: {rel_path!r}")
    return target


def _owner(path: Path) -> str | None:
    try:
        return pwd.getpwuid(path.stat().st_uid).pw_name
    except (KeyError, OSError):
        return None


def harden_sealed_evidence(case_dir: Path, rel_paths: list[str], *, service_user: str = DEFAULT_SERVICE_USER) -> list[dict]:
    results: list[dict] = []
    for rel_path in rel_paths:
        target = _resolve_sealed_target(case_dir, rel_path)
        owner = _owner(target)
        if owner != service_user or not _set_immutable(target, True) or not get_immutable_flag(target):
            raise EvidenceHardeningError(f"Could not establish immutable posture for {rel_path!r}")
        results.append({"path": rel_path, "immutable": True, "owner": owner})
    return results


def unharden_sealed_evidence(case_dir: Path, rel_paths: list[str]) -> list[dict]:
    results: list[dict] = []
    for rel_path in rel_paths:
        target = _resolve_sealed_target(case_dir, rel_path)
        _set_immutable(target, False)
        if get_immutable_flag(target):
            raise EvidenceHardeningError(f"Could not clear immutable posture for {rel_path!r}")
        results.append({"path": rel_path, "immutable": False})
    return results
