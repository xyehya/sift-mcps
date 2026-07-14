"""Final-open binding for Gateway-authorized evidence versions."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import NotRequired, Required, TypedDict

from sift_core.evidence_chain import get_immutable_flag_fd
from sift_core.evidence_storage import (
    StorageAuthorityError,
    StorageProfile,
    external_storage_facts,
)


class AdmittedEvidenceBinding(TypedDict, total=False):
    ref: Required[str]
    evidence_id: Required[str]
    version_id: Required[str]
    display_path: Required[str]
    path: Required[str]
    sha256: Required[str]
    bytes: Required[int]
    st_dev: Required[int]
    st_ino: Required[int]
    st_mtime_ns: Required[int]
    st_ctime_ns: NotRequired[int]
    immutable_required: NotRequired[bool]
    storage_profile: NotRequired[str]
    storage_source_identity: NotRequired[str]
    mount_instance_identity: NotRequired[str]
    read_only_required: NotRequired[bool]


InventoryIdentity = tuple[str, int, int, int, int, int, int, int]


def inventory_identity_rows(case_dir: str) -> list[InventoryIdentity]:
    """Return the shared pure direct-entry identity scan for custody freshness."""
    evidence_dir = Path(case_dir).resolve() / "evidence"
    rows: list[InventoryIdentity] = []
    with os.scandir(evidence_dir) as entries:
        for entry in sorted(entries, key=lambda item: item.name):
            st = entry.stat(follow_symlinks=False)
            rows.append(
                (
                    entry.name,
                    st.st_mode,
                    st.st_dev,
                    st.st_ino,
                    st.st_size,
                    st.st_mtime_ns,
                    st.st_ctime_ns,
                    st.st_nlink,
                )
            )
    return rows


def inventory_token(case_dir: str) -> str:
    material = json.dumps(
        inventory_identity_rows(case_dir), separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(material).hexdigest()


def validate_binding_fd(fd: int, binding: AdmittedEvidenceBinding) -> os.stat_result:
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
    profile = str(binding.get("storage_profile") or StorageProfile.LOCAL_IMMUTABLE)
    if profile == StorageProfile.LOCAL_IMMUTABLE:
        if binding.get("immutable_required") and get_immutable_flag_fd(fd) is not True:
            raise ValueError("admitted evidence immutable posture changed")
    elif profile == StorageProfile.EXTERNALLY_READ_ONLY:
        if not binding.get("read_only_required"):
            raise ValueError("external admitted evidence lacks read-only authority")
        try:
            facts = external_storage_facts(fd)
        except StorageAuthorityError as exc:
            raise ValueError("external admitted evidence posture changed") from exc
        if facts.source_identity != binding.get(
            "storage_source_identity"
        ) or facts.mount_instance_identity != binding.get("mount_instance_identity"):
            raise ValueError("external admitted evidence mount identity changed")
    else:
        raise ValueError("admitted evidence storage profile is invalid")
    return current


def open_bound_evidence(bindings: list[AdmittedEvidenceBinding]) -> dict[str, int]:
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
            # Evidence symlink aliases are unsupported. If a different lexical
            # operand resolves to an admitted file, fail closed instead of
            # letting the tool reopen the alias pathname after authorization.
            if os.path.realpath(lexical_path) in opened:
                raise ValueError("evidence symlink aliases are not supported")
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
