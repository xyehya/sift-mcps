"""Read-only MCP evidence admission helpers.

The filesystem is observation input only.  This module extracts evidence
operands from agent commands and carries Gateway-authorized, version-bound
references through the current tool dispatch.  It never changes evidence
bytes or metadata.
"""

from __future__ import annotations

import os
from contextvars import ContextVar
from pathlib import Path
from typing import Any

from sift_core.execute.evidence_binding import (
    AdmittedEvidenceBinding,
)

_ADMITTED_REFS: ContextVar[tuple[AdmittedEvidenceBinding, ...]] = ContextVar(
    "sift_gateway_admitted_evidence_refs", default=()
)
_INVENTORY_TOKEN: ContextVar[str] = ContextVar("sift_gateway_inventory_token", default="")


def current_admitted_refs() -> list[AdmittedEvidenceBinding]:
    """Return a defensive copy of the references bound to this dispatch."""
    return [_copy_admitted_ref(item) for item in _ADMITTED_REFS.get()]


def current_inventory_token() -> str:
    return _INVENTORY_TOKEN.get()


def bind_admitted_refs(refs: list[AdmittedEvidenceBinding], *, inventory_token: str):
    """Bind authorized references for the duration of one middleware call."""
    return (
        _ADMITTED_REFS.set(tuple(_copy_admitted_ref(item) for item in refs)),
        _INVENTORY_TOKEN.set(inventory_token),
    )


def reset_admitted_refs(token: Any) -> None:
    refs_token, inventory_token = token
    _ADMITTED_REFS.reset(refs_token)
    _INVENTORY_TOKEN.reset(inventory_token)


def serialize_resolved_ref(item: AdmittedEvidenceBinding) -> AdmittedEvidenceBinding:
    """Keep a private evidence-version binding JSON-safe and explicit."""
    return _copy_admitted_ref(item)


def _copy_admitted_ref(item: AdmittedEvidenceBinding) -> AdmittedEvidenceBinding:
    """Copy the complete, required private binding without widening its type."""
    return {
        "ref": item["ref"],
        "evidence_id": item["evidence_id"],
        "version_id": item["version_id"],
        "display_path": item["display_path"],
        "path": str(item["path"]),
        "sha256": item["sha256"],
        "bytes": item["bytes"],
        "st_dev": item["st_dev"],
        "st_ino": item["st_ino"],
        "st_mtime_ns": item["st_mtime_ns"],
        "st_ctime_ns": item.get("st_ctime_ns", -1),
        "immutable_required": item.get("immutable_required", False),
    }


def command_evidence_references(
    command: Any,
    *,
    case_dir: str,
    working_dir: Any = None,
) -> list[str]:
    """Extract case-relative evidence paths from an agent command.

    This is deliberately conservative: every token that resolves beneath the
    evidence directory is treated as an evidence operand, whether it is an
    input, output, redirect, or ``flag=value`` value.  The command policy still
    independently decides whether an operation is executable.  Admission only
    decides whether referenced evidence has an active sealed version.
    """
    text = str(command or "").strip()
    if not text or not case_dir:
        return []
    case_root = Path(case_dir).resolve()
    evidence_root = case_root / "evidence"
    cwd = _working_directory(case_root, working_dir)
    from sift_core.execute.security import (
        parse_subcommand_argv_and_redirects,
        split_command_by_operators,
    )

    tokens: list[str] = []
    try:
        for subcommand, _operator in split_command_by_operators(text):
            argv, redirects = parse_subcommand_argv_and_redirects(subcommand)
            tokens.extend(argv[1:])
            tokens.extend(target for op, target in redirects if op != "2>&1")
    except (TypeError, ValueError):
        # The execution parser will reject malformed quoting.  Admission must
        # not guess at an incompletely parsed path.
        return []

    found: list[str] = []
    for raw in tokens:
        value = raw.split("=", 1)[1] if raw.startswith("-") and "=" in raw else raw
        value = value.strip()
        if not value or value.startswith("-"):
            continue
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = cwd / candidate
        lexical = Path(os.path.abspath(os.path.normpath(candidate)))
        try:
            resolved = candidate.resolve(strict=False)
        except OSError:
            resolved = lexical
        if not resolved.is_relative_to(evidence_root):
            continue
        if lexical != resolved:
            raise ValueError("evidence symlink aliases are not supported")
        rel = resolved.relative_to(case_root).as_posix()
        if rel not in found:
            found.append(rel)
    return found


def _working_directory(case_root: Path, value: Any) -> Path:
    text = str(value or "").strip()
    if not text:
        return case_root
    candidate = Path(text)
    if not candidate.is_absolute():
        candidate = case_root / candidate
    resolved = candidate.resolve(strict=False)
    return resolved if resolved.is_relative_to(case_root) else case_root
