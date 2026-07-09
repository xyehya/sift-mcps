"""Filesystem path helpers shared across SIFT-platform MCP servers."""

from __future__ import annotations

import tempfile
from pathlib import Path


def is_under_system_tmpdir(path: Path) -> bool:
    """Return True if ``path`` resolves under the OS temp directory.

    Used to detect throwaway pytest/dev-tool cases so integrity-record and
    audit writes route to a tmp-adjacent fallback instead of the production
    state root (see callers in sift_core.case_io, sift_core.evidence_chain,
    sift_core.audit_ops, sift_core.execute.security, sift_common.audit).

    Compares against ``tempfile.gettempdir()`` (resolved on both sides)
    rather than a hardcoded ``"/tmp/"`` prefix. On Linux — the SIFT VM
    production target and GitHub CI — ``/tmp`` is a real directory and
    ``gettempdir()`` returns it directly, so this is behavior-identical to
    the old hardcoded check there. On macOS, ``/tmp`` is a symlink to
    ``/private/tmp``; ``Path.resolve()`` follows it, so a literal
    ``"/tmp/"`` prefix check silently never matches, routing every case to
    the production state root instead of the intended tmp-adjacent
    fallback (2026-07-01: this caused real Mac-only test failures — case
    state either raised PermissionError against /var/lib/sift, or leaked
    across unrelated tests that happened to reuse the same case ID under a
    developer-configured SIFT_STATE_DIR).
    """
    resolved = Path(path).resolve()
    tmp_root = Path(tempfile.gettempdir()).resolve()
    return resolved.is_relative_to(tmp_root)
