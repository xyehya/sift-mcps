"""XYE-35: CaseManager._require_active_case() must FAIL CLOSED on a runtime
authority-context error.

The historical bug wrapped both the optional ``active_case_context`` import and
the runtime authority calls (``current_active_case`` / ``db_authority_active``)
in a broad ``except Exception: pass``. If an authority call raised, ``db_active``
stayed ``False`` and resolution fell through to the tamperable
``SIFT_CASE_DIR`` / ``~/.sift/active_case`` file paths — a fail-OPEN downgrade
that violates the DB-authority invariant (BU1-BU4).

These tests pin the corrected behavior:

* a runtime error from ``db_authority_active()`` or ``current_active_case()``
  PROPAGATES (the call fails closed) and never adopts a file-mode active case;
* the legacy file fallback is preserved ONLY when the authority-context module
  is genuinely absent (``ImportError``) and DB authority is not active.
"""

from __future__ import annotations

import pytest

import sift_core.active_case_context as acc
from sift_core.case_manager import CaseManager


def _write_open_case(case_dir):
    case_dir.mkdir()
    (case_dir / "CASE.yaml").write_text("case_id: legacy-case\nstatus: open\n")
    return case_dir


def test_db_authority_active_runtime_error_fails_closed(monkeypatch, tmp_path):
    """db_authority_active() raising must propagate, not fall back to files."""

    def _boom() -> bool:
        raise RuntimeError("authority probe failed")

    monkeypatch.setattr(acc, "db_authority_active", _boom)

    # A tempting legacy file case that must NOT be adopted on a fail-open path.
    case_dir = _write_open_case(tmp_path / "legacy-case")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))

    cm = CaseManager()
    with pytest.raises(RuntimeError):
        cm._require_active_case()

    # Proof of fail-closed: the SIFT_CASE_DIR file case was never resolved.
    assert cm._active_case_path is None
    assert cm._active_case_id is None


def test_current_active_case_runtime_error_fails_closed(monkeypatch, tmp_path):
    """current_active_case() raising must propagate, not fall back to files."""

    def _boom():
        raise RuntimeError("context resolution failed")

    monkeypatch.setattr(acc, "current_active_case", _boom)

    case_dir = _write_open_case(tmp_path / "legacy-case")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))

    cm = CaseManager()
    with pytest.raises(RuntimeError):
        cm._require_active_case()

    assert cm._active_case_path is None
    assert cm._active_case_id is None


def test_import_error_preserves_file_fallback(monkeypatch, tmp_path):
    """Genuine ImportError of the authority module → legacy file mode still works.

    Deleting ``db_authority_active`` from the module makes the in-method
    ``from sift_core.active_case_context import current_active_case,
    db_authority_active`` raise ImportError — the one case where falling back to
    a valid SIFT_CASE_DIR file case is allowed (DB authority is not active).
    """
    monkeypatch.delattr(acc, "db_authority_active", raising=False)
    monkeypatch.delenv("SIFT_DB_ACTIVE", raising=False)

    case_dir = _write_open_case(tmp_path / "case-x")
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))

    cm = CaseManager()
    assert cm._require_active_case() == case_dir
    assert cm._active_case_path == case_dir
