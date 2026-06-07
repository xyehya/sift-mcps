from __future__ import annotations

from pathlib import Path

from sift_core.active_case_context import ActiveCaseContext, use_active_case_context
from sift_core.case_io import get_case_dir, resolve_case_path


def test_gateway_active_case_context_wins_over_stale_env(monkeypatch, tmp_path):
    stale = tmp_path / "stale"
    db_case = tmp_path / "db-case"
    stale.mkdir()
    db_case.mkdir()
    monkeypatch.setenv("SIFT_CASE_DIR", str(stale))

    ctx = ActiveCaseContext(
        case_id="11111111-1111-1111-1111-111111111111",
        case_key="db-case",
        artifact_path=str(db_case),
        membership_role="operator",
    )
    with use_active_case_context(ctx):
        assert get_case_dir() == db_case
        assert resolve_case_path("artifact.bin") == db_case / "evidence" / "artifact.bin"

    assert get_case_dir() == stale


def test_active_case_context_is_request_local(tmp_path):
    one = tmp_path / "one"
    two = tmp_path / "two"
    one.mkdir()
    two.mkdir()

    with use_active_case_context(ActiveCaseContext("1", "one", str(one))):
        assert get_case_dir() == one
        with use_active_case_context(ActiveCaseContext("2", "two", str(two))):
            assert get_case_dir() == two
        assert get_case_dir() == one
