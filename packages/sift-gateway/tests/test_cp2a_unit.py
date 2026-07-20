"""CP2A — domain-level unit tests with fakes at the frozen interfaces.

These prove the pure custody-mutation logic that does NOT require a database: the
EC-6 canonical binding mirror, the distinct-per-target batch key derivation, the
fail-closed identity-authority verifier seam, and the input validation that every
mutation entry performs BEFORE it touches PostgreSQL. The end-to-end behavior on a
real migrated PostgreSQL is proven by ``test_cp2a_custody_postgres.py`` (DSN-skip).

Private helpers (``_run_verifier`` / ``_batch_target_key``) are exercised here for
fast unit feedback only; they are never the acceptance surface — the composed
tests prove acceptance through the public functions on a real database.
"""

from __future__ import annotations

import getpass
import hashlib
import os
import stat
from dataclasses import dataclass

import pytest
from sift_gateway.custody import actions, reauth, seal
from sift_gateway.custody.actions import ActionError, FindingDisposition, resolve
from sift_gateway.custody.reauth import ReauthError, build_binding
from sift_gateway.custody.seal import SealError, SealTarget, begin_seal, commit_seal


@dataclass
class _Session:
    """A minimal structural OperatorSession (actor_user_id + session_id)."""

    actor_user_id: str = "00000000-0000-0000-0000-0000000000aa"
    session_id: str = "sess-unit"


# ---------------------------------------------------------------------------
# EC-6 — the canonical binding mirror orders by code point == COLLATE "C"
# ---------------------------------------------------------------------------
def test_build_binding_ec6_mixed_case_rocba_codepoint_order() -> None:
    # 'R' (0x52) sorts before 'r' (0x72): code-point order == COLLATE "C". A revert
    # to a locale sort (lowercase first) would flip these and fail the assert.
    binding = build_binding(
        "seal-key",
        "  seal reason  ",
        ["evidence/rocba-cdrive.e01", "evidence/Rocba-Memory.raw"],
    )
    assert binding.targets == (
        "evidence/Rocba-Memory.raw",
        "evidence/rocba-cdrive.e01",
    )
    assert binding.reason == "seal reason"  # btrim mirror
    assert binding.idempotency_key == "seal-key"


def test_build_binding_input_order_independent() -> None:
    a = build_binding("k", "r", ["evidence/Rocba-Memory.raw", "evidence/rocba-cdrive.e01"])
    b = build_binding("k", "r", ["evidence/rocba-cdrive.e01", "evidence/Rocba-Memory.raw"])
    assert a.targets == b.targets


# ---------------------------------------------------------------------------
# D4 — distinct per-target batch idempotency keys
# ---------------------------------------------------------------------------
def test_batch_target_key_distinct_deterministic_bounded() -> None:
    k_ign_a = reauth._batch_target_key("bk", "IGNORE", "evidence/a")
    k_ign_b = reauth._batch_target_key("bk", "IGNORE", "evidence/b")
    k_ret_a = reauth._batch_target_key("bk", "RETIRE", "evidence/a")
    # Distinct across target AND across verb, so the reauth-idempotency index never
    # collides inside a heterogeneous batch (two RETIREs, or ignore+retire of one).
    assert len({k_ign_a, k_ign_b, k_ret_a}) == 3
    # Deterministic: a resubmitted batch (same batch_key) replays idempotently.
    assert k_ign_a == reauth._batch_target_key("bk", "IGNORE", "evidence/a")
    # Bounded to the schema's 1..128 key length.
    assert all(1 <= len(k) <= 128 for k in (k_ign_a, k_ign_b, k_ret_a))


# ---------------------------------------------------------------------------
# Fail-closed identity-authority verifier seam (operator constraint 1)
# ---------------------------------------------------------------------------
def test_run_verifier_unset_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    # An UNSET verifier means the authority is unreachable -> fail closed, never
    # a silent "skip verification".
    monkeypatch.setattr(reauth, "_VERIFIER", None)
    with pytest.raises(ReauthError) as exc:
        reauth._run_verifier("owner@example.com", "pw", "auth-uid")
    assert exc.value.reason == "reauth_unavailable"


def test_run_verifier_wrong_password_denies(monkeypatch: pytest.MonkeyPatch) -> None:
    def _reject(**_kw: object) -> None:
        raise ValueError("gotrue 401")

    monkeypatch.setattr(reauth, "_VERIFIER", _reject)
    with pytest.raises(ReauthError) as exc:
        reauth._run_verifier("owner@example.com", "wrong", "auth-uid")
    assert exc.value.reason == "reauth_failed"


def test_run_verifier_correct_password_binds_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[dict[str, object]] = []

    def _accept(**kw: object) -> None:
        seen.append(kw)

    monkeypatch.setattr(reauth, "_VERIFIER", _accept)
    reauth._run_verifier("owner@example.com", "correct", "auth-uid")
    # The verifier receives the session-bound expected_auth_user_id so a logged-in
    # operator cannot re-auth as a different operator (B-MVP-017 identity binding).
    assert seen == [
        {
            "email": "owner@example.com",
            "password": "correct",
            "expected_auth_user_id": "auth-uid",
        }
    ]


# ---------------------------------------------------------------------------
# D2 — evidence-DIRECTORY immutable protection (DB-independent; runs everywhere)
# ---------------------------------------------------------------------------
def _dir_flag_recorder(monkeypatch: pytest.MonkeyPatch) -> list[tuple[bool, bool]]:
    """Record (is_directory, immutable) for every set_immutable_flag_fd call."""
    calls: list[tuple[bool, bool]] = []

    def _set(fd: int, immutable: bool) -> bool:
        calls.append((stat.S_ISDIR(os.fstat(fd).st_mode), bool(immutable)))
        return True

    monkeypatch.setattr(seal, "set_immutable_flag_fd", _set)
    monkeypatch.setattr(seal, "get_immutable_flag_fd", lambda fd: True)
    return calls


def test_protect_and_verify_makes_directory_immutable(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    # Closes the D2 test blindness: the directory fd itself must get +i at protect,
    # AFTER every file fd — asserted against a real temp dir, no DB.
    calls = _dir_flag_recorder(monkeypatch)
    monkeypatch.setenv("SIFT_GATEWAY_SERVICE_USER", getpass.getuser())
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    f = evidence_dir / "img.raw"
    f.write_bytes(b"evidence bytes")
    os.chmod(f, 0o644)

    facts = seal._protect_and_verify(evidence_dir, [SealTarget("evidence/img.raw", 1)], {})
    assert len(facts) == 1
    assert (False, True) in calls  # the file fd was made immutable
    assert (True, True) in calls  # the DIRECTORY fd was made immutable (D2)
    assert calls[-1] == (True, True)  # directory +i comes after every file +i


def test_set_directory_immutable_lifts_the_flag(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    calls = _dir_flag_recorder(monkeypatch)
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    seal._set_directory_immutable(evidence_dir, immutable=False)
    assert calls == [(True, False)]  # exactly one directory-fd call, lifting +i


def test_reprotect_restores_fixed_posture_and_rehashes_same_pinned_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """A-F1 fail-on-revert: Reprotect is an on-disk posture repair, not an assertion."""
    evidence_dir = tmp_path / "case" / "evidence"
    evidence_dir.mkdir(parents=True)
    target = evidence_dir / "disk.E01"
    target.write_bytes(b"custody bytes")
    os.chmod(target, 0o600)
    st = target.stat()
    committed_sha256 = "sha256:" + hashlib.sha256(target.read_bytes()).hexdigest()

    class _Cursor:
        row = None

        def execute(self, sql, _params):
            if "from app.evidence_objects" in sql:
                self.row = (
                    "evidence/disk.E01",
                    committed_sha256,
                    st.st_size,
                    st.st_dev,
                    st.st_ino,
                )
            elif "select legacy_case_dir" in sql:
                self.row = (str(tmp_path / "case"),)
            else:  # pragma: no cover - catches unexpected query growth
                raise AssertionError(sql)

        def fetchone(self):
            return self.row

    immutable = {"value": False}
    transitions: list[bool] = []

    def _set_flag(_fd: int, enabled: bool) -> bool:
        transitions.append(enabled)
        immutable["value"] = enabled
        return True

    monkeypatch.setattr(seal, "set_immutable_flag_fd", _set_flag)
    monkeypatch.setattr(
        seal, "get_immutable_flag_fd", lambda _fd: immutable["value"]
    )

    posture = actions._restore_reprotect_posture(
        _Cursor(), "case-1", "evidence-object-1"
    )

    assert transitions == [False, True]
    assert stat.S_IMODE(target.stat().st_mode) == 0o644
    assert target.read_bytes() == b"custody bytes"
    assert posture == {
        "sha256": committed_sha256,
        "mode": "0644",
        "immutable": True,
    }


def test_reprotect_domain_uses_posture_restore_before_recording(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The honest REPROTECT verb cannot regress to the former hash-only precheck."""
    import psycopg

    class _Cursor:
        def __init__(self) -> None:
            self.row = None
            self.executions: list[tuple[str, object]] = []

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def execute(self, sql, params=None):
            self.executions.append((sql, params))
            if "select actor_user_id" in sql:
                self.row = ("operator-1",)
            elif "select display_path" in sql or "select o.display_path" in sql:
                self.row = ("evidence/disk.E01",)
            elif "select exists" in sql:
                self.row = (False,)
            elif "custody_reprotect" in sql:
                self.row = ("receipt-1",)
            elif "custody_gate_state" in sql:
                self.row = ("OPEN",)
            else:  # pragma: no cover - catches unexpected query growth
                raise AssertionError(sql)

        def fetchone(self):
            return self.row

    class _Connection:
        def __init__(self) -> None:
            self.cur = _Cursor()
            self.committed = False

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def cursor(self):
            return self.cur

        def commit(self):
            self.committed = True

    connection = _Connection()
    monkeypatch.setenv("SIFT_CONTROL_PLANE_DSN", "postgresql://unused")
    monkeypatch.setattr(psycopg, "connect", lambda _dsn: connection)
    restored: list[tuple[str, str]] = []

    def _restore(_cur, case_id, evidence_object_id):
        restored.append((case_id, evidence_object_id))
        return {"sha256": "sha256:" + "a" * 64, "mode": "0644", "immutable": True}

    monkeypatch.setattr(actions, "_restore_reprotect_posture", _restore)
    receipt = actions._reprotect(
        case_id="case-1",
        evidence_object_id="evidence-object-1",
        batch=reauth.BatchReauth(
            batch_key="batch-1",
            case_id="case-1",
            reason="restore posture",
            entries=(("REPROTECT", "evidence-object-1", "reauth-1"),),
        ),
        reauth_id="reauth-1",
    )

    assert restored == [("case-1", "evidence-object-1")]
    assert any("custody_reprotect" in sql for sql, _ in connection.cur.executions)
    assert connection.committed is True
    assert receipt.action == "REPROTECT"


# ---------------------------------------------------------------------------
# Input validation that raises BEFORE any database/network contact
# ---------------------------------------------------------------------------
def test_resolve_rejects_add_seal_before_any_reauth() -> None:
    # ADD_SEAL has no snapshot binding in a FindingDisposition -> rejected shaped
    # before record_batch_reauth is ever called (no orphaned authorization).
    with pytest.raises(ActionError) as exc:
        resolve(
            session=_Session(),
            case_id="c",
            password="pw",
            reason="r",
            dispositions=[FindingDisposition(verb="ADD_SEAL", target="evidence/x")],
            batch_key="bk",
        )
    assert exc.value.reason == "invalid_request"


def test_resolve_rejects_empty_dispositions() -> None:
    with pytest.raises(ActionError):
        resolve(
            session=_Session(),
            case_id="c",
            password="pw",
            reason="r",
            dispositions=[],
            batch_key="bk",
        )


def test_record_batch_reauth_rejects_empty_targets() -> None:
    with pytest.raises(ReauthError):
        reauth.record_batch_reauth(
            session=_Session(),
            password="pw",
            case_id="c",
            reason="r",
            targets=[],
            batch_key="bk",
        )


def test_begin_seal_rejects_empty_targets() -> None:
    # opens_staging_window reconciliation: the RPC requires a non-empty target set,
    # so the frozen targets=None default is rejected shaped before any reauth.
    with pytest.raises(SealError) as exc:
        begin_seal(
            session=_Session(),
            case_id="c",
            password="pw",
            reason="r",
            idempotency_key="k",
            targets=None,
        )
    assert exc.value.reason == "invalid_request"


def test_begin_seal_rejects_heterogeneous_snapshots() -> None:
    targets = [SealTarget("evidence/a", 1), SealTarget("evidence/b", 2)]
    with pytest.raises(SealError):
        begin_seal(
            session=_Session(),
            case_id="c",
            password="pw",
            reason="r",
            idempotency_key="k",
            targets=targets,
        )


def test_commit_seal_rejects_heterogeneous_snapshots() -> None:
    targets = [SealTarget("evidence/a", 1), SealTarget("evidence/b", 2)]
    with pytest.raises(SealError):
        commit_seal(
            session=_Session(),
            case_id="c",
            idempotency_key="k",
            targets=targets,
        )
