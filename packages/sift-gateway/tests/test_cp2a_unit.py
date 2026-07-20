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

from dataclasses import dataclass

import pytest
from sift_gateway.custody import reauth
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
