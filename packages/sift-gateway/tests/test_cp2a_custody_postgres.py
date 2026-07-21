"""CP2A — seal/reauth/actions acceptance on a migrated PostgreSQL (composed).

The DB-level + composed acceptance for the custody mutation lane (SPEC §Automated
contract level + the amendment-acceptance bullet; OPERATING-MODEL §9). These run
the frozen ``app.custody_*`` RPCs through the CP2A Python orchestration against a
real migrated PostgreSQL, proving the non-negotiable matrix:

* **EC-6** — a mixed-case multi-file (``Rocba-Memory.raw`` + ``rocba-cdrive.e01``)
  reauth-and-seal SUCCEEDS, and a locale-sorted binding is REJECTED (fail-on-
  revert: the SQL builder orders COLLATE "C" on both write and verify).
* **Verifier seam (fail-closed)** — an unset verifier and a wrong password each
  record NOTHING; a correct password records the SQL-authoritative binding.
* **§4 retry** — same-key resume returns the pointer; a COMMITTED op replays; a
  different key while incomplete is rejected (one active Seal per case).
* **One password** — happy-path single-shot prompts once; a resume commit demands
  a fresh reauth.
* **D2 staging window**, **snapshot TOCTOU**, and **EC-2** (a failed DB-only
  action leaves no block; a subsequent action succeeds).

Gated on ``SIFT_CONTROL_PLANE_DSN`` and marked integration, exactly like the CP1
``*_postgres`` suites; CI's Postgres job and the CP3 VM gate run them, locally
they skip. The filesystem immutable-flag primitive is monkeypatched (hosts
without CAP_LINUX_IMMUTABLE) but the digest recompute, identity checks, and every
RPC run for real. Rows are permanent by design (append-only custody chain).
"""

from __future__ import annotations

import getpass
import os
import stat
import uuid
from dataclasses import dataclass

import pytest
from sift_core.execute.evidence_binding import classify_inventory_entries
from sift_gateway.custody import reauth, seal
from sift_gateway.custody.actions import ActionError, FindingDisposition, resolve
from sift_gateway.custody.seal import SealTarget, begin_seal, commit_seal, seal_status

pytestmark = pytest.mark.integration


def _dsn() -> str:
    dsn = os.environ.get("SIFT_CONTROL_PLANE_DSN", "").strip()
    if not dsn:
        pytest.skip("SIFT_CONTROL_PLANE_DSN is required for the CP2A custody acceptance")
    return dsn


def _conn():
    import psycopg

    return psycopg.connect(_dsn())


@dataclass
class _Session:
    actor_user_id: str
    session_id: str = "sess-cp2a"


class _Verifier:
    """A fake identity-authority verifier recording each (email, password) call."""

    def __init__(self, *, reject: bool = False) -> None:
        self.calls: list[dict[str, object]] = []
        self._reject = reject

    def __call__(self, **kw: object) -> None:
        self.calls.append(kw)
        if self._reject:
            raise ValueError("gotrue rejected the password")


class _FlagRecorder:
    """Records every immutable-flag CALL so tests can assert the directory fd got
    ``+i`` at commit and was lifted at window-open (real ``chattr +i`` is
    unavailable in CI, so we assert the calls, not the on-disk flag). Each recorded
    call is ``(is_directory, immutable)`` — the directory fd is distinguished from
    file fds by ``S_ISDIR`` on the live fd at call time."""

    def __init__(self) -> None:
        self.set_calls: list[tuple[bool, bool]] = []

    def set(self, fd: int, immutable: bool) -> bool:
        self.set_calls.append((stat.S_ISDIR(os.fstat(fd).st_mode), bool(immutable)))
        return True

    def get(self, fd: int) -> bool:  # commit re-verifies get(...) is True.
        return True

    def dir_calls(self) -> list[bool]:
        """The immutable-values applied to DIRECTORY fds, in call order."""
        return [immutable for (is_dir, immutable) in self.set_calls if is_dir]


def _install(
    monkeypatch: pytest.MonkeyPatch, verifier: object | None
) -> _FlagRecorder:
    """Wire the verifier seam + a CALL-RECORDING immutable-flag primitive.

    Returns the recorder so a test can assert the directory-fd ``+i`` calls (D2).
    """
    monkeypatch.setattr(reauth, "_VERIFIER", verifier)
    recorder = _FlagRecorder()
    monkeypatch.setattr(seal, "set_immutable_flag_fd", recorder.set)
    monkeypatch.setattr(seal, "get_immutable_flag_fd", recorder.get)
    # The evidence files are created by THIS process, so the seal's service-owner
    # check must resolve to the current user.
    monkeypatch.setenv("SIFT_GATEWAY_SERVICE_USER", getpass.getuser())
    return recorder


def _new_operator(cur) -> str:
    op_id = str(uuid.uuid4())
    cur.execute(
        "insert into app.operator_profiles(id, display_name, email, status) "
        "values(%s, 'CP2A Owner', %s, 'active')",
        (op_id, f"owner-{uuid.uuid4().hex[:8]}@example.com"),
    )
    return op_id


def _new_case(cur, case_dir: str) -> str:
    case_id = str(uuid.uuid4())
    cur.execute(
        "insert into app.cases(id, case_key, title, status, legacy_case_dir) "
        "values(%s, %s, 'CP2A seal test', 'active', %s)",
        (case_id, "cp2a-" + uuid.uuid4().hex, case_dir),
    )
    return case_id


def _make_evidence(tmp_path, names: list[str]):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir(exist_ok=True)
    for name in names:
        f = evidence_dir / name
        f.write_bytes(f"content of {name}\n".encode())
        os.chmod(f, 0o644)
    return evidence_dir


def _reconcile(cur, case_id: str, case_dir: str) -> int:
    from psycopg.types.json import Jsonb

    entries = classify_inventory_entries(case_dir)
    cur.execute(
        "select app.custody_reconcile(%s,%s,true,'refresh',null,null,null)",
        (case_id, Jsonb(entries or [])),
    )
    cur.execute(
        "select max(id) from app.admission_observations where case_id=%s", (case_id,)
    )
    return int(cur.fetchone()[0])


def _setup(cur, tmp_path, names: list[str]) -> tuple[str, str, int]:
    op_id = _new_operator(cur)
    _make_evidence(tmp_path, names)
    case_id = _new_case(cur, str(tmp_path))
    snapshot_id = _reconcile(cur, case_id, str(tmp_path))
    return case_id, op_id, snapshot_id


def _targets(names: list[str], snapshot_id: int) -> list[SealTarget]:
    return [SealTarget(f"evidence/{n}", snapshot_id) for n in names]


_ROCBA = ["Rocba-Memory.raw", "rocba-cdrive.e01"]


# ===========================================================================
# EC-6 — mixed-case multi-file seal (the permanent regression fixture)
# ===========================================================================
def test_ec6_mixed_case_rocba_seal_succeeds(monkeypatch, tmp_path) -> None:
    verifier = _Verifier()
    recorder = _install(monkeypatch, verifier)
    with _conn() as conn, conn.cursor() as cur:
        case_id, op_id, snap = _setup(cur, tmp_path, _ROCBA)
        conn.commit()
    session = _Session(op_id)
    targets = _targets(_ROCBA, snap)

    begun = begin_seal(
        session=session, case_id=case_id, password="pw",
        reason="seal the rocba set", idempotency_key="k1", targets=targets,
    )
    assert begun.phase == "REQUESTED"
    assert begun.staging_window_open is False  # fresh case, no window

    committed = commit_seal(
        session=session, case_id=case_id, idempotency_key="k1", targets=targets,
    )
    assert committed.phase == "COMMITTED"
    assert committed.gate_state == "OPEN"
    assert len(committed.sealed_object_ids) == 2
    # Happy-path single-shot: ONE password (verified at begin, consumed at commit).
    assert len(verifier.calls) == 1
    # D2: the evidence DIRECTORY itself is made immutable at COMMITTED — a fresh
    # case opens no window, so the only directory-fd call is the commit +i (True).
    assert recorder.dir_calls() == [True]

    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "select count(*) from app.evidence_objects where case_id=%s and status='sealed'",
            (case_id,),
        )
        assert cur.fetchone()[0] == 2
        cur.execute("select app.custody_gate_state(%s)", (case_id,))
        assert cur.fetchone()[0] == "OPEN"
        # The persisted reauth binding is the SQL-authoritative canonical form
        # (COLLATE "C" order), NOT a Python-built dict.
        cur.execute(
            "select details->'binding' from app.audit_events where id="
            "(select reauth_audit_event_id from app.custody_seal_operations "
            " where case_id=%s and idempotency_key='k1')",
            (case_id,),
        )
        stored = cur.fetchone()[0]
        assert stored["targets"] == ["evidence/Rocba-Memory.raw", "evidence/rocba-cdrive.e01"]
        conn.rollback()


def test_ec6_locale_sorted_binding_is_rejected(monkeypatch, tmp_path) -> None:
    """Fail-on-revert: a locale-sorted (lowercase-first) binding must be denied."""
    import psycopg
    from psycopg.types.json import Jsonb

    _install(monkeypatch, _Verifier())
    with _conn() as conn, conn.cursor() as cur:
        case_id, op_id, _snap = _setup(cur, tmp_path, _ROCBA)
        # A reauth event whose binding targets are in LOCALE order (lowercase
        # 'rocba-*' before 'Rocba-*') — what the as-built Python writer produced.
        cur.execute(
            """
            insert into app.audit_events
              (case_id, event_type, actor_type, actor_user_id, source, status, details)
            values (%s, 'reauth.evidence_seal', 'user', %s, 'portal_reauth', 'success',
                    jsonb_build_object('binding', jsonb_build_object(
                      'idempotency_key', 'kx', 'reason', 'r',
                      'targets', %s)))
            returning id::text
            """,
            (case_id, op_id, Jsonb(["evidence/rocba-cdrive.e01", "evidence/Rocba-Memory.raw"])),
        )
        bad_reauth = cur.fetchone()[0]
        conn.commit()

        digest = "sha256:" + "0" * 64
        with pytest.raises(psycopg.Error) as exc:
            cur.execute(
                "select app.custody_seal_begin(%s,'kx',%s,'r',%s,%s,%s,false,null)",
                (
                    case_id, digest, bad_reauth,
                    # The RPC recomputes COLLATE "C" order (Rocba-* first) -> mismatch.
                    Jsonb(["evidence/Rocba-Memory.raw", "evidence/rocba-cdrive.e01"]),
                    op_id,
                ),
            )
        assert "seal_reauth_scope_mismatch" in str(exc.value)
        conn.rollback()


# ===========================================================================
# Verifier seam — fail-closed (operator constraint 4)
# ===========================================================================
def test_verifier_unset_records_nothing(monkeypatch, tmp_path) -> None:
    _install(monkeypatch, None)  # UNSET verifier -> fail closed
    with _conn() as conn, conn.cursor() as cur:
        case_id, op_id, snap = _setup(cur, tmp_path, _ROCBA)
        conn.commit()
    with pytest.raises(reauth.ReauthError) as exc:
        begin_seal(
            session=_Session(op_id), case_id=case_id, password="pw",
            reason="seal", idempotency_key="k1", targets=_targets(_ROCBA, snap),
        )
    assert exc.value.reason == "reauth_unavailable"
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "select count(*) from app.audit_events where case_id=%s and source='portal_reauth'",
            (case_id,),
        )
        assert cur.fetchone()[0] == 0  # nothing recorded
        cur.execute(
            "select count(*) from app.custody_seal_operations where case_id=%s", (case_id,)
        )
        assert cur.fetchone()[0] == 0
        conn.rollback()


def test_verifier_wrong_password_records_nothing(monkeypatch, tmp_path) -> None:
    _install(monkeypatch, _Verifier(reject=True))  # wrong password -> raises
    with _conn() as conn, conn.cursor() as cur:
        case_id, op_id, snap = _setup(cur, tmp_path, _ROCBA)
        conn.commit()
    with pytest.raises(reauth.ReauthError) as exc:
        begin_seal(
            session=_Session(op_id), case_id=case_id, password="wrong",
            reason="seal", idempotency_key="k1", targets=_targets(_ROCBA, snap),
        )
    assert exc.value.reason == "reauth_failed"
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "select count(*) from app.audit_events where case_id=%s and source='portal_reauth'",
            (case_id,),
        )
        assert cur.fetchone()[0] == 0
        conn.rollback()


# ===========================================================================
# §4 retry semantics + one active Seal per case
# ===========================================================================
def test_same_key_resume_returns_pointer(monkeypatch, tmp_path) -> None:
    _install(monkeypatch, _Verifier())
    with _conn() as conn, conn.cursor() as cur:
        case_id, op_id, snap = _setup(cur, tmp_path, _ROCBA)
        conn.commit()
    session, targets = _Session(op_id), _targets(_ROCBA, snap)
    first = begin_seal(
        session=session, case_id=case_id, password="pw", reason="seal",
        idempotency_key="k1", targets=targets,
    )
    again = begin_seal(
        session=session, case_id=case_id, password="pw", reason="seal",
        idempotency_key="k1", targets=targets,
    )
    assert first.operation_id == again.operation_id  # resume pointer, no duplicate
    status = seal_status(case_id=case_id, dsn=_dsn())
    assert status.incomplete_operation_id == first.operation_id
    assert status.incomplete_idempotency_key == "k1"


def test_committed_replay_returns_recorded_success(monkeypatch, tmp_path) -> None:
    _install(monkeypatch, _Verifier())
    with _conn() as conn, conn.cursor() as cur:
        case_id, op_id, snap = _setup(cur, tmp_path, _ROCBA)
        conn.commit()
    session, targets = _Session(op_id), _targets(_ROCBA, snap)
    begin_seal(
        session=session, case_id=case_id, password="pw", reason="seal",
        idempotency_key="k1", targets=targets,
    )
    first = commit_seal(session=session, case_id=case_id, idempotency_key="k1", targets=targets)
    replay = commit_seal(session=session, case_id=case_id, idempotency_key="k1", targets=targets)
    assert replay.phase == "COMMITTED"
    assert replay.manifest_version == first.manifest_version
    assert replay.gate_state == "OPEN"
    with _conn() as conn, conn.cursor() as cur:
        cur.execute("select count(*) from app.manifest_versions where case_id=%s", (case_id,))
        assert cur.fetchone()[0] == 1  # exactly one manifest transition
        conn.rollback()


def test_different_key_while_incomplete_rejected(monkeypatch, tmp_path) -> None:
    import psycopg

    _install(monkeypatch, _Verifier())
    with _conn() as conn, conn.cursor() as cur:
        case_id, op_id, snap = _setup(cur, tmp_path, _ROCBA)
        conn.commit()
    session, targets = _Session(op_id), _targets(_ROCBA, snap)
    begin_seal(
        session=session, case_id=case_id, password="pw", reason="seal",
        idempotency_key="k1", targets=targets,
    )
    # A different idempotency key while k1 is incomplete violates one-active-Seal.
    with pytest.raises(psycopg.Error):
        begin_seal(
            session=session, case_id=case_id, password="pw", reason="seal",
            idempotency_key="k2", targets=targets,
        )


# ===========================================================================
# Conditional reauth — happy path vs resume
# ===========================================================================
def test_resume_commit_demands_fresh_reauth(monkeypatch, tmp_path) -> None:
    verifier = _Verifier()
    _install(monkeypatch, verifier)
    with _conn() as conn, conn.cursor() as cur:
        case_id, op_id, snap = _setup(cur, tmp_path, _ROCBA)
        conn.commit()
    session, targets = _Session(op_id), _targets(_ROCBA, snap)
    begin_seal(
        session=session, case_id=case_id, password="pw", reason="seal",
        idempotency_key="k1", targets=targets,
    )
    # resume=True without a password fails closed.
    with pytest.raises(seal.SealError) as exc:
        commit_seal(
            session=session, case_id=case_id, idempotency_key="k1",
            targets=targets, resume=True,
        )
    assert exc.value.reason == "reauth_required"
    # resume=True WITH a fresh password verifies again and commits.
    committed = commit_seal(
        session=session, case_id=case_id, idempotency_key="k1", targets=targets,
        password="pw", reason="resume", resume=True,
    )
    assert committed.phase == "COMMITTED"
    assert len(verifier.calls) == 2  # begin + resume commit


# ===========================================================================
# Snapshot TOCTOU
# ===========================================================================
def test_snapshot_toctou_stale_rejected(monkeypatch, tmp_path) -> None:
    _install(monkeypatch, _Verifier())
    with _conn() as conn, conn.cursor() as cur:
        case_id, op_id, snap = _setup(cur, tmp_path, _ROCBA)
        conn.commit()
    session, targets = _Session(op_id), _targets(_ROCBA, snap)
    begin_seal(
        session=session, case_id=case_id, password="pw", reason="seal",
        idempotency_key="k1", targets=targets,
    )
    # A newer Refresh supersedes the selected snapshot before commit.
    with _conn() as conn, conn.cursor() as cur:
        _reconcile(cur, case_id, str(tmp_path))
        conn.commit()
    with pytest.raises(seal.SealError) as exc:
        commit_seal(session=session, case_id=case_id, idempotency_key="k1", targets=targets)
    assert exc.value.reason == "seal_snapshot_stale"


# ===========================================================================
# D2 staging window (add evidence to a sealed case)
# ===========================================================================
def test_d2_staging_window_on_sealed_case(monkeypatch, tmp_path) -> None:
    verifier = _Verifier()
    recorder = _install(monkeypatch, verifier)
    with _conn() as conn, conn.cursor() as cur:
        case_id, op_id, snap = _setup(cur, tmp_path, _ROCBA)
        conn.commit()
    session = _Session(op_id)
    # First seal (fresh case): no window; the directory is made immutable at commit.
    begin_seal(
        session=session, case_id=case_id, password="pw", reason="seal",
        idempotency_key="k1", targets=_targets(_ROCBA, snap),
    )
    commit_seal(session=session, case_id=case_id, idempotency_key="k1", targets=_targets(_ROCBA, snap))
    assert recorder.dir_calls() == [True]  # directory +i at the first COMMITTED

    # SPEC scenario 12 order: the window OPENS FIRST (begin to ADD a new file the
    # operator has not staged yet), which lifts the directory immutable flag; only
    # THEN is the file staged. The extra file does NOT exist on disk at begin_seal.
    add_targets = _targets(["extra-image.e01"], snap)
    begun = begin_seal(
        session=session, case_id=case_id, password="pw", reason="add evidence",
        idempotency_key="k2", targets=add_targets,
    )
    assert begun.staging_window_open is True  # server-derived: committed set exists
    # D2: the directory immutable flag was LIFTED (False) when the window opened.
    assert recorder.dir_calls() == [True, False]
    with _conn() as conn, conn.cursor() as cur:
        cur.execute("select app.custody_gate_state(%s)", (case_id,))
        assert cur.fetchone()[0] != "OPEN"  # gate blocked during the window
        cur.execute(
            "select count(*) from app.evidence_custody_events "
            "where case_id=%s and event_type='SEAL_WINDOW_OPENED'",
            (case_id,),
        )
        assert cur.fetchone()[0] == 1
        conn.rollback()

    # NOW stage the new file inside the open window and Refresh (post-window snapshot).
    _make_evidence(tmp_path, ["extra-image.e01"])
    with _conn() as conn, conn.cursor() as cur:
        snap2 = _reconcile(cur, case_id, str(tmp_path))
        conn.commit()
    commit_targets = _targets(["extra-image.e01"], snap2)

    # Closing the window (a staging-window commit) demands a fresh reauth and
    # re-applies the directory immutable flag.
    committed = commit_seal(
        session=session, case_id=case_id, idempotency_key="k2", targets=commit_targets,
        password="pw", reason="add evidence",
    )
    assert committed.phase == "COMMITTED"
    # D2: directory immutability RE-APPLIED (True) at the window re-commit.
    assert recorder.dir_calls() == [True, False, True]
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "select count(*) from app.evidence_custody_events "
            "where case_id=%s and event_type='SEAL_WINDOW_CLOSED'",
            (case_id,),
        )
        assert cur.fetchone()[0] == 1
        cur.execute(
            "select count(*) from app.evidence_objects where case_id=%s and status='sealed'",
            (case_id,),
        )
        assert cur.fetchone()[0] == 3  # rocba x2 + extra
        conn.rollback()


# ===========================================================================
# EC-2 — a failed DB-only action leaves no block; a later action succeeds
# ===========================================================================
def test_ec2_failed_action_then_new_action_succeeds(monkeypatch, tmp_path) -> None:
    import psycopg

    _install(monkeypatch, _Verifier())
    # A sealed case plus a spare pending file to Ignore.
    with _conn() as conn, conn.cursor() as cur:
        case_id, op_id, snap = _setup(cur, tmp_path, _ROCBA)
        conn.commit()
    session = _Session(op_id)
    begin_seal(
        session=session, case_id=case_id, password="pw", reason="seal",
        idempotency_key="k1", targets=_targets(_ROCBA, snap),
    )
    commit_seal(session=session, case_id=case_id, idempotency_key="k1", targets=_targets(_ROCBA, snap))

    # Add a pending file and Refresh.
    _make_evidence(tmp_path, ["stray.txt"])
    with _conn() as conn, conn.cursor() as cur:
        _reconcile(cur, case_id, str(tmp_path))
        conn.commit()

    # A failing action: Retire a non-existent object -> the RPC raises and the
    # verb's single transaction rolls back, recording no receipt/manifest/block.
    with pytest.raises(psycopg.Error):
        resolve(
            session=session, case_id=case_id, password="pw", reason="retire",
            dispositions=[FindingDisposition(verb="RETIRE", target=str(uuid.uuid4()))],
            batch_key="bkfail",
        )

    # A NEW action on the SAME case still succeeds (no permanent block — EC-2).
    receipts = resolve(
        session=session, case_id=case_id, password="pw", reason="ignore the stray",
        dispositions=[FindingDisposition(verb="IGNORE", target="evidence/stray.txt")],
        batch_key="bkok",
    )
    assert len(receipts) == 1
    assert receipts[0].action == "IGNORE"
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "select disposition from app.evidence_inventory "
            "where case_id=%s and display_path='evidence/stray.txt'",
            (case_id,),
        )
        assert cur.fetchone()[0] == "ignored"
        conn.rollback()


# ===========================================================================
# EC-2b — DB-only action overlapping an active Seal's target set is rejected;
# a disjoint target proceeds (SPEC Custody Lifecycle scenario 11)
# ===========================================================================
def test_ec2b_overlap_rejected_disjoint_permitted(monkeypatch, tmp_path) -> None:
    _install(monkeypatch, _Verifier())
    with _conn() as conn, conn.cursor() as cur:
        case_id, op_id, snap = _setup(cur, tmp_path, ["stray-a.txt", "stray-b.txt"])
        conn.commit()
    session = _Session(op_id)
    # An ACTIVE (non-committed) Seal whose target set is exactly {evidence/stray-a.txt}.
    begin_seal(
        session=session, case_id=case_id, password="pw", reason="seal a",
        idempotency_key="ks", targets=_targets(["stray-a.txt"], snap),
    )

    # EC-2b: a DB-only action whose target is INSIDE the active Seal's set is
    # rejected shaped before any mutation.
    with pytest.raises(ActionError) as exc:
        resolve(
            session=session, case_id=case_id, password="pw", reason="ignore a",
            dispositions=[FindingDisposition(verb="IGNORE", target="evidence/stray-a.txt")],
            batch_key="bk-overlap",
        )
    assert exc.value.reason == "seal_in_progress"

    # EC-2b: the same action on a DISJOINT target proceeds during the active Seal.
    receipts = resolve(
        session=session, case_id=case_id, password="pw", reason="ignore b",
        dispositions=[FindingDisposition(verb="IGNORE", target="evidence/stray-b.txt")],
        batch_key="bk-disjoint",
    )
    assert len(receipts) == 1 and receipts[0].action == "IGNORE"
    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "select disposition from app.evidence_inventory "
            "where case_id=%s and display_path='evidence/stray-b.txt'",
            (case_id,),
        )
        assert cur.fetchone()[0] == "ignored"  # disjoint action took effect
        cur.execute(
            "select disposition from app.evidence_inventory "
            "where case_id=%s and display_path='evidence/stray-a.txt'",
            (case_id,),
        )
        assert cur.fetchone()[0] == "pending"  # overlapping action was rejected
        conn.rollback()


# ===========================================================================
# PF-010 — real-SQL reauth INSERT type soundness (fail-on-revert)
# ===========================================================================
def test_pf010_reauth_event_insert_persists_canonical_binding(monkeypatch, tmp_path) -> None:
    """Fail-on-revert at the REAL SQL seam: record_reauth -> _insert_reauth_event
    persists ONE bound portal_reauth event. Before the ``::text`` casts on the
    ``jsonb_build_object`` (VARIADIC "any") ``action``/``examiner`` params, this
    INSERT raised ``psycopg.errors.IndeterminateDatatype`` ("could not determine
    data type of parameter") for EVERY caller. Mixed-case targets additionally lock
    the EC-6 canonical (COLLATE "C") binding. This drives the PRODUCTION INSERT (not
    a raw-SQL/mock that would bypass the parameter-inference bug)."""
    from psycopg.types.json import Jsonb

    _install(monkeypatch, _Verifier())  # verifier accepts the operator password
    with _conn() as conn, conn.cursor() as cur:
        op_id = _new_operator(cur)
        case_id = _new_case(cur, str(tmp_path))
        conn.commit()
    session = _Session(op_id)
    binding = reauth.ReauthBinding(
        idempotency_key="pf010-k1",
        reason="seal the rocba set",
        targets=("evidence/Rocba-Memory.raw", "evidence/rocba-cdrive.e01"),
    )

    # Would raise IndeterminateDatatype on the un-cast INSERT (the live blocker).
    event_id = reauth.record_reauth(
        session=session, password="pw", action="ADD_SEAL",
        case_id=case_id, binding=binding,
    )
    assert event_id

    with _conn() as conn, conn.cursor() as cur:
        cur.execute(
            "select event_type, details->>'action', details->>'examiner', "
            "       details->'binding', "
            "       details->'binding' is not distinct from "
            "         app.custody_reauth_binding(%s, %s, %s) "
            "from app.audit_events where id = %s",
            ("pf010-k1", "seal the rocba set", Jsonb(list(binding.targets)), event_id),
        )
        row = cur.fetchone()
        conn.rollback()
    assert row is not None
    event_type, action, examiner, stored_binding, binding_matches = row
    assert event_type == "reauth.evidence_seal"
    assert action == "evidence_seal"
    assert examiner and "@" in examiner  # the SESSION-resolved operator email
    # EC-6: the persisted binding IS the SQL-authoritative canonical form.
    assert binding_matches is True
    assert stored_binding["targets"] == [
        "evidence/Rocba-Memory.raw", "evidence/rocba-cdrive.e01"
    ]

    # The idempotency SELECT path (same key + identical binding/action/examiner)
    # returns the SAME event — proving that comparison branch is type-sound too.
    again = reauth.record_reauth(
        session=session, password="pw", action="ADD_SEAL",
        case_id=case_id, binding=binding,
    )
    assert again == event_id
