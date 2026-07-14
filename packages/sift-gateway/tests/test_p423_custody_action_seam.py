from __future__ import annotations

from typing import Any, cast, get_type_hints

import pytest
from sift_gateway.custody_operations import (
    AuthorizedRecoveryIntent,
    CustodyAction,
    CustodyOperationCommandProtocol,
    CustodyOperationError,
    CustodyOperationRepository,
    ObjectCustodyCommand,
    RecoveryAction,
    RecoveryAuthorityProtocol,
    RecoverySelection,
    SealCommand,
)


class _Cursor:
    def __init__(self) -> None:
        self.sql = ""
        self.params: tuple[Any, ...] = ()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def execute(self, sql: str, params: tuple[Any, ...]) -> None:
        self.sql = sql
        self.params = params

    def fetchone(self):
        storage_v3 = "begin_or_resume_storage_v3" in self.sql
        return (
            "33333333-3333-3333-3333-333333333333",
            "11111111-1111-1111-1111-111111111111",
            "ADD_SEAL" if storage_v3 else self.params[1],
            "GATE_BLOCKED",
            self.params[5] if storage_v3 else self.params[6],
            self.params[2] if storage_v3 else self.params[3],
            None,
            None,
            None,
            self.params[7] if storage_v3 else self.params[9],
            {},
            {},
        )


class _Connection:
    def __init__(self) -> None:
        self.cursor_instance = _Cursor()
        self.committed = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def cursor(self):
        return self.cursor_instance

    def commit(self) -> None:
        self.committed = True


def _seal_command() -> SealCommand:
    return SealCommand(
        case_id="11111111-1111-1111-1111-111111111111",
        file_specs=({"path": "evidence/disk.raw"},),
        actor_user_id="55555555-5555-5555-5555-555555555555",
        actor_service_identity_id=None,
        reason="initial intake",
        reauth_audit_event_id="22222222-2222-2222-2222-222222222222",
        idempotency_key="seal-1",
        runner_instance_id="runner-1",
    )


def _object_command(action: CustodyAction) -> ObjectCustodyCommand:
    return ObjectCustodyCommand(
        case_id="11111111-1111-1111-1111-111111111111",
        actor_user_id="55555555-5555-5555-5555-555555555555",
        actor_service_identity_id=None,
        reason="operator recovery",
        reauth_audit_event_id="22222222-2222-2222-2222-222222222222",
        idempotency_key="recovery-1",
        runner_instance_id="runner-1",
        resume_reauth_audit_event_id=None,
        action=action,
        evidence_object_id="44444444-4444-4444-4444-444444444444",
    )


def _json_value(value: Any) -> Any:
    return getattr(value, "obj", value)


def test_add_seal_uses_storage_bound_v3_rpc_and_payload_contract():
    conn = _Connection()
    record = CustodyOperationRepository(lambda: conn).begin_or_resume(_seal_command())

    assert (
        "app.custody_operation_begin_or_resume_storage_v3(" in conn.cursor_instance.sql
    )
    payload = _json_value(conn.cursor_instance.params[1])
    assert payload["action"] == "ADD_SEAL"
    assert payload["schema_version"] == 3
    assert payload["storage_profile"] == "LOCAL_IMMUTABLE"
    assert record.action == "ADD_SEAL"
    assert conn.committed is True


def test_stored_v1_local_seal_resume_keeps_legacy_rpc_compatibility():
    conn = _Connection()
    command = _seal_command()
    object.__setattr__(command, "schema_version", 1)
    record = CustodyOperationRepository(lambda: conn).begin_or_resume(command)
    assert "app.custody_operation_begin_or_resume(" in conn.cursor_instance.sql
    assert _json_value(conn.cursor_instance.params[2])["schema_version"] == 1
    assert "storage_profile" not in _json_value(conn.cursor_instance.params[2])
    assert record.action == "ADD_SEAL"


@pytest.mark.parametrize("action", tuple(CustodyAction)[1:])
def test_later_actions_use_the_closed_cumulative_rpc(action: CustodyAction):
    conn = _Connection()
    command = _object_command(action)

    record = CustodyOperationRepository(lambda: conn).begin_or_resume(command)

    assert "app.custody_operation_begin_or_resume(" in conn.cursor_instance.sql
    assert conn.cursor_instance.params[1] == action.value
    assert _json_value(conn.cursor_instance.params[2]) == command.operation_payload()
    assert record.action == action.value


def test_unknown_action_is_rejected_before_database_access():
    connected = False

    def connect():
        nonlocal connected
        connected = True
        return _Connection()

    command = cast(
        CustodyOperationCommandProtocol, _object_command(CustodyAction.RETIRE)
    )
    object.__setattr__(command, "action", "CUSTOM_SQL")

    with pytest.raises(CustodyOperationError) as exc:
        CustodyOperationRepository(connect).begin_or_resume(command)

    assert exc.value.reason == "custody_action_unknown"
    assert connected is False


def test_add_seal_cannot_use_the_object_command_shape():
    with pytest.raises(ValueError, match="SealCommand"):
        _object_command(CustodyAction.ADD_SEAL)


def test_ticket4_recovery_seam_contains_only_opaque_object_selection():
    selection = RecoverySelection(
        case_id="11111111-1111-1111-1111-111111111111",
        evidence_object_id="44444444-4444-4444-4444-444444444444",
        action=RecoveryAction.RESTORE_EXACT,
    )

    intent = AuthorizedRecoveryIntent(
        selection=selection,
        actor_user_id="55555555-5555-5555-5555-555555555555",
        reason="  exact-byte recovery  ",
        reauth_audit_event_id="22222222-2222-2222-2222-222222222222",
        idempotency_key="restore-1",
    )

    assert set(vars(selection)) == {"case_id", "evidence_object_id", "action"}
    assert set(vars(intent)) == {
        "selection",
        "actor_user_id",
        "reason",
        "reauth_audit_event_id",
        "idempotency_key",
    }
    assert intent.reason == "exact-byte recovery"
    forbidden = ("path", "password", "receipt", "command")
    assert not any(term in name for name in vars(intent) for term in forbidden)
    annotations = get_type_hints(RecoveryAuthorityProtocol.execute_authorized_recovery)
    assert annotations["intent"] is AuthorizedRecoveryIntent


@pytest.mark.parametrize("reason", ["", "   ", "x" * 1001])
def test_authorized_recovery_intent_bounds_reason(reason: str):
    with pytest.raises(ValueError, match="reason"):
        AuthorizedRecoveryIntent(
            selection=RecoverySelection(
                case_id="11111111-1111-1111-1111-111111111111",
                evidence_object_id="44444444-4444-4444-4444-444444444444",
                action=RecoveryAction.REPLACE_REACQUIRE,
            ),
            actor_user_id="55555555-5555-5555-5555-555555555555",
            reason=reason,
            reauth_audit_event_id="22222222-2222-2222-2222-222222222222",
            idempotency_key="replace-1",
        )
