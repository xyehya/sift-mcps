from __future__ import annotations

import os
import subprocess
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from sift_gateway.active_case import ActiveCase
from sift_gateway.identity import Identity
from sift_gateway.portal_services import (
    EvidenceAuthorityService,
)


class _CaseService:
    def __init__(self, case):
        self.case = case

    def require_active_case_for_principal(self, _principal):
        return self.case


class _AdmissionService:
    def __init__(self, *, reject=False, case_dir=None, known=(), unavailable=False):
        self.reject = reject
        self.case_dir = case_dir
        self.reconciled = []
        self.resolved = []
        self.observations = []
        self.known = set(known)
        self.unavailable = unavailable
        self.execution_lock_held = False
        self.execution_authority = {
            "storage_profile": "LOCAL_IMMUTABLE",
            "storage_source_identity": "",
            "mount_instance_identity": "",
            "storage_generation": 1,
            "storage_verified_generation": 1,
            "storage_manifest_version": 1,
            "storage_manifest_hash": "sha256:manifest",
            "storage_verification_receipt_id": "receipt-1",
        }

    def reconcile_for_admission(self, case_id):
        self.reconciled.append(case_id)
        if self.case_dir is not None:
            self.observations = [
                f"evidence/{entry.name}"
                for entry in os.scandir(self.case_dir / "evidence")
                if f"evidence/{entry.name}" not in self.known
            ]
        if self.unavailable:
            return {
                "state": "unavailable",
                "observed": 0,
                "issues": ["evidence_storage_unavailable"],
            }
        return {
            "state": "available",
            "observed": len(self.observations),
            "issues": [],
            "execution_authority": dict(self.execution_authority),
        }

    def revalidate_execution_authority(self, _case_id, expected):
        if expected != self.execution_authority:
            raise RuntimeError("authority changed")
        return dict(self.execution_authority)

    @contextmanager
    def hold_execution_authority(self, case_id, expected):
        self.revalidate_execution_authority(case_id, expected)
        self.execution_lock_held = True
        try:
            yield
        finally:
            self.execution_lock_held = False

    def attempt_storage_transition(self):
        if self.execution_lock_held:
            return False
        self.execution_authority["storage_generation"] += 1
        return True

    def resolve_evidence_reference(self, case_id, ref):
        self.resolved.append((case_id, ref))
        if self.reject or (self.known and ref not in self.known):
            raise RuntimeError("not sealed")
        return {
            "evidence_id": "11111111-1111-1111-1111-111111111112",
            "version_id": "11111111-1111-1111-1111-111111111113",
            "display_path": ref,
            "path": "/case/evidence/sealed.E01",
            "sha256": "sha256:" + "a" * 64,
            "bytes": 1,
            "st_dev": 1,
            "st_ino": 2,
            "st_mtime_ns": 3,
            **self.execution_authority,
        }


def _gateway(tmp_path, service):
    case = ActiveCase(
        case_id="11111111-1111-1111-1111-111111111111",
        case_key="case-one",
        title="Case One",
        description=None,
        status="active",
        artifact_path=str(tmp_path),
        metadata={},
        membership_role="agent",
    )
    gateway = MagicMock()
    gateway.control_plane_dsn = "postgresql://service@db/sift"
    gateway.active_case_service = _CaseService(case)
    gateway.evidence_service = service
    gateway._tool_map = {}
    gateway._audit.log.return_value = "audit-1"
    return gateway


@pytest.mark.asyncio
async def test_authenticated_catalog_has_no_custody_mutation_tools(tmp_path):
    from sift_gateway.mcp_server import create_gateway_mcp_server

    (tmp_path / "evidence").mkdir()
    token = "test-agent-token"
    mcp = create_gateway_mcp_server(
        _gateway(tmp_path, _AdmissionService()),
        api_keys={token: {"examiner": "agent", "role": "agent"}},
    )
    identity = Identity(
        principal="agent",
        principal_type="agent",
        token_id="token-1",
        agent_id="agent-1",
        created_by=None,
        role="agent",
        source_ip="127.0.0.1",
        auth_surface="mcp",
        tool_scopes=frozenset({"mcp:*"}),
        token_fingerprint="fingerprint",
        principal_id="agent-1",
        auth_user_id="auth-agent-1",
    )
    with patch(
        "sift_gateway.policy_middleware.current_mcp_identity", return_value=identity
    ):
        names = {tool.name for tool in await mcp.list_tools()}
    forbidden = {
        "evidence_prepare",
        "evidence_rescan",
        "evidence_register",
        "evidence_seal",
        "evidence_unseal",
        "evidence_replace",
        "evidence_reacquire",
        "evidence_ignore",
        "evidence_delete",
        "evidence_retire",
        "evidence_restore",
        "evidence_verify",
        "evidence_sign",
        "evidence_purge",
    }
    assert names.isdisjoint(forbidden)


def test_execution_authority_guard_holds_shared_case_lock_through_dispatch(
    monkeypatch,
):
    calls = []

    class Cursor:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, query, params):
            calls.append(("sql", " ".join(query.split()), params))

    class Connection:
        def __enter__(self):
            calls.append(("connection", "enter"))
            return self

        def __exit__(self, *_args):
            calls.append(("connection", "exit"))
            return None

        def cursor(self):
            return Cursor()

    service = EvidenceAuthorityService("postgresql://unused")
    monkeypatch.setattr(service, "_connect", lambda: Connection())
    monkeypatch.setattr(
        service,
        "revalidate_execution_authority",
        lambda case_id, expected: calls.append(("revalidate", case_id, dict(expected))),
    )
    expected = {"storage_generation": 7}

    with service.hold_execution_authority("case-1", expected):
        calls.append(("process", "start"))

    lock_index = next(
        index
        for index, call in enumerate(calls)
        if call[0] == "sql" and "pg_advisory_xact_lock_shared" in call[1]
    )
    revalidate_index = next(
        index for index, call in enumerate(calls) if call[0] == "revalidate"
    )
    process_index = calls.index(("process", "start"))
    exit_index = calls.index(("connection", "exit"))
    assert lock_index < revalidate_index < process_index < exit_index


def test_final_process_reads_pinned_descriptor_after_path_replacement(tmp_path):
    from sift_core.execute.evidence_binding import (
        close_bound_evidence,
        open_bound_evidence,
        rewrite_bound_operands,
    )

    target = tmp_path / "sealed.raw"
    target.write_bytes(b"admitted")
    st = target.stat()
    binding = {
        "path": str(target),
        "bytes": st.st_size,
        "st_dev": st.st_dev,
        "st_ino": st.st_ino,
        "st_mtime_ns": st.st_mtime_ns,
        "st_ctime_ns": st.st_ctime_ns,
        "immutable_required": False,
    }
    opened = open_bound_evidence([binding])
    replacement = tmp_path / "replacement.raw"
    replacement.write_bytes(b"replacement")
    os.replace(replacement, target)
    argv, _ = rewrite_bound_operands(
        ["cat", str(target)], [], opened, cwd=str(tmp_path)
    )
    try:
        result = subprocess.run(
            argv, check=True, capture_output=True, pass_fds=tuple(opened.values())
        )
    finally:
        close_bound_evidence(opened)
    assert result.stdout == b"admitted"
    assert target.read_bytes() == b"replacement"


def test_linux_final_binding_uses_proc_self_fd(tmp_path, monkeypatch):
    from sift_core.execute.evidence_binding import rewrite_bound_operands

    target = tmp_path / "sealed.raw"
    target.write_bytes(b"sealed")
    original_is_dir = type(target).is_dir

    def is_dir(path):
        if str(path) == "/proc/self/fd":
            return True
        return original_is_dir(path)

    monkeypatch.setattr(type(target), "is_dir", is_dir)
    argv, _ = rewrite_bound_operands(
        ["cat", str(target)], [], {str(target.resolve()): 19}, cwd=str(tmp_path)
    )
    assert argv[1] == "/proc/self/fd/19"


def test_normalized_non_symlink_spelling_still_rewrites_to_pinned_fd(tmp_path):
    from sift_core.execute.evidence_binding import rewrite_bound_operands

    target = tmp_path / "evidence" / "sealed.raw"
    target.parent.mkdir()
    target.write_bytes(b"sealed")
    argv, _ = rewrite_bound_operands(
        ["cat", "evidence/../evidence/sealed.raw"],
        [],
        {str(target): 23},
        cwd=str(tmp_path),
    )
    assert argv[1].endswith("/fd/23")

