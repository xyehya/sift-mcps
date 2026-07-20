from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastmcp import FastMCP
from sift_core.active_case_context import ActiveCaseContext, use_active_case_context
from sift_core.custody_types import ChainStatus
from sift_gateway.active_case import ActiveCase
from sift_gateway.identity import Identity
from sift_gateway.policy_middleware import gateway_policy_middlewares
from sift_gateway.portal_services import (
    EvidenceAuthorityService,
    PortalServiceError,
)


def _tree_snapshot(root, target):
    st = target.stat(follow_symlinks=False)
    inode_flags = getattr(st, "st_flags", None)
    if sys.platform.startswith("linux"):
        import ctypes
        import fcntl

        value = ctypes.c_int(0)
        fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            fcntl.ioctl(fd, 0x80086601, value)
            inode_flags = value.value
        finally:
            os.close(fd)
    if hasattr(os, "listxattr") and hasattr(os, "getxattr"):
        xattrs = {
            name: os.getxattr(target, name, follow_symlinks=False)
            for name in os.listxattr(target, follow_symlinks=False)
        }
    else:
        xattrs = subprocess.run(
            ["/usr/bin/xattr", "-l", str(target)],
            check=False,
            capture_output=True,
        ).stdout
    return {
        "names": sorted(path.relative_to(root).as_posix() for path in root.rglob("*")),
        "bytes": target.read_bytes(),
        "uid": st.st_uid,
        "gid": st.st_gid,
        "mode": st.st_mode,
        "flags": inode_flags,
        "nlink": st.st_nlink,
        "xattrs": xattrs,
    }


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
@pytest.mark.skip(
    reason="P4.23 CP1: external-storage admission E2E re-homed by CP2A/CP2B; CP1 "
    "gate-denial routing covered by test_cp1_admission.py + the CP3 VM gate"
)
async def test_force_added_file_reconciles_and_denies_before_tool(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    planted = evidence / "force-added.bin"
    planted.write_bytes(b"secret bytes")
    before = _tree_snapshot(tmp_path, planted)
    service = _AdmissionService(case_dir=tmp_path)
    gateway = _gateway(tmp_path, service)
    mcp = FastMCP("aggregate", middleware=gateway_policy_middlewares(gateway))
    ran = False

    @mcp.tool(name="run_command")
    async def run_command(command: str):
        nonlocal ran
        ran = True
        return command

    def observed_gate(*_args):
        return {
            "blocked": bool(service.observations),
            "status": ChainStatus.UNSEALED if service.observations else ChainStatus.OK,
            "issues": ["Pending inventory observation"] if service.observations else [],
            "manifest_version": 1,
        }

    with (
        patch(
            "sift_gateway.policy_middleware.check_evidence_gate_db",
            side_effect=observed_gate,
        ),
        patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=None),
    ):
        result = await mcp.call_tool(
            "run_command", {"command": "sha256sum evidence/force-added.bin"}
        )

    assert ran is False
    assert service.reconciled == [gateway.active_case_service.case.case_id]
    assert service.observations == ["evidence/force-added.bin"]
    assert "secret bytes" not in json.dumps(result.model_dump(mode="json"), default=str)
    assert _tree_snapshot(tmp_path, planted) == before


@pytest.mark.asyncio
@pytest.mark.skip(
    reason="P4.23 CP1: external-storage admission E2E re-homed by CP2A/CP2B; CP1 "
    "gate-denial routing covered by test_cp1_admission.py + the CP3 VM gate"
)
async def test_stale_open_gate_cannot_authorize_raw_unregistered_operand(tmp_path):
    (tmp_path / "evidence").mkdir()
    service = _AdmissionService(reject=True)
    gateway = _gateway(tmp_path, service)
    mcp = FastMCP("aggregate", middleware=gateway_policy_middlewares(gateway))
    ran = False

    @mcp.tool(name="run_command")
    async def run_command(command: str):
        nonlocal ran
        ran = True
        return command

    opened = {
        "blocked": False,
        "status": ChainStatus.OK,
        "issues": [],
        "manifest_version": 4,
    }
    with (
        patch(
            "sift_gateway.policy_middleware.check_evidence_gate_db", return_value=opened
        ),
        patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=None),
    ):
        result = await mcp.call_tool(
            "run_command", {"command": "cat evidence/unregistered.raw"}
        )

    assert ran is False
    assert service.resolved == [
        (gateway.active_case_service.case.case_id, "evidence/unregistered.raw")
    ]
    assert "active sealed version" in result.content[0].text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "command",
    [
        "echo changed > evidence/unregistered.raw",
        "cp evidence/unregistered.raw agent/copy.raw",
        "rm evidence/unregistered.raw",
        "mv evidence/unregistered.raw agent/moved.raw",
        "chmod 600 evidence/unregistered.raw",
        "chown root evidence/unregistered.raw",
        "chattr -i evidence/unregistered.raw",
        "setfattr -n user.test -v changed evidence/unregistered.raw",
        "ln evidence/unregistered.raw agent/linked.raw",
        "truncate -s 0 evidence/unregistered.raw",
    ],
)
@pytest.mark.skip(
    reason="P4.23 CP1: external-storage admission E2E re-homed by CP2A/CP2B; CP1 "
    "gate-denial routing covered by test_cp1_admission.py + the CP3 VM gate"
)
async def test_sync_mutation_operands_never_reach_tool_or_change_file(
    tmp_path, command
):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    target = evidence / "unregistered.raw"
    target.write_bytes(b"original")
    before = _tree_snapshot(tmp_path, target)
    service = _AdmissionService(reject=True)
    gateway = _gateway(tmp_path, service)
    mcp = FastMCP("aggregate", middleware=gateway_policy_middlewares(gateway))
    ran = False

    @mcp.tool(name="run_command")
    async def run_command(command: str):
        nonlocal ran
        ran = True
        return command

    opened = {
        "blocked": False,
        "status": ChainStatus.OK,
        "issues": [],
        "manifest_version": 4,
    }
    with (
        patch(
            "sift_gateway.policy_middleware.check_evidence_gate_db", return_value=opened
        ),
        patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=None),
    ):
        await mcp.call_tool("run_command", {"command": command})

    assert ran is False
    assert _tree_snapshot(tmp_path, target) == before


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


@pytest.mark.asyncio
@pytest.mark.skip(
    reason="P4.23 CP1: external-storage admission E2E re-homed by CP2A/CP2B; CP1 "
    "gate-denial routing covered by test_cp1_admission.py + the CP3 VM gate"
)
async def test_unavailable_inventory_blocks_without_mass_missing_violation(tmp_path):
    service = _AdmissionService(unavailable=True)
    gateway = _gateway(tmp_path, service)
    mcp = FastMCP("aggregate", middleware=gateway_policy_middlewares(gateway))
    ran = False

    @mcp.tool(name="run_command")
    async def run_command(command: str):
        nonlocal ran
        ran = True
        return command

    opened = {
        "blocked": False,
        "status": ChainStatus.OK,
        "issues": [],
        "manifest_version": 9,
    }
    with (
        patch(
            "sift_gateway.policy_middleware.check_evidence_gate_db", return_value=opened
        ),
        patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=None),
    ):
        result = await mcp.call_tool("run_command", {"command": "date"})

    assert ran is False
    assert "evidence_storage_unavailable" in result.content[0].text
    assert any(
        call.kwargs.get("source") == "gateway_evidence_gate"
        and call.kwargs.get("extra", {}).get("evidence_chain_status")
        == ChainStatus.LEDGER_ERROR
        for call in gateway._audit.log.mock_calls
    )


@pytest.mark.asyncio
@pytest.mark.skip(
    reason="P4.23 CP1: external-storage admission E2E re-homed by CP2A/CP2B; CP1 "
    "gate-denial routing covered by test_cp1_admission.py + the CP3 VM gate"
)
async def test_operator_recovery_allows_only_sealed_version_with_no_pending_sibling(
    tmp_path,
):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    sealed = evidence / "sealed.raw"
    sealed.write_bytes(b"sealed")
    sibling = evidence / "pending.raw"
    sibling.write_bytes(b"pending")
    service = _AdmissionService(case_dir=tmp_path, known={"evidence/sealed.raw"})
    gateway = _gateway(tmp_path, service)
    mcp = FastMCP("aggregate", middleware=gateway_policy_middlewares(gateway))
    calls = []

    @mcp.tool(name="run_command")
    async def run_command(command: str):
        calls.append(command)
        return "sealed-only"

    def gate(*_args):
        return {
            "blocked": bool(service.observations),
            "status": ChainStatus.UNSEALED if service.observations else ChainStatus.OK,
            "issues": ["pending"] if service.observations else [],
            "manifest_version": 2,
        }

    with (
        patch(
            "sift_gateway.policy_middleware.check_evidence_gate_db", side_effect=gate
        ),
        patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=None),
    ):
        blocked = await mcp.call_tool(
            "run_command", {"command": "cat evidence/sealed.raw"}
        )
        sibling.unlink()  # models operator disposition/Seal completing outside MCP
        allowed = await mcp.call_tool(
            "run_command", {"command": "cat evidence/sealed.raw"}
        )
        denied = await mcp.call_tool(
            "run_command", {"command": "cat evidence/pending.raw"}
        )

    assert blocked.is_error is True
    assert allowed.is_error is False
    assert calls == ["cat evidence/sealed.raw"]
    assert denied.is_error is True


@pytest.mark.asyncio
@pytest.mark.skip(
    reason="P4.23 CP1: external-storage admission E2E re-homed by CP2A/CP2B; CP1 "
    "gate-denial routing covered by test_cp1_admission.py + the CP3 VM gate"
)
async def test_storage_authorization_change_after_admission_denies_before_handler(
    tmp_path,
):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "sealed.raw").write_bytes(b"sealed")
    service = _AdmissionService(case_dir=tmp_path, known={"evidence/sealed.raw"})
    gateway = _gateway(tmp_path, service)
    mcp = FastMCP("aggregate", middleware=gateway_policy_middlewares(gateway))
    calls = []

    @mcp.tool(name="run_command")
    async def run_command(command: str):
        calls.append(command)
        return "must-not-run"

    def changed(_case_id, _expected):
        # Models profile/source authorization after the first reconcile while
        # file/source/mount fingerprint values themselves remain unchanged.
        service.execution_authority["storage_generation"] += 1
        raise RuntimeError("storage authorization changed")

    service.revalidate_execution_authority = changed
    opened = {
        "blocked": False,
        "status": ChainStatus.OK,
        "issues": [],
        "manifest_version": 2,
    }
    with (
        patch(
            "sift_gateway.policy_middleware.check_evidence_gate_db",
            return_value=opened,
        ),
        patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=None),
    ):
        result = await mcp.call_tool(
            "run_command", {"command": "cat evidence/sealed.raw"}
        )

    assert result.is_error is True
    assert calls == []


@pytest.mark.asyncio
@pytest.mark.skip(
    reason="P4.23 CP1: external-storage admission E2E re-homed by CP2A/CP2B; CP1 "
    "gate-denial routing covered by test_cp1_admission.py + the CP3 VM gate"
)
async def test_storage_transition_after_final_check_cannot_commit_before_process(
    tmp_path,
):
    from sift_core.execute.evidence_binding import validate_final_open_authority

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "sealed.raw").write_bytes(b"sealed")
    service = _AdmissionService(case_dir=tmp_path, known={"evidence/sealed.raw"})
    gateway = _gateway(tmp_path, service)
    mcp = FastMCP("aggregate", middleware=gateway_policy_middlewares(gateway))
    process_starts = []
    transition_commits = []

    @mcp.tool(name="run_command")
    async def run_command(command: str):
        del command
        expected = dict(service.execution_authority)
        # Final DB validation succeeds under the shared execution lease. The
        # authority-changing transaction then cannot acquire its exclusive
        # per-case lock before descriptor pin/process start.
        validate_final_open_authority(expected)
        transition_commits.append(service.attempt_storage_transition())
        process_starts.append(True)
        return "started-under-stable-authority"

    opened = {
        "blocked": False,
        "status": ChainStatus.OK,
        "issues": [],
        "manifest_version": 2,
    }
    with (
        patch(
            "sift_gateway.policy_middleware.check_evidence_gate_db",
            return_value=opened,
        ),
        patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=None),
    ):
        result = await mcp.call_tool(
            "run_command", {"command": "cat evidence/sealed.raw"}
        )

    assert result.is_error is False
    assert transition_commits == [False]
    assert process_starts == [True]


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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "command",
    [
        "echo changed > evidence/sealed.raw",
        "cp agent/source.raw evidence/sealed.raw",
        "rm evidence/sealed.raw",
        "mv evidence/sealed.raw agent/moved.raw",
        "chmod 600 evidence/sealed.raw",
        "chown root evidence/sealed.raw",
        "chattr -i evidence/sealed.raw",
        "setfattr -n user.test -v changed evidence/sealed.raw",
        "ln evidence/sealed.raw agent/linked.raw",
        "truncate -s 0 evidence/sealed.raw",
    ],
)
@pytest.mark.skip(
    reason="P4.23 CP1: external-storage admission E2E re-homed by CP2A/CP2B; CP1 "
    "gate-denial routing covered by test_cp1_admission.py + the CP3 VM gate"
)
async def test_public_durable_mutations_are_denied_before_enqueue(tmp_path, command):
    from sift_gateway.mcp_server import create_gateway_mcp_server

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    target = evidence / "sealed.raw"
    target.write_bytes(b"sealed")
    (tmp_path / "agent").mkdir()
    (tmp_path / "agent" / "source.raw").write_bytes(b"source")
    service = _AdmissionService(case_dir=tmp_path, known={"evidence/sealed.raw"})
    before = _tree_snapshot(tmp_path, target)
    gateway = _gateway(tmp_path, service)
    mcp = create_gateway_mcp_server(gateway, api_keys={})
    opened = {
        "blocked": False,
        "status": ChainStatus.OK,
        "issues": [],
        "manifest_version": 3,
    }

    with (
        patch(
            "sift_gateway.policy_middleware.check_evidence_gate_db", return_value=opened
        ),
        patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=None),
    ):
        result = await mcp.call_tool(
            "run_command_job", {"command": command, "purpose": "mutation negative"}
        )

    assert result.is_error is False  # handler returns a sanitized error envelope
    gateway.job_service.enqueue_job.assert_not_called()
    assert _tree_snapshot(tmp_path, target) == before


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


@pytest.mark.asyncio
@pytest.mark.skip(
    reason="P4.23 CP1: external-storage admission E2E re-homed by CP2A/CP2B; CP1 "
    "gate-denial routing covered by test_cp1_admission.py + the CP3 VM gate"
)
async def test_evidence_symlink_alias_is_denied_before_aggregate_tool(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    sealed = evidence / "sealed.raw"
    sealed.write_bytes(b"sealed")
    agent = tmp_path / "agent"
    agent.mkdir()
    (agent / "alias.raw").symlink_to(sealed)
    service = _AdmissionService(case_dir=tmp_path, known={"evidence/sealed.raw"})
    gateway = _gateway(tmp_path, service)
    mcp = FastMCP("aggregate", middleware=gateway_policy_middlewares(gateway))
    ran = False

    @mcp.tool(name="run_command")
    async def run_command(command: str):
        nonlocal ran
        ran = True
        return command

    opened = {
        "blocked": False,
        "status": ChainStatus.OK,
        "issues": [],
        "manifest_version": 3,
    }
    with (
        patch(
            "sift_gateway.policy_middleware.check_evidence_gate_db", return_value=opened
        ),
        patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=None),
    ):
        result = await mcp.call_tool("run_command", {"command": "cat agent/alias.raw"})

    assert ran is False
    assert result.is_error is True
    assert "active sealed version" in result.content[0].text


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


class _Cursor:
    def __init__(self, row):
        self.row = row

    def execute(self, sql, _params):
        self.sql = " ".join(sql.split())

    def fetchall(self):
        if "evidence_exact_restore_posture_receipts" in self.sql:
            return []
        return [self.row]

    def fetchone(self):
        if "from app.evidence_storage_authorities a" in self.sql:
            return (
                "LOCAL_IMMUTABLE",
                None,
                None,
                "AVAILABLE",
                1,
                1,
                None,
                1,
                "sha256:manifest",
                "receipt-1",
                1,
            )
        if "evidence_storage_authorities" in self.sql:
            return (
                "LOCAL_IMMUTABLE",
                None,
                None,
                "AVAILABLE",
                1,
                1,
                None,
                None,
                "NONE",
            )
        return None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None


class _Connection:
    def __init__(self, row):
        self.row = row

    def cursor(self):
        return _Cursor(self.row)

    def commit(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None


class _ResolveCursor:
    def __init__(self, row):
        self.row = row

    def execute(self, sql, _params):
        self.sql = " ".join(sql.split())

    def fetchone(self):
        if "from app.evidence_storage_authorities a" in self.sql:
            return (
                "LOCAL_IMMUTABLE",
                None,
                None,
                "AVAILABLE",
                1,
                1,
                None,
                1,
                "sha256:manifest",
                "receipt-1",
                1,
            )
        if "evidence_storage_authorities" in self.sql:
            return ("LOCAL_IMMUTABLE", None, None, "AVAILABLE", 1, 1, None)
        if "evidence_storage_verifications" in self.sql:
            return None
        return self.row

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None


class _ResolveConnection:
    def __init__(self, row):
        self.row = row

    def cursor(self):
        return _ResolveCursor(self.row)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None


class _ExternalResolveCursor(_ResolveCursor):
    def __init__(self, row, storage, receipt):
        super().__init__(row)
        self.storage = storage
        self.receipt = receipt
        self.queries = []

    def execute(self, sql, _params):
        super().execute(sql, _params)
        self.queries.append(self.sql)

    def fetchone(self):
        if "from app.evidence_storage_authorities a" in self.sql:
            return (
                self.storage[0],
                self.storage[1],
                self.storage[2],
                self.storage[3],
                self.storage[4],
                self.storage[5],
                self.storage[6],
                1,
                "sha256:manifest",
                "receipt-1",
                1,
            )
        if "evidence_storage_verifications" in self.sql:
            return ("receipt-1", self.receipt)
        if "evidence_storage_authorities" in self.sql:
            return self.storage
        return self.row


class _ExternalResolveConnection:
    def __init__(self, row, storage, receipt):
        self.cursor_instance = _ExternalResolveCursor(row, storage, receipt)

    def cursor(self):
        return self.cursor_instance

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None


class _ObservationCursor:
    def __init__(self):
        self.calls = []
        self._one = None
        self.last_sql = ""

    def execute(self, sql, params):
        normalized = " ".join(sql.split())
        self.last_sql = normalized
        self.calls.append((normalized, params))
        if "evidence_storage_authorities" in normalized:
            self._one = (
                (
                    "LOCAL_IMMUTABLE",
                    None,
                    None,
                    "AVAILABLE",
                    1,
                    1,
                    None,
                    1,
                    "sha256:manifest",
                    "receipt-1",
                    0,
                )
                if "join app.evidence_chain_heads" in normalized
                else (
                    "LOCAL_IMMUTABLE",
                    None,
                    None,
                    "AVAILABLE",
                    1,
                    1,
                    None,
                    None,
                    "NONE",
                )
            )
        elif "evidence_storage_verifications" in normalized:
            self._one = None
        else:
            self._one = (
                ("observed-evidence",)
                if "evidence_observe_admission" in normalized
                else None
            )

    def fetchall(self):
        return []

    def fetchone(self):
        return self._one

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None


class _ObservationConnection:
    def __init__(self, cursor):
        self._cursor = cursor
        self.commits = 0

    def cursor(self):
        return self._cursor

    def commit(self):
        self.commits += 1

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None


class _SealedObservationCursor(_ObservationCursor):
    def __init__(self, sealed):
        super().__init__()
        self.sealed = sealed

    def fetchall(self):
        if "evidence_exact_restore_posture_receipts" in self.last_sql:
            return []
        return self.sealed


class _ReceiptObservationCursor(_SealedObservationCursor):
    def __init__(self, sealed, receipt):
        super().__init__(sealed)
        self.receipt = receipt

    def fetchall(self):
        if "evidence_exact_restore_posture_receipts" in self.last_sql:
            return [
                (
                    item["evidence_object_id"],
                    item["evidence_version_id"],
                    item["sha256"],
                    item["bytes"],
                    item["st_dev"],
                    item["st_ino"],
                    item["st_mtime_ns"],
                    item["st_ctime_ns"],
                    item["st_nlink"],
                    item["owner"],
                    item["mode"],
                    item["immutable"],
                    item.get("_authority_created_at"),
                )
                for item in self.receipt
            ]
        return super().fetchall()


class _CompetingReceiptObservationCursor(_ReceiptObservationCursor):
    def __init__(self, sealed, restore_receipt, storage_receipt, storage_created):
        super().__init__(sealed, restore_receipt)
        self.storage_receipt = storage_receipt
        self.storage_created = storage_created

    def execute(self, sql, params):
        normalized = " ".join(sql.split())
        super().execute(sql, params)
        if normalized.startswith(
            "select v.id::text,v.item_facts,v.created_at "
            "from app.evidence_storage_verifications v"
        ):
            self._one = (
                "whole-case-receipt",
                self.storage_receipt,
                self.storage_created,
            )


class _LatchEnforcingObservationCursor(_SealedObservationCursor):
    """Model the migrated RPC's persisted-violation prerequisite check."""

    def __init__(self, sealed):
        super().__init__(sealed)
        self.violation_latched = False

    def execute(self, sql, params):
        normalized = " ".join(sql.split())
        if (
            "evidence_record_inventory_classification_v2" in normalized
            and self.violation_latched
        ):
            findings = getattr(params[3], "obj", params[3])
            if not any(
                finding["code"] == "PERSISTED_VIOLATION" for finding in findings
            ):
                raise RuntimeError("persisted_custody_violation_requires_recovery")
        super().execute(sql, params)
        if "evidence_mark_admission_violation" in normalized:
            self.violation_latched = True


class _ViolatedObservationCursor(_SealedObservationCursor):
    def fetchone(self):
        if "from app.evidence_chain_heads" in self.last_sql:
            return ("violated",)
        return super().fetchone()


@pytest.mark.parametrize("condition", ["changed", "missing"])
def test_reconciliation_violation_uses_request_correlation(
    condition, tmp_path, monkeypatch
):
    case_dir = tmp_path / "case"
    evidence = case_dir / "evidence"
    evidence.mkdir(parents=True)
    rel = "evidence/sealed.raw"
    if condition == "changed":
        (evidence / "sealed.raw").write_bytes(b"changed")
    cursor = _LatchEnforcingObservationCursor(
        [
            (
                "sealed-object",
                rel,
                "sha256:" + "a" * 64,
                1,
                datetime.now(timezone.utc) + timedelta(seconds=5),
            )
        ]
    )
    service = EvidenceAuthorityService("postgresql://unused")
    monkeypatch.setattr(service, "_case_artifact_path", lambda _case_id: case_dir)
    monkeypatch.setattr(service, "_connect", lambda: _ObservationConnection(cursor))
    context = ActiveCaseContext(
        case_id="11111111-1111-1111-1111-111111111111",
        case_key="case-one",
        artifact_path=str(case_dir),
        request_id="opaque-request-violation",
        db_active=True,
    )

    with use_active_case_context(context):
        result = service.reconcile_for_admission(context.case_id)

    violations = [
        call for call in cursor.calls if "evidence_mark_admission_violation" in call[0]
    ]
    assert len(violations) == 1
    assert violations[0][1][1] == "sealed-object"
    assert violations[0][1][2] == f"sealed_evidence_{condition}"
    violation_findings = getattr(violations[0][1][3], "obj", violations[0][1][3])
    assert [finding["code"] for finding in violation_findings] == [
        "CONTENT_CHANGED" if condition == "changed" else "SEALED_EVIDENCE_MISSING"
    ]
    assert violations[0][1][4] == "opaque-request-violation"
    classification_index = next(
        index
        for index, call in enumerate(cursor.calls)
        if "evidence_record_inventory_classification_v2" in call[0]
    )
    violation_index = next(
        index
        for index, call in enumerate(cursor.calls)
        if "evidence_mark_admission_violation" in call[0]
    )
    assert classification_index < violation_index
    assert result["state"] == "available"


def test_classification_failure_never_marks_or_commits_violation(tmp_path, monkeypatch):
    class RejectingClassificationCursor(_SealedObservationCursor):
        def execute(self, sql, params):
            if "evidence_record_inventory_classification_v2" in sql:
                raise RuntimeError("classification_write_failed")
            super().execute(sql, params)

    case_dir = tmp_path / "case"
    evidence = case_dir / "evidence"
    evidence.mkdir(parents=True)
    (evidence / "sealed.raw").write_bytes(b"changed")
    cursor = RejectingClassificationCursor(
        [
            (
                "sealed-object",
                "evidence/sealed.raw",
                "sha256:" + "a" * 64,
                1,
                datetime.now(timezone.utc) + timedelta(seconds=5),
            )
        ]
    )
    connection = _ObservationConnection(cursor)
    service = EvidenceAuthorityService("postgresql://unused")
    monkeypatch.setattr(service, "_case_artifact_path", lambda _case_id: case_dir)
    monkeypatch.setattr(service, "_connect", lambda: connection)

    with pytest.raises(RuntimeError, match="classification_write_failed"):
        service.reconcile_for_admission("11111111-1111-1111-1111-111111111111")

    assert connection.commits == 0
    assert not any(
        "evidence_mark_admission_violation" in sql for sql, _params in cursor.calls
    )


def test_violation_failure_rolls_back_successful_classification(tmp_path, monkeypatch):
    class TransactionConnection(_ObservationConnection):
        def __init__(self):
            self.pending: list[str] = []
            self.durable: list[str] = []
            super().__init__(TransactionCursor(self))

        def commit(self):
            super().commit()
            self.durable.extend(self.pending)
            self.pending.clear()

        def __exit__(self, *exc):
            if exc and exc[0] is not None:
                self.pending.clear()
            return None

    class TransactionCursor(_SealedObservationCursor):
        def __init__(self, connection):
            super().__init__(
                [
                    (
                        "sealed-object",
                        "evidence/sealed.raw",
                        "sha256:" + "a" * 64,
                        1,
                        datetime.now(timezone.utc) + timedelta(seconds=5),
                    )
                ]
            )
            self.connection = connection

        def execute(self, sql, params):
            normalized = " ".join(sql.split())
            if "evidence_record_inventory_classification_v2" in normalized:
                assert self.connection.commits == 0
                self.connection.pending.extend(["observation", "head"])
            elif "evidence_mark_admission_violation" in normalized:
                assert self.connection.pending == ["observation", "head"]
                assert self.connection.commits == 0
                raise RuntimeError("violation_write_failed")
            super().execute(sql, params)

    case_dir = tmp_path / "case"
    evidence = case_dir / "evidence"
    evidence.mkdir(parents=True)
    (evidence / "sealed.raw").write_bytes(b"changed")
    connection = TransactionConnection()
    service = EvidenceAuthorityService("postgresql://unused")
    monkeypatch.setattr(service, "_case_artifact_path", lambda _case_id: case_dir)
    monkeypatch.setattr(service, "_connect", lambda: connection)

    with pytest.raises(RuntimeError, match="violation_write_failed"):
        service.reconcile_for_admission("11111111-1111-1111-1111-111111111111")

    assert connection.commits == 0
    assert connection.pending == []
    assert connection.durable == []


def test_unavailable_storage_is_not_recorded_as_a_violation(tmp_path, monkeypatch):
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    cursor = _SealedObservationCursor(
        [
            (
                "sealed-object",
                "evidence/sealed.raw",
                "sha256:" + "a" * 64,
                1,
                datetime.now(timezone.utc),
            )
        ]
    )
    service = EvidenceAuthorityService("postgresql://unused")
    monkeypatch.setattr(service, "_case_artifact_path", lambda _case_id: case_dir)
    monkeypatch.setattr(service, "_connect", lambda: _ObservationConnection(cursor))

    result = service.reconcile_for_admission("11111111-1111-1111-1111-111111111111")

    assert result["state"] == "unavailable"
    assert not any(
        "evidence_mark_admission_violation" in call[0] for call in cursor.calls
    )


@pytest.mark.parametrize("has_sealed_authority", [False, True])
def test_external_mount_loss_never_scans_same_named_writable_underlay(
    has_sealed_authority, tmp_path, monkeypatch
):
    from sift_core.evidence_storage import StorageAuthorityError

    case_dir = tmp_path / "case"
    evidence = case_dir / "evidence"
    evidence.mkdir(parents=True)
    # This is the local directory exposed after the external mount disappears.
    # A stale same-named file must not be treated as the sealed mounted object.
    (evidence / "sealed.raw").write_bytes(b"writable underlay")

    class ExternalObservationCursor(_SealedObservationCursor):
        def execute(self, sql, params):
            normalized = " ".join(sql.split())
            super().execute(sql, params)
            if "from app.evidence_storage_authorities where case_id=%s" in normalized:
                self._one = (
                    "EXTERNALLY_READ_ONLY",
                    "a" * 64,
                    "b" * 64,
                    "AVAILABLE",
                    2,
                    2,
                    True,
                    None,
                    "NONE",
                )

    sealed_rows = (
        [
            (
                "sealed-object",
                "evidence/sealed.raw",
                "sha256:" + "c" * 64,
                1,
                datetime.now(timezone.utc),
                {},
                "sealed",
                "sealed-version",
            )
        ]
        if has_sealed_authority
        else []
    )
    cursor = ExternalObservationCursor(sealed_rows)
    service = EvidenceAuthorityService("postgresql://unused")
    monkeypatch.setattr(service, "_case_artifact_path", lambda _case_id: case_dir)
    monkeypatch.setattr(service, "_connect", lambda: _ObservationConnection(cursor))
    monkeypatch.setattr(
        service,
        "storage_execution_authority",
        lambda _case_id: pytest.fail("mount loss cannot issue execution authority"),
    )
    monkeypatch.setattr(
        service,
        "_record_detected_observation",
        lambda *_args, **_kwargs: pytest.fail(
            "writable underlay cannot create DETECTED observations"
        ),
    )

    def missing_exact_mount(_fd, *, require_read_only=True, expected_mount_path=None):
        assert require_read_only is False
        assert expected_mount_path == evidence
        raise StorageAuthorityError("external evidence root is not the mounted source")

    monkeypatch.setattr(
        "sift_gateway.portal_services.external_storage_facts",
        missing_exact_mount,
    )
    monkeypatch.setattr(
        os,
        "scandir",
        lambda _path: pytest.fail("writable underlay must not be enumerated"),
    )

    result = service.reconcile_for_admission("11111111-1111-1111-1111-111111111111")

    assert result["state"] == "unavailable"
    assert result["gate_state"] == "BLOCKED_UNAVAILABLE"
    assert result["observed"] == 0
    assert result["execution_authority"] is None
    classification_call = next(
        call
        for call in cursor.calls
        if "evidence_record_inventory_classification" in call[0]
    )
    findings = getattr(classification_call[1][3], "obj", classification_call[1][3])
    assert findings == [
        {
            "code": "STORAGE_UNAVAILABLE",
            "gate_state": "BLOCKED_UNAVAILABLE",
            "recovery": "RECONNECT_AND_VERIFY",
            "evidence_object_id": None,
            "observation_id": None,
            "full_verification_required": False,
        }
    ]
    assert any(
        "evidence_storage_record_observation" in sql and "false" in sql
        for sql, _params in cursor.calls
    )
    assert not any(
        marker in sql
        for sql, _params in cursor.calls
        for marker in (
            "evidence_observe_admission",
            "evidence_mark_admission_violation",
        )
    )


def test_external_read_only_reconnect_classifies_returned_full_verify_authority(
    tmp_path, monkeypatch
):
    from sift_core.evidence_storage import ExternalStorageFacts

    case_dir = tmp_path / "case"
    evidence = case_dir / "evidence"
    evidence.mkdir(parents=True)
    image = evidence / "sealed.raw"
    image.write_bytes(b"sealed")
    sibling = evidence / "sibling.raw"
    sibling.write_bytes(b"sibling")
    st = image.stat()
    sibling_st = sibling.stat()
    source, verified_mount, observed_mount = "a" * 64, "b" * 64, "e" * 64
    unavailable_finding = {
        "code": "STORAGE_UNAVAILABLE",
        "gate_state": "BLOCKED_UNAVAILABLE",
        "recovery": "RECONNECT_AND_VERIFY",
        "evidence_object_id": None,
        "observation_id": None,
        "full_verification_required": False,
        "storage_generation": 2,
    }
    full_verify_finding = {
        "code": "STORAGE_FULL_VERIFY_REQUIRED",
        "gate_state": "BLOCKED_UNAVAILABLE",
        "recovery": "FULL_VERIFY_AND_REPAIR",
        "evidence_object_id": None,
        "observation_id": None,
        "full_verification_required": True,
    }

    class ReconnectObservationCursor(_SealedObservationCursor):
        def execute(self, sql, params):
            normalized = " ".join(sql.split())
            super().execute(sql, params)
            if "from app.evidence_chain_heads where case_id=%s" in normalized:
                self._one = (
                    "violated",
                    [unavailable_finding],
                    1,
                    "sha256:" + "d" * 64,
                )
            elif "from app.evidence_storage_authorities where case_id=%s" in normalized:
                self._one = (
                    "EXTERNALLY_READ_ONLY",
                    source,
                    verified_mount,
                    "UNAVAILABLE",
                    2,
                    2,
                    None,
                    None,
                    "RECONNECT_AND_VERIFY",
                )
            elif "from app.evidence_storage_record_observation(" in normalized:
                self._one = (
                    "EXTERNALLY_READ_ONLY",
                    source,
                    verified_mount,
                    "FULL_VERIFY_REQUIRED",
                    2,
                    2,
                    True,
                    None,
                    "FULL_VERIFY",
                )
            elif "evidence_record_inventory_classification_v2" in normalized:
                findings = getattr(params[3], "obj", params[3])
                if findings != [full_verify_finding]:
                    raise RuntimeError("persisted_custody_violation_requires_recovery")

    cursor = ReconnectObservationCursor(
        [
            (
                "sealed-object",
                "evidence/sealed.raw",
                "sha256:" + hashlib.sha256(b"sealed").hexdigest(),
                st.st_size,
                datetime.now(timezone.utc),
                {},
                "sealed",
                "sealed-version",
            ),
            (
                "sibling-object",
                "evidence/sibling.raw",
                "sha256:" + hashlib.sha256(b"sibling").hexdigest(),
                sibling_st.st_size,
                datetime.now(timezone.utc),
                {},
                "sealed",
                "sibling-version",
            ),
        ]
    )
    service = EvidenceAuthorityService("postgresql://unused")
    monkeypatch.setattr(service, "_case_artifact_path", lambda _case_id: case_dir)
    monkeypatch.setattr(service, "_connect", lambda: _ObservationConnection(cursor))
    monkeypatch.setattr(
        service,
        "storage_execution_authority",
        lambda _case_id: (_ for _ in ()).throw(
            PortalServiceError("external_storage_full_verify_required", http_status=403)
        ),
    )
    monkeypatch.setattr(
        "sift_gateway.portal_services.external_storage_facts",
        lambda _fd, **_kwargs: ExternalStorageFacts(
            source, observed_mount, "ext4", True
        ),
    )

    result = service.reconcile_for_admission("11111111-1111-1111-1111-111111111111")

    assert result["gate_state"] == "BLOCKED_UNAVAILABLE"
    assert result["state"] == "unavailable"
    assert result["observed"] == 2
    classification_call = next(
        call
        for call in cursor.calls
        if "evidence_record_inventory_classification_v2" in call[0]
    )
    findings = getattr(classification_call[1][3], "obj", classification_call[1][3])
    assert findings == [full_verify_finding]
    assert all(finding["evidence_object_id"] is None for finding in findings)
    observation_query = next(
        sql
        for sql, _params in cursor.calls
        if "from app.evidence_storage_record_observation(" in sql
    )
    assert "observed.verified_generation" in observation_query
    assert "observed.remediation" in observation_query


def test_midscan_entry_race_discards_all_object_conclusions(tmp_path, monkeypatch):
    case_dir = tmp_path / "case"
    evidence = case_dir / "evidence"
    evidence.mkdir(parents=True)
    stable = evidence / "new.raw"
    stable.write_bytes(b"new")

    class StableEntry:
        name = "new.raw"
        path = str(stable)

        @staticmethod
        def stat(*, follow_symlinks=False):
            return stable.stat(follow_symlinks=follow_symlinks)

        @staticmethod
        def is_file(*, follow_symlinks=False):
            del follow_symlinks
            return True

    class RacyEntry:
        name = "racy.raw"
        path = str(evidence / "racy.raw")

        @staticmethod
        def stat(*, follow_symlinks=False):
            del follow_symlinks
            raise OSError("entry disappeared")

        @staticmethod
        def is_file(*, follow_symlinks=False):
            del follow_symlinks
            return True

    cursor = _ObservationCursor()
    service = EvidenceAuthorityService("postgresql://unused")
    monkeypatch.setattr(service, "_case_artifact_path", lambda _case_id: case_dir)
    monkeypatch.setattr(service, "_connect", lambda: _ObservationConnection(cursor))
    monkeypatch.setattr(
        service,
        "storage_execution_authority",
        lambda _case_id: pytest.fail("partial scan cannot issue execution authority"),
    )
    monkeypatch.setattr(os, "scandir", lambda _path: [StableEntry(), RacyEntry()])

    result = service.reconcile_for_admission("11111111-1111-1111-1111-111111111111")

    assert result["state"] == "unavailable"
    assert "evidence_inventory_unavailable" in result["issues"]
    assert not any(
        marker in sql
        for sql, _params in cursor.calls
        for marker in (
            "evidence_observe_admission",
            "evidence_mark_admission_violation",
        )
    )
    classification_call = next(
        call
        for call in cursor.calls
        if "evidence_record_inventory_classification" in call[0]
    )
    findings = getattr(classification_call[1][3], "obj", classification_call[1][3])
    assert [finding["code"] for finding in findings] == ["STORAGE_UNAVAILABLE"]


def test_posture_drift_requires_full_verify_without_generic_content_violation(
    tmp_path, monkeypatch
):
    case_dir = tmp_path / "case"
    evidence = case_dir / "evidence"
    evidence.mkdir(parents=True)
    image = evidence / "sealed.raw"
    image.write_bytes(b"sealed")
    st = image.stat()
    cursor = _SealedObservationCursor(
        [
            (
                "sealed-object",
                "evidence/sealed.raw",
                "sha256:" + hashlib.sha256(b"sealed").hexdigest(),
                st.st_size,
                datetime.now(timezone.utc),
                {
                    "posture": {
                        "st_dev": st.st_dev,
                        "st_ino": st.st_ino,
                        "st_mtime_ns": st.st_mtime_ns,
                        "st_ctime_ns": st.st_ctime_ns,
                        "st_nlink": st.st_nlink,
                    }
                },
            )
        ]
    )
    service = EvidenceAuthorityService("postgresql://unused")
    monkeypatch.setattr(service, "_case_artifact_path", lambda _case_id: case_dir)
    monkeypatch.setattr(service, "_connect", lambda: _ObservationConnection(cursor))
    monkeypatch.setattr(
        "sift_core.evidence_posture.get_immutable_flag_fd", lambda _fd: False
    )

    result = service.reconcile_for_admission("11111111-1111-1111-1111-111111111111")

    assert result["gate_state"] == "BLOCKED_VIOLATION"
    classification_call = next(
        call
        for call in cursor.calls
        if "evidence_record_inventory_classification" in call[0]
    )
    classification_findings = getattr(
        classification_call[1][3], "obj", classification_call[1][3]
    )
    assert [finding["code"] for finding in classification_findings] == [
        "FULL_VERIFY_REQUIRED"
    ]
    assert classification_findings[0]["full_verification_required"] is True
    assert not any(
        "evidence_mark_admission_violation" in call[0] for call in cursor.calls
    )


def test_exact_restore_receipt_rebinds_current_posture_without_new_version(
    tmp_path, monkeypatch
):
    case_dir = tmp_path / "case"
    evidence = case_dir / "evidence"
    evidence.mkdir(parents=True)
    image = evidence / "sealed.raw"
    image.write_bytes(b"restored-exact")
    st = image.stat()
    sha256 = "sha256:" + hashlib.sha256(b"restored-exact").hexdigest()
    receipt = [
        {
            "evidence_object_id": "sealed-object",
            "evidence_version_id": "version-7",
            "sha256": sha256,
            "bytes": st.st_size,
            "st_dev": st.st_dev,
            "st_ino": st.st_ino,
            "st_mtime_ns": st.st_mtime_ns,
            "st_ctime_ns": st.st_ctime_ns,
            "st_nlink": st.st_nlink,
            "owner": "sift-service",
            "mode": "0644",
            "immutable": True,
        }
    ]
    cursor = _ReceiptObservationCursor(
        [
            (
                "sealed-object",
                "evidence/sealed.raw",
                sha256,
                st.st_size,
                datetime.now(timezone.utc) - timedelta(days=1),
                {
                    "posture": {
                        "st_dev": st.st_dev,
                        "st_ino": st.st_ino - 1,
                        "st_mtime_ns": st.st_mtime_ns - 1,
                        "st_ctime_ns": st.st_ctime_ns - 1,
                        "st_nlink": st.st_nlink,
                    }
                },
                "sealed",
                "version-7",
            )
        ],
        receipt,
    )
    service = EvidenceAuthorityService("postgresql://unused")
    connection = _ObservationConnection(cursor)
    monkeypatch.setattr(service, "_case_artifact_path", lambda _case_id: case_dir)
    monkeypatch.setattr(service, "_connect", lambda: connection)
    monkeypatch.setattr(
        "sift_core.evidence_posture.get_immutable_flag_fd", lambda _fd: True
    )

    result = service.reconcile_for_admission("11111111-1111-1111-1111-111111111111")

    assert result["gate_state"] == "OPEN"
    classification_call = next(
        call
        for call in cursor.calls
        if "evidence_record_inventory_classification" in call[0]
    )
    findings = getattr(classification_call[1][3], "obj", classification_call[1][3])
    assert findings == []

    assert cursor.calls[0][0].startswith(
        "select pg_advisory_xact_lock(hashtextextended(%s,0))"
    )
    restore_query = next(
        sql
        for sql, _params in cursor.calls
        if "evidence_exact_restore_posture_receipts" in sql
    )
    assert "a.generation=r.storage_generation" in restore_query
    assert "o.current_version_id=r.evidence_version_id" in restore_query
    assert connection.commits == 1

    drift_cursor = _ReceiptObservationCursor(cursor.sealed, receipt)
    drift_service = EvidenceAuthorityService("postgresql://unused")
    monkeypatch.setattr(drift_service, "_case_artifact_path", lambda _case_id: case_dir)
    monkeypatch.setattr(
        drift_service, "_connect", lambda: _ObservationConnection(drift_cursor)
    )
    monkeypatch.setattr(
        "sift_core.evidence_posture.get_immutable_flag_fd", lambda _fd: False
    )
    drift = drift_service.reconcile_for_admission(
        "11111111-1111-1111-1111-111111111111"
    )
    assert drift["gate_state"] == "BLOCKED_VIOLATION"
    drift_call = next(
        call
        for call in drift_cursor.calls
        if "evidence_record_inventory_classification" in call[0]
    )
    drift_findings = getattr(drift_call[1][3], "obj", drift_call[1][3])
    assert [finding["code"] for finding in drift_findings] == ["FULL_VERIFY_REQUIRED"]


@pytest.mark.parametrize(
    (
        "storage_offset",
        "restore_offset",
        "actual_source",
        "restore_version",
        "expected_gate",
        "baseline_matches_live",
    ),
    (
        (2, 1, "storage", "version-7", "OPEN", False),
        (1, 2, "restore", "version-7", "OPEN", False),
        (1, 1, "storage", "version-7", "BLOCKED_VIOLATION", False),
        (1, 1, "storage", "version-7", "BLOCKED_VIOLATION", True),
        (1, 2, "storage", "version-old", "OPEN", False),
    ),
)
def test_local_posture_authority_uses_strictly_newest_complete_receipt(
    tmp_path,
    monkeypatch,
    storage_offset,
    restore_offset,
    actual_source,
    restore_version,
    expected_gate,
    baseline_matches_live,
):
    case_dir = tmp_path / "case"
    evidence = case_dir / "evidence"
    evidence.mkdir(parents=True)
    image = evidence / "sealed.raw"
    image.write_bytes(b"verified-current")
    st = image.stat()
    sha256 = "sha256:" + hashlib.sha256(b"verified-current").hexdigest()
    now = datetime.now(timezone.utc)

    def receipt(*, actual, created):
        return {
            "evidence_object_id": "sealed-object",
            "evidence_version_id": "version-7",
            "sha256": sha256,
            "bytes": st.st_size,
            "st_dev": st.st_dev,
            "st_ino": st.st_ino if actual else st.st_ino + 100,
            "st_mtime_ns": st.st_mtime_ns if actual else st.st_mtime_ns - 100,
            "st_ctime_ns": st.st_ctime_ns if actual else st.st_ctime_ns - 100,
            "st_nlink": st.st_nlink,
            "owner": "sift-service",
            "mode": "0644",
            "immutable": True,
            "_authority_created_at": created,
        }

    storage_created = now + timedelta(seconds=storage_offset)
    restore_created = now + timedelta(seconds=restore_offset)
    storage_receipt = receipt(
        actual=actual_source == "storage", created=storage_created
    )
    restore_receipt = receipt(
        actual=actual_source == "restore", created=restore_created
    )
    restore_receipt["evidence_version_id"] = restore_version
    cursor = _CompetingReceiptObservationCursor(
        [
            (
                "sealed-object",
                "evidence/sealed.raw",
                sha256,
                st.st_size,
                now - timedelta(days=1),
                {
                    "posture": {
                        "st_dev": st.st_dev,
                        "st_ino": st.st_ino if baseline_matches_live else st.st_ino - 1,
                        "st_mtime_ns": st.st_mtime_ns
                        if baseline_matches_live
                        else st.st_mtime_ns - 1,
                        "st_ctime_ns": st.st_ctime_ns
                        if baseline_matches_live
                        else st.st_ctime_ns - 1,
                        "st_nlink": st.st_nlink,
                    }
                },
                "sealed",
                "version-7",
            )
        ],
        [restore_receipt],
        [storage_receipt],
        storage_created,
    )
    service = EvidenceAuthorityService("postgresql://unused")
    monkeypatch.setattr(service, "_case_artifact_path", lambda _case_id: case_dir)
    monkeypatch.setattr(service, "_connect", lambda: _ObservationConnection(cursor))
    monkeypatch.setattr(
        "sift_core.evidence_posture.get_immutable_flag_fd", lambda _fd: True
    )

    result = service.reconcile_for_admission("11111111-1111-1111-1111-111111111111")

    assert result["gate_state"] == expected_gate
    storage_query = next(
        sql
        for sql, _params in cursor.calls
        if "from app.evidence_storage_verifications v" in sql
    )
    assert "jsonb_array_length(v.item_facts)=(select count(*)" in storage_query
    assert (
        "not exists(select 1 from jsonb_array_elements(v.item_facts)" in storage_query
    )
    assert storage_query.startswith(
        "select v.id::text,v.item_facts,v.created_at "
        "from app.evidence_storage_verifications v"
    )


def test_persisted_violation_is_returned_and_recorded_when_mount_matches(
    tmp_path, monkeypatch
):
    case_dir = tmp_path / "case"
    evidence = case_dir / "evidence"
    evidence.mkdir(parents=True)
    image = evidence / "sealed.raw"
    image.write_bytes(b"sealed")
    st = image.stat()
    cursor = _ViolatedObservationCursor(
        [
            (
                "violated-object",
                "evidence/sealed.raw",
                "sha256:" + hashlib.sha256(b"sealed").hexdigest(),
                st.st_size,
                datetime.now(timezone.utc),
                {
                    "posture": {
                        "st_dev": st.st_dev,
                        "st_ino": st.st_ino,
                        "st_mtime_ns": st.st_mtime_ns,
                        "st_ctime_ns": st.st_ctime_ns,
                        "st_nlink": st.st_nlink,
                    }
                },
                "violated",
            )
        ]
    )
    service = EvidenceAuthorityService("postgresql://unused")
    monkeypatch.setattr(service, "_case_artifact_path", lambda _case_id: case_dir)
    monkeypatch.setattr(service, "_connect", lambda: _ObservationConnection(cursor))
    monkeypatch.setattr(
        "sift_core.evidence_posture.get_immutable_flag_fd", lambda _fd: True
    )

    result = service.reconcile_for_admission("11111111-1111-1111-1111-111111111111")

    assert result["gate_state"] == "BLOCKED_VIOLATION"
    classification_call = next(
        call
        for call in cursor.calls
        if "evidence_record_inventory_classification" in call[0]
    )
    findings = getattr(classification_call[1][3], "obj", classification_call[1][3])
    assert classification_call[1][2] == "BLOCKED_VIOLATION"
    assert [finding["code"] for finding in findings] == ["PERSISTED_VIOLATION"]
    assert not any(
        "evidence_mark_admission_violation" in call[0] for call in cursor.calls
    )


def test_persisted_changed_object_does_not_append_duplicate_violation(
    tmp_path, monkeypatch
):
    case_dir = tmp_path / "case"
    evidence = case_dir / "evidence"
    evidence.mkdir(parents=True)
    image = evidence / "sealed.raw"
    image.write_bytes(b"changed")
    cursor = _ViolatedObservationCursor(
        [
            (
                "violated-object",
                "evidence/sealed.raw",
                "sha256:" + hashlib.sha256(b"original").hexdigest(),
                len(b"original"),
                datetime.now(timezone.utc) + timedelta(seconds=5),
                {},
                "violated",
            )
        ]
    )
    service = EvidenceAuthorityService("postgresql://unused")
    monkeypatch.setattr(service, "_case_artifact_path", lambda _case_id: case_dir)
    monkeypatch.setattr(service, "_connect", lambda: _ObservationConnection(cursor))

    result = service.reconcile_for_admission("11111111-1111-1111-1111-111111111111")

    assert result["gate_state"] == "BLOCKED_VIOLATION"
    classification_call = next(
        call
        for call in cursor.calls
        if "evidence_record_inventory_classification_v2" in call[0]
    )
    findings = getattr(classification_call[1][3], "obj", classification_call[1][3])
    assert [finding["code"] for finding in findings] == [
        "PERSISTED_VIOLATION",
        "CONTENT_CHANGED",
    ]
    assert not any(
        "evidence_mark_admission_violation" in call[0] for call in cursor.calls
    )


def test_inventory_reconciliation_does_not_hash_large_unchanged_sibling(
    tmp_path, monkeypatch
):
    case_dir = tmp_path / "case"
    evidence = case_dir / "evidence"
    evidence.mkdir(parents=True)
    image = evidence / "large.E01"
    with image.open("wb") as handle:
        handle.truncate(19 * 1024 * 1024 * 1024)
    future = datetime.now(timezone.utc) + timedelta(seconds=5)
    row = (
        "ev-1",
        "evidence/large.E01",
        "sha256:" + "a" * 64,
        image.stat().st_size,
        future,
    )
    service = EvidenceAuthorityService("postgresql://unused")
    monkeypatch.setattr(service, "_case_artifact_path", lambda _case_id: case_dir)
    monkeypatch.setattr(service, "_connect", lambda: _Connection(row))
    monkeypatch.setattr(
        "sift_gateway.portal_services._admission_fingerprint",
        lambda _path: pytest.fail(
            "aggregate inventory scan must not hash sealed siblings"
        ),
    )
    monkeypatch.setattr(
        "sift_core.evidence_posture.get_immutable_flag_fd", lambda _fd: True
    )

    result = service.reconcile_for_admission("11111111-1111-1111-1111-111111111111")
    assert result["state"] == "available"
    assert result["gate_state"] == "OPEN"
    assert result["observed"] == 1
    assert result["issues"] == []
    assert result["correlation_id"].startswith("portal-")
    assert image.stat().st_size == 19 * 1024 * 1024 * 1024


def test_admitted_sparse_19gib_reference_never_reads_file_content(
    tmp_path, monkeypatch
):
    case_dir = tmp_path / "case"
    evidence = case_dir / "evidence"
    evidence.mkdir(parents=True)
    image = evidence / "large.E01"
    with image.open("wb") as handle:
        handle.truncate(19 * 1024 * 1024 * 1024)
    row = (
        "ev-1",
        "evidence/large.E01",
        "sealed",
        "sealed",
        "ver-1",
        "sha256:" + "a" * 64,
        image.stat().st_size,
        "ACTIVE",
        "sealed",
    )
    service = EvidenceAuthorityService("postgresql://unused")
    monkeypatch.setattr(
        service,
        "reconcile_for_admission",
        lambda _case_id: {"state": "available", "observed": 1, "issues": []},
    )
    monkeypatch.setattr(service, "_connect", lambda: _ResolveConnection(row))
    monkeypatch.setattr(service, "_resolve_evidence_path", lambda *_args: image)
    monkeypatch.setattr(
        "sift_core.evidence_posture.get_immutable_flag_fd",
        lambda _fd: True,
    )
    monkeypatch.setattr(
        "sift_gateway.portal_services._hash_file",
        lambda _path: pytest.fail("admission must not hash evidence bytes"),
    )
    monkeypatch.setattr(
        os,
        "fdopen",
        lambda *_args, **_kwargs: pytest.fail(
            "admission must not stream evidence bytes"
        ),
    )

    resolved = service.resolve_evidence_reference("case-1", "evidence/large.E01")

    assert resolved["version_id"] == "ver-1"
    assert resolved["sha256"] == "sha256:" + "a" * 64
    assert resolved["bytes"] == 19 * 1024 * 1024 * 1024


def test_local_immutable_posture_drift_denies_reference(tmp_path, monkeypatch):
    case_dir = tmp_path / "case"
    evidence = case_dir / "evidence"
    evidence.mkdir(parents=True)
    image = evidence / "sealed.raw"
    image.write_bytes(b"sealed")
    row = (
        "ev-1",
        "evidence/sealed.raw",
        "sealed",
        "sealed",
        "ver-1",
        "sha256:" + "a" * 64,
        image.stat().st_size,
        "ACTIVE",
        "sealed",
    )
    service = EvidenceAuthorityService("postgresql://unused")
    monkeypatch.setattr(
        service,
        "reconcile_for_admission",
        lambda _case_id: {"state": "available", "observed": 1, "issues": []},
    )
    monkeypatch.setattr(service, "_connect", lambda: _ResolveConnection(row))
    monkeypatch.setattr(service, "_resolve_evidence_path", lambda *_args: image)
    monkeypatch.setattr("sift_gateway.portal_services.sys.platform", "linux")
    monkeypatch.setattr(
        "sift_gateway.portal_services._admission_fingerprint",
        lambda _path: (image.stat(), False),
    )

    with pytest.raises(PortalServiceError, match="evidence_posture_changed"):
        service.resolve_evidence_reference("case-1", "evidence/sealed.raw")


@pytest.mark.parametrize(
    "receipt_version,allowed", [("ver-1", True), ("stale-ver", False)]
)
def test_external_reference_requires_exact_current_receipt_version(
    receipt_version, allowed, tmp_path, monkeypatch
):
    from sift_core.evidence_storage import ExternalStorageFacts

    image = tmp_path / "evidence" / "sealed.raw"
    image.parent.mkdir()
    image.write_bytes(b"sealed")
    st = image.stat()
    source, mount = "a" * 64, "b" * 64
    row = (
        "ev-1",
        "evidence/sealed.raw",
        "sealed",
        "sealed",
        "ver-1",
        "sha256:" + "c" * 64,
        st.st_size,
        "ACTIVE",
        "sealed",
    )
    receipt = [
        {
            "evidence_object_id": "ev-1",
            "evidence_version_id": receipt_version,
            "sha256": "sha256:" + "c" * 64,
            "bytes": st.st_size,
            "st_dev": st.st_dev,
            "st_ino": st.st_ino,
            "st_mtime_ns": st.st_mtime_ns,
            "st_ctime_ns": st.st_ctime_ns,
            "st_nlink": st.st_nlink,
            "storage_source_identity": source,
            "mount_instance_identity": mount,
        }
    ]
    connection = _ExternalResolveConnection(
        row, ("EXTERNALLY_READ_ONLY", source, mount, "AVAILABLE", 7, 7, True), receipt
    )
    service = EvidenceAuthorityService("postgresql://unused")
    monkeypatch.setattr(
        service, "reconcile_for_admission", lambda _case_id: {"state": "available"}
    )
    monkeypatch.setattr(service, "_connect", lambda: connection)
    monkeypatch.setattr(service, "_case_artifact_path", lambda _case_id: tmp_path)
    monkeypatch.setattr(service, "_resolve_evidence_path", lambda *_args: image)

    observed_roots = []

    def exact_root_facts(_fd, **kwargs):
        observed_roots.append(kwargs.get("expected_mount_path"))
        return ExternalStorageFacts(source, mount, "ext4", True)

    monkeypatch.setattr(
        "sift_gateway.portal_services.external_storage_facts",
        exact_root_facts,
    )

    if allowed:
        resolved = service.resolve_evidence_reference("case-1", "evidence/sealed.raw")
        assert resolved["version_id"] == "ver-1"
        assert resolved["storage_source_identity"] == source
        receipt_query = next(
            q
            for q in connection.cursor_instance.queries
            if "evidence_storage_verifications" in q
        )
        assert "v.outcome='SUCCESS'" in receipt_query
        assert "v.generation=a.generation" in receipt_query
        assert "v.manifest_version=h.manifest_version" in receipt_query
    else:
        with pytest.raises(
            PortalServiceError, match="external_storage_full_verify_required"
        ):
            service.resolve_evidence_reference("case-1", "evidence/sealed.raw")
    assert tmp_path / "evidence" in observed_roots


def test_reconciliation_custody_observation_uses_audit_envelope_request_id(
    tmp_path, monkeypatch
):
    case_dir = tmp_path / "case"
    evidence = case_dir / "evidence"
    evidence.mkdir(parents=True)
    (evidence / "new.raw").write_bytes(b"new")
    cursor = _ObservationCursor()
    service = EvidenceAuthorityService("postgresql://unused")
    monkeypatch.setattr(service, "_case_artifact_path", lambda _case_id: case_dir)
    monkeypatch.setattr(service, "_connect", lambda: _ObservationConnection(cursor))
    context = ActiveCaseContext(
        case_id="11111111-1111-1111-1111-111111111111",
        case_key="case-one",
        artifact_path=str(case_dir),
        request_id="opaque-request-123",
        db_active=True,
    )

    with use_active_case_context(context):
        result = service.reconcile_for_admission(context.case_id)

    observation = next(
        call for call in cursor.calls if "evidence_observe_admission" in call[0]
    )
    assert observation[1][4] == "opaque-request-123"
    assert result["correlation_id"] == "opaque-request-123"


@pytest.mark.asyncio
@pytest.mark.skip(
    reason="P4.23 CP1: external-storage admission E2E re-homed by CP2A/CP2B; CP1 "
    "gate-denial routing covered by test_cp1_admission.py + the CP3 VM gate"
)
async def test_aggregate_audit_and_custody_ledgers_share_opaque_request_id(
    tmp_path, monkeypatch
):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "new.raw").write_bytes(b"new")
    cursor = _ObservationCursor()
    service = EvidenceAuthorityService("postgresql://unused")
    monkeypatch.setattr(service, "_case_artifact_path", lambda _case_id: tmp_path)
    monkeypatch.setattr(service, "_connect", lambda: _ObservationConnection(cursor))
    gateway = _gateway(tmp_path, service)
    mcp = FastMCP("aggregate", middleware=gateway_policy_middlewares(gateway))

    @mcp.tool(name="run_command")
    async def run_command(command: str):
        return command

    blocked = {
        "blocked": True,
        "status": ChainStatus.UNSEALED,
        "issues": ["pending"],
        "manifest_version": 1,
    }
    with (
        patch(
            "sift_gateway.policy_middleware.check_evidence_gate_db",
            return_value=blocked,
        ),
        patch("sift_gateway.policy_middleware.current_mcp_identity", return_value=None),
    ):
        await mcp.call_tool("run_command", {"command": "date"})

    observation = next(
        call for call in cursor.calls if "evidence_observe_admission" in call[0]
    )
    custody_correlation = observation[1][4]
    envelope = next(
        call
        for call in gateway._audit.log.mock_calls
        if call.kwargs.get("source") == "gateway_mcp_envelope"
    )
    assert custody_correlation
    assert envelope.kwargs["extra"]["request_id"] == custody_correlation
