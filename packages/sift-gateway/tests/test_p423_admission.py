from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from sift_core.active_case_context import ActiveCaseContext, use_active_case_context
from sift_core.evidence_chain import ChainStatus
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
async def test_storage_authority_change_inside_handler_denies_at_final_open(
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

    @mcp.tool(name="run_command")
    async def run_command(command: str):
        del command
        expected = dict(service.execution_authority)
        # The middleware pre-dispatch check has passed. Model a DB authority
        # generation change immediately before core's final evidence open.
        service.execution_authority["storage_generation"] += 1
        validate_final_open_authority(expected)
        process_starts.append(True)
        return "must-not-run"

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
        with pytest.raises(ToolError, match="authority changed"):
            await mcp.call_tool(
                "run_command", {"command": "cat evidence/sealed.raw"}
            )

    assert process_starts == []


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

    def cursor(self):
        return self._cursor

    def commit(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None


class _SealedObservationCursor(_ObservationCursor):
    def __init__(self, sealed):
        super().__init__()
        self.sealed = sealed

    def fetchall(self):
        return self.sealed


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
    cursor = _SealedObservationCursor(
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
    assert violations[0][1][4] == "opaque-request-violation"
    assert result["state"] == "available"


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
        "sift_core.evidence_chain.get_immutable_flag_fd", lambda _fd: False
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
        "sift_core.evidence_chain.get_immutable_flag_fd", lambda _fd: True
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
        "sift_core.evidence_chain.get_immutable_flag_fd", lambda _fd: True
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
        "sift_core.evidence_chain.get_immutable_flag_fd",
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
    monkeypatch.setattr(
        "sift_gateway.portal_services.external_storage_facts",
        lambda _fd: ExternalStorageFacts(source, mount, "ext4", True),
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
