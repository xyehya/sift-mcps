from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastmcp import FastMCP
from sift_core.evidence_chain import ChainStatus
from sift_gateway.active_case import ActiveCase
from sift_gateway.policy_middleware import gateway_policy_middlewares
from sift_gateway.portal_services import EvidenceAuthorityService


class _CaseService:
    def __init__(self, case):
        self.case = case

    def require_active_case_for_principal(self, _principal):
        return self.case


class _AdmissionService:
    def __init__(self, *, reject=False, case_dir=None):
        self.reject = reject
        self.case_dir = case_dir
        self.reconciled = []
        self.resolved = []
        self.observations = []

    def reconcile_for_admission(self, case_id):
        self.reconciled.append(case_id)
        if self.case_dir is not None:
            self.observations = [
                f"evidence/{entry.name}"
                for entry in os.scandir(self.case_dir / "evidence")
            ]

    def resolve_evidence_reference(self, case_id, ref):
        self.resolved.append((case_id, ref))
        if self.reject:
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
    before = planted.stat()
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

    with patch("sift_gateway.policy_middleware.check_evidence_gate_db", side_effect=observed_gate), patch(
        "sift_gateway.policy_middleware.current_mcp_identity", return_value=None
    ):
        result = await mcp.call_tool("run_command", {"command": "sha256sum evidence/force-added.bin"})

    assert ran is False
    assert service.reconciled == [gateway.active_case_service.case.case_id]
    assert service.observations == ["evidence/force-added.bin"]
    assert "secret bytes" not in json.dumps(result.model_dump(mode="json"), default=str)
    after = planted.stat()
    assert planted.read_bytes() == b"secret bytes"
    assert (before.st_mode, before.st_uid, before.st_gid, before.st_nlink) == (
        after.st_mode,
        after.st_uid,
        after.st_gid,
        after.st_nlink,
    )


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

    opened = {"blocked": False, "status": ChainStatus.OK, "issues": [], "manifest_version": 4}
    with patch("sift_gateway.policy_middleware.check_evidence_gate_db", return_value=opened), patch(
        "sift_gateway.policy_middleware.current_mcp_identity", return_value=None
    ):
        result = await mcp.call_tool("run_command", {"command": "cat evidence/unregistered.raw"})

    assert ran is False
    assert service.resolved == [(gateway.active_case_service.case.case_id, "evidence/unregistered.raw")]
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
async def test_sync_mutation_operands_never_reach_tool_or_change_file(tmp_path, command):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    target = evidence / "unregistered.raw"
    target.write_bytes(b"original")
    before = target.stat()
    service = _AdmissionService(reject=True)
    gateway = _gateway(tmp_path, service)
    mcp = FastMCP("aggregate", middleware=gateway_policy_middlewares(gateway))
    ran = False

    @mcp.tool(name="run_command")
    async def run_command(command: str):
        nonlocal ran
        ran = True
        return command

    opened = {"blocked": False, "status": ChainStatus.OK, "issues": [], "manifest_version": 4}
    with patch("sift_gateway.policy_middleware.check_evidence_gate_db", return_value=opened), patch(
        "sift_gateway.policy_middleware.current_mcp_identity", return_value=None
    ):
        await mcp.call_tool("run_command", {"command": command})

    after = target.stat()
    assert ran is False
    assert target.read_bytes() == b"original"
    assert (before.st_mode, before.st_uid, before.st_gid, before.st_nlink) == (
        after.st_mode,
        after.st_uid,
        after.st_gid,
        after.st_nlink,
    )


@pytest.mark.asyncio
async def test_authenticated_catalog_has_no_custody_mutation_tools(tmp_path):
    from sift_gateway.mcp_server import create_gateway_mcp_server

    (tmp_path / "evidence").mkdir()
    mcp = create_gateway_mcp_server(_gateway(tmp_path, _AdmissionService()), api_keys={})
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


class _Cursor:
    def __init__(self, row):
        self.row = row

    def execute(self, _sql, _params):
        return None

    def fetchall(self):
        return [self.row]

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


def test_inventory_reconciliation_does_not_hash_large_unchanged_sibling(tmp_path, monkeypatch):
    case_dir = tmp_path / "case"
    evidence = case_dir / "evidence"
    evidence.mkdir(parents=True)
    image = evidence / "large.E01"
    with image.open("wb") as handle:
        handle.truncate(19 * 1024 * 1024 * 1024)
    future = datetime.now(timezone.utc) + timedelta(seconds=5)
    row = ("ev-1", "evidence/large.E01", "sha256:" + "a" * 64, image.stat().st_size, future)
    service = EvidenceAuthorityService("postgresql://unused")
    monkeypatch.setattr(service, "_case_artifact_path", lambda _case_id: case_dir)
    monkeypatch.setattr(service, "_connect", lambda: _Connection(row))
    monkeypatch.setattr(
        "sift_gateway.portal_services._hash_admission_file",
        lambda _path: pytest.fail("aggregate inventory scan must not hash sealed siblings"),
    )

    result = service.reconcile_for_admission("11111111-1111-1111-1111-111111111111")
    assert result == {"observed": 1, "issues": []}
    assert image.stat().st_size == 19 * 1024 * 1024 * 1024
