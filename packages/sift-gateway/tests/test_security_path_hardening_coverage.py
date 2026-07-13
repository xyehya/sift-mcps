"""Fail-on-revert coverage for gateway-owned DFIR authority boundaries.

These tests deliberately exercise the small gateway seams that turn untrusted
agent input into DB-authoritative case/evidence state.  They assert observable
failure behaviour: the gateway must never silently fall back to a file manifest
or preserve a caller-controlled evidence reference when DB authority is active.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import cast

import pytest
from fastmcp.tools import ToolResult
from mcp.types import TextContent
from sift_core.execute.security_policy import (
    build_security_policy,
    load_policy_from_env,
)
from sift_gateway.active_case import ActiveCase
from sift_gateway.mcp_server import (
    _db_orientation_authority,
    _normalize_output_schema,
    _OrientationAuthorityError,
    _prepare_core_tool_arguments,
)
from sift_gateway.policy_middleware import _use_gateway_active_case
from sift_gateway.response_guard import (
    _DEFAULT_OUTPUT_CAP_BYTES,
    _content_to_jsonable,
    cap_tool_result,
    guard_tool_result,
    output_cap_bytes,
    redact_paths_structured,
    redact_structured,
)

_CASE = ActiveCase(
    case_id="11111111-1111-1111-1111-111111111111",
    case_key="case-one",
    title="Case One",
    description=None,
    status="active",
    artifact_path="/cases/case-one",
    metadata={},
)


class _EvidenceService:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def list_evidence(self, case_id):
        self.calls.append(case_id)
        return self.rows


class _Resolver:
    def __init__(self):
        self.calls = []

    def resolve_evidence_reference(self, case_id, reference):
        self.calls.append((case_id, reference))
        return {
            "evidence_id": "ev-1",
            "version_id": "ver-1",
            "display_path": "evidence/disk.E01",
            "path": "/cases/case-one/evidence/disk.E01",
            "sha256": "sha256:" + "a" * 64,
            "bytes": 4096,
            "st_dev": 1,
            "st_ino": 2,
            "st_mtime_ns": 3,
            "st_ctime_ns": 4,
            "immutable_required": True,
        }


def _gateway(*, dsn="postgresql://service@db/sift", evidence_service=None):
    return SimpleNamespace(control_plane_dsn=dsn, evidence_service=evidence_service)


def test_db_case_orientation_replaces_manifest_evidence_gate(monkeypatch):
    monkeypatch.setattr(
        "sift_gateway.evidence_gate.check_evidence_gate_db",
        lambda *_: {
            "status": SimpleNamespace(value="unsealed"),
            "blocked": True,
            "issues": ["evidence chain unsealed"],
            "manifest_version": 8,
        },
    )
    stale = json.dumps({"evidence_chain": {"status": "ok", "authority": "file"}})

    with _use_gateway_active_case(_CASE):
        result = json.loads(_db_orientation_authority(_gateway(), "case_info", stale))

    assert result["evidence_chain"] == {
        "status": "unsealed",
        "ok": False,
        "issues": ["evidence chain unsealed"],
        "manifest_version": 8,
        "authority": "db",
    }


def test_db_evidence_orientation_exposes_only_sealed_db_rows(monkeypatch):
    monkeypatch.setattr(
        "sift_gateway.evidence_gate.check_evidence_gate_db",
        lambda *_: {
            "status": SimpleNamespace(value="ok"),
            "blocked": False,
            "issues": [],
            "manifest_version": 3,
        },
    )
    service = _EvidenceService([
        {"evidence_id": "sealed", "display_name": "disk.E01", "display_path": "evidence/disk.E01", "status": "sealed", "seal_status": "sealed", "current_sha256": "a" * 64, "current_bytes": 7, "path": "/host/private"},
        {"evidence_id": "pending", "display_path": "evidence/pending.raw", "status": "registered", "seal_status": "unsealed", "path": "/host/pending"},
    ])

    with _use_gateway_active_case(_CASE):
        result = json.loads(_db_orientation_authority(_gateway(evidence_service=service), "evidence_info", "{}"))

    assert result["authority"] == "db"
    assert result["listing_authority"] == "db"
    assert result["total_evidence_files"] == 1
    assert result["unregistered_files"] == ["evidence/pending.raw"]
    assert result["evidence_files"][0]["display_path"] == "evidence/disk.E01"
    assert "path" not in result["evidence_files"][0]
    assert service.calls == [_CASE.case_id]


def test_db_orientation_fails_closed_when_evidence_service_is_unavailable(monkeypatch):
    monkeypatch.setattr(
        "sift_gateway.evidence_gate.check_evidence_gate_db",
        lambda *_: {"status": "ok", "blocked": False, "issues": [], "manifest_version": 1},
    )
    with _use_gateway_active_case(_CASE), pytest.raises(_OrientationAuthorityError):
        _db_orientation_authority(_gateway(evidence_service=None), "evidence_info", "{}")


def test_run_command_evidence_refs_are_resolved_only_by_active_case_service():
    resolver = _Resolver()
    supplied = {"evidence_refs": ["evidence/disk.E01"], "_resolved_evidence_refs": [{"path": "/attacker"}]}

    with _use_gateway_active_case(_CASE):
        prepared = _prepare_core_tool_arguments(_gateway(evidence_service=resolver), "run_command", supplied)

    assert prepared["_resolved_evidence_refs"] == [{
        "ref": "evidence/disk.E01",
        "evidence_id": "ev-1",
        "version_id": "ver-1",
        "display_path": "evidence/disk.E01",
        "path": "/cases/case-one/evidence/disk.E01",
        "sha256": "sha256:" + "a" * 64,
        "bytes": 4096,
        "st_dev": 1,
        "st_ino": 2,
        "st_mtime_ns": 3,
        "st_ctime_ns": 4,
        "immutable_required": True,
    }]
    assert resolver.calls == [(_CASE.case_id, "evidence/disk.E01")]


def test_run_command_reference_resolution_failure_is_internal_and_typed():
    class _FailingResolver:
        def resolve_evidence_reference(self, *_):
            raise RuntimeError("evidence_not_registered")

    with _use_gateway_active_case(_CASE):
        prepared = _prepare_core_tool_arguments(
            _gateway(evidence_service=_FailingResolver()),
            "run_command",
            {"evidence_refs": "evidence/unknown.E01"},
        )

    assert prepared["_evidence_ref_error"] == "evidence_not_registered"
    assert "_resolved_evidence_refs" not in prepared


def test_run_command_incomplete_authority_binding_fails_closed():
    class _IncompleteResolver:
        def resolve_evidence_reference(self, *_):
            return {
                "evidence_id": "ev-1",
                "display_path": "evidence/disk.E01",
                "path": "/cases/case-one/evidence/disk.E01",
            }

    with _use_gateway_active_case(_CASE):
        prepared = _prepare_core_tool_arguments(
            _gateway(evidence_service=_IncompleteResolver()),
            "run_command",
            {"evidence_refs": ["evidence/disk.E01"]},
        )

    assert prepared["_evidence_ref_error"] == "evidence_binding_incomplete"
    assert "_resolved_evidence_refs" not in prepared


@pytest.mark.parametrize(
    ("schema", "expected"),
    [
        ({"oneOf": [{"type": "object"}]}, {"type": "object", "oneOf": [{"type": "object"}]}),
        ({"type": "string"}, None),
    ],
)
def test_catalog_repairs_or_removes_invalid_output_schemas(schema, expected):
    tool = SimpleNamespace(outputSchema=schema)
    _normalize_output_schema(tool)
    assert tool.outputSchema == expected


def test_output_cap_uses_default_for_invalid_environment(monkeypatch):
    monkeypatch.setenv("SIFT_OUTPUT_CAP", "not-a-number")
    assert output_cap_bytes() == _DEFAULT_OUTPUT_CAP_BYTES


def test_capped_result_never_leaks_absolute_spill_path(tmp_path):
    case_dir = tmp_path / "case"
    result = ToolResult(content=[TextContent(type="text", text="x" * 100)])
    guarded, _, events = guard_tool_result(
        result,
        override_active=False,
        case_dir=str(case_dir),
        tool_name="run_command",
        cap_bytes=20,
    )

    agent_text = cast(TextContent, guarded.content[0]).text
    assert str(case_dir) not in agent_text
    assert "agent/tool_outputs/" in agent_text
    assert events and events[0]["output_file"].startswith(str(case_dir))


def test_capping_without_case_directory_does_not_claim_persistence():
    capped, meta = cap_tool_result("é" * 40, max_bytes=17, case_dir=None)
    assert "NOT persisted" in capped
    assert meta is not None
    assert meta["returned_bytes"] <= 17


def test_structured_output_depth_limit_stops_hostile_recursive_payload():
    value = {"child": {"child": {"child": "password=SuperSecretValue"}}}
    redacted, findings = redact_structured(value, _max_depth=1)
    assert redacted["child"]["child"] == "[SIFT_STRUCTURED_CONTENT_DEPTH_LIMIT]"
    assert findings == [{
        "pattern_name": "Structured Content Depth Limit",
        "severity": "medium",
        "char_offset": 0,
        "path": "$.child.child",
    }]


def test_structured_path_redaction_preserves_case_relative_paths_and_hides_host_paths(tmp_path):
    case_dir = tmp_path / "case"
    value = {"inside": str(case_dir / "evidence" / "disk.E01"), "outside": "/dev/sda"}
    redacted, findings = redact_paths_structured(value, case_dir_resolved=str(case_dir))
    assert redacted["inside"] == "evidence/disk.E01"
    assert redacted["outside"] == "[REDACTED:absolute_path]"
    assert findings[0]["path"] == "$.outside"


def test_state_directory_is_a_sensitive_path_prefix(monkeypatch):
    monkeypatch.setenv("SIFT_STATE_DIR", "/srv/sift-state")
    redacted, findings = redact_paths_structured(
        {"state": "/srv/sift-state/active-case.json"}, case_dir_resolved=None
    )
    assert redacted["state"] == "[REDACTED:absolute_path]"
    assert findings[0]["pattern_name"] == "Absolute Path"


def test_structured_tuple_values_are_recursively_redacted_with_precise_path():
    redacted, findings = redact_structured(("clean", "password=SuperSecretValue"))
    assert redacted[0] == "clean"
    assert redacted[1] == "[REDACTED:Generic Password]"
    assert findings[0]["path"] == "$[1]"


@pytest.mark.parametrize(
    "operator_policy",
    [
        "not-a-mapping",
        {"allowed_binaries": "fls"},
        {"tool_allowed_flags": ["not-a-map"]},
        {"tool_blocked_flags": {1: ["--write"]}},
        {"unlisted_policy": "permit"},
    ],
)
def test_operator_policy_malformed_security_controls_fail_closed(operator_policy):
    with pytest.raises(ValueError):
        build_security_policy(operator_policy)


def test_operator_policy_requires_an_explicit_nonempty_mapping():
    with pytest.raises(ValueError, match="required"):
        build_security_policy(None, require_operator_policy=True)
    with pytest.raises(ValueError, match="cannot be empty"):
        build_security_policy({}, require_operator_policy=True)


def test_result_serialization_handles_nontext_extension_content_safely():
    content = _content_to_jsonable(
        [SimpleNamespace(kind="image"), "legacy extension payload"]
    )
    assert content == [{"kind": "image"}, "legacy extension payload"]


def test_policy_environment_invalid_json_fails_closed(monkeypatch):
    monkeypatch.setenv("SIFT_EXECUTE_SECURITY_POLICY", "not-json")
    with pytest.raises(RuntimeError, match="invalid JSON"):
        load_policy_from_env()


def test_policy_environment_absent_does_not_invent_a_policy(monkeypatch):
    monkeypatch.delenv("SIFT_EXECUTE_SECURITY_POLICY", raising=False)
    assert load_policy_from_env() is None
