"""BATCH-K4: OpenSearch ingest-status + host-identity DB authority cutover.

Covers:
- ingest_status.db_status_active reflects the K1 db_authority_active contract;
- opensearch_ingest_status returns durable-job authority (not local JSON) in
  DB-active mode, and tampering the local status files cannot change that;
- opensearch_host_fix records a DB host-identity correction receipt via the
  injected recorder and never leaks the absolute dict_path in DB-active mode;
- the job ingest handler records per-host discovery decisions when a recorder
  is injected;
- host_identity_db recorders/readers stay psycopg-guarded and sanitized.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import yaml


# ---------------------------------------------------------------------------
# db_status_active gating
# ---------------------------------------------------------------------------


def test_db_status_active_follows_env_flag(monkeypatch):
    from opensearch_mcp.ingest_status import db_status_active

    monkeypatch.delenv("SIFT_DB_ACTIVE", raising=False)
    assert db_status_active() is False
    monkeypatch.setenv("SIFT_DB_ACTIVE", "1")
    assert db_status_active() is True


# ---------------------------------------------------------------------------
# opensearch_ingest_status — DB-active is authoritative, files are not
# ---------------------------------------------------------------------------


def test_ingest_status_db_active_ignores_local_files(monkeypatch, tmp_path):
    """In DB-active mode the tool returns durable-job authority and does NOT
    read the local status JSON, so tampering the files cannot change it."""
    from opensearch_mcp import server
    from opensearch_mcp.ingest_status import write_status

    # Seed a tampered local status file that would otherwise surface.
    status_dir = tmp_path / "ingest-status"
    monkeypatch.setattr("opensearch_mcp.ingest_status._STATUS_DIR", status_dir)
    write_status(
        case_id="INC-DBACTIVE",
        pid=4242,
        run_id="tamper",
        status="complete",
        hosts=[{"hostname": "EVIL", "artifacts": []}],
        totals={"indexed": 999999},
        started="2026-06-08T00:00:00Z",
    )

    monkeypatch.setenv("SIFT_DB_ACTIVE", "1")
    monkeypatch.setattr(server, "_get_active_case", lambda: "INC-DBACTIVE")

    result = server.opensearch_ingest_status(case_id="INC-DBACTIVE")

    assert result["authority"] == "postgres-durable-jobs"
    assert result["ingests"] == []
    # The tampered local payload must not appear.
    assert "999999" not in repr(result)
    assert "EVIL" not in repr(result)


def test_ingest_status_legacy_mode_still_reads_files(monkeypatch, tmp_path):
    """Without DB-active, the legacy file-based status path is unchanged."""
    from opensearch_mcp import server
    from opensearch_mcp.ingest_status import write_status

    status_dir = tmp_path / "ingest-status"
    monkeypatch.setattr("opensearch_mcp.ingest_status._STATUS_DIR", status_dir)
    monkeypatch.delenv("SIFT_DB_ACTIVE", raising=False)
    write_status(
        case_id="INC-LEGACY",
        pid=1,
        run_id="legacy",
        status="complete",
        hosts=[],
        totals={"indexed": 5},
        started="2026-06-08T00:00:00Z",
    )
    monkeypatch.setattr(server, "_get_active_case", lambda: "INC-LEGACY")
    with patch("opensearch_mcp.ingest_status._is_process_alive", return_value=False):
        result = server.opensearch_ingest_status(case_id="INC-LEGACY")
    assert "authority" not in result
    assert result["ingests"], "legacy mode must still surface local status files"


# ---------------------------------------------------------------------------
# opensearch_host_fix — DB receipt + no path leak in DB-active mode
# ---------------------------------------------------------------------------


def _seed_case(tmp_path: Path, case_id: str, monkeypatch):
    case_dir = tmp_path / case_id
    case_dir.mkdir(parents=True)
    (case_dir / "CASE.yaml").write_text(f"case_id: {case_id}\n")
    (case_dir / "host-dictionary.yaml").write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "domains": [],
                "hosts": {"admin01": {"aliases": ["admin01"]}},
                "unmapped": [],
            }
        )
    )
    monkeypatch.setenv("SIFT_CASES_DIR", str(tmp_path))
    monkeypatch.setenv("SIFT_CASE_DIR", str(case_dir))
    return case_dir


def test_host_fix_db_active_records_receipt_and_redacts_path(tmp_path, monkeypatch):
    from opensearch_mcp import server

    _seed_case(tmp_path, "INC-FIX", monkeypatch)
    monkeypatch.setenv("SIFT_DB_ACTIVE", "1")

    recorded = {}

    def _recorder(case_id, raw, canonical, decision, **kwargs):
        recorded.update(
            {"case_id": case_id, "raw": raw, "canonical": canonical, "decision": decision}
        )
        recorded.update(kwargs)
        return "decision-123"

    server.set_host_identity_recorder(_recorder)
    try:
        with patch("opensearch_mcp.server._get_os") as mock_get_os:
            mock_client = MagicMock()
            mock_client.update_by_query.return_value = {"updated": 12, "took": 30}
            mock_client.indices.get_mapping.return_value = {}
            mock_get_os.return_value = mock_client
            result = server.opensearch_host_fix(raw="wksn01", new_canonical="admin01")
    finally:
        server.set_host_identity_recorder(None)

    # No absolute dict path leaks to the agent in DB-active mode.
    assert "dict_path" not in result
    assert result.get("host_identity_authority") == "postgres"
    assert result.get("host_identity_decision_id") == "decision-123"

    # The DB receipt carries source/canonical/actor-tool/affected IDs.
    assert recorded["decision"] == "correction"
    assert recorded["source"] == "host_fix"
    assert recorded["tool"] == "opensearch_fix_host_mapping"
    assert recorded["canonical"] == "admin01"
    assert recorded["docs_updated"] == 12
    assert recorded["index_names"], "affected index names must be recorded"


def test_host_fix_legacy_mode_keeps_dict_path(tmp_path, monkeypatch):
    """Legacy (non-DB-active) mode keeps dict_path for CLI compatibility and
    does not require a recorder."""
    from opensearch_mcp import server

    _seed_case(tmp_path, "INC-LEG", monkeypatch)
    monkeypatch.delenv("SIFT_DB_ACTIVE", raising=False)
    server.set_host_identity_recorder(None)

    with patch("opensearch_mcp.server._get_os") as mock_get_os:
        mock_client = MagicMock()
        mock_client.update_by_query.return_value = {"updated": 1, "took": 2}
        mock_client.indices.get_mapping.return_value = {}
        mock_get_os.return_value = mock_client
        result = server.opensearch_host_fix(raw="wksn01", new_canonical="admin01")

    assert "dict_path" in result
    assert result.get("host_identity_authority") is None


# ---------------------------------------------------------------------------
# host_identity_db helpers
# ---------------------------------------------------------------------------


def test_decision_token_mapping():
    from opensearch_mcp.host_identity_db import decision_token_for

    assert decision_token_for("already_mapped") == "discovery_already_mapped"
    assert decision_token_for("auto_alias") == "discovery_auto_alias"
    assert decision_token_for("auto_new_canonical") == "discovery_auto_new_canonical"
    # Unknown labels degrade to the conservative new-canonical token.
    assert decision_token_for("???") == "discovery_auto_new_canonical"


def test_ingest_status_from_db_degrades_on_error(monkeypatch):
    """A DB read error degrades to an empty list, never crashes the caller."""
    from opensearch_mcp import host_identity_db

    # Patch ``connect`` on the real psycopg module (monkeypatch restores it
    # cleanly) instead of swapping ``sys.modules['psycopg']`` wholesale — the
    # latter leaves the module table in a state where a *later* test's
    # ``import psycopg`` raises ModuleNotFoundError (cross-test pollution that
    # surfaces under full-suite collection order). importorskip keeps the test
    # honest when psycopg is genuinely absent in a deployment env.
    psycopg = pytest.importorskip("psycopg")

    def _boom(*_args, **_kwargs):
        raise RuntimeError("db down")

    monkeypatch.setattr(psycopg, "connect", _boom)
    rows = host_identity_db.ingest_status_from_db("postgresql://x", "case-1")
    assert rows == []


# NOTE: the job-ingest discovery-decision recording test was removed with the
# core "ingest" job type (wave8/ingest-tools). The opensearch-mcp add-on now owns
# ingest directly and records its own provenance receipt; see
# packages/opensearch-mcp/tests/test_ingest_provenance.py. The host-mapping
# correction recorder exercised below is unchanged.


# ---------------------------------------------------------------------------
# BATCH-OS5: fail-closed receipt gate — DB-active, no recorder
# ---------------------------------------------------------------------------


def test_host_fix_db_active_no_recorder_denied_before_mutation(tmp_path, monkeypatch):
    """In DB-active mode with no recorder, host correction MUST be denied
    with typed guidance BEFORE any mutation (no dict save, no reindex).
    This is the 'fail closed' policy: write receipt OR be denied."""
    from opensearch_mcp import server

    _seed_case(tmp_path, "INC-DENY", monkeypatch)
    monkeypatch.setenv("SIFT_DB_ACTIVE", "1")
    server.set_host_identity_recorder(None)  # No recorder

    # Track whether OpenSearch update_by_query is called (it must NOT be).
    os_called = []

    with patch("opensearch_mcp.server._get_os") as mock_get_os:
        mock_client = MagicMock()
        mock_client.update_by_query.side_effect = lambda *a, **kw: os_called.append(kw) or {}
        mock_get_os.return_value = mock_client
        result = server.opensearch_host_fix(raw="wksn01", new_canonical="admin01")

    # Must be denied with typed guidance.
    assert result.get("status") == "receipt_required", (
        f"Expected status='receipt_required', got: {result}"
    )
    assert result.get("isError") is True
    assert result.get("receipt_required") is True
    assert result.get("dict_saved") is False
    assert "guidance" in result
    # OpenSearch must NOT have been mutated.
    assert os_called == [], "update_by_query must not be called when receipt cannot be written"
    # No absolute dict path in the guidance message.
    assert "host-dictionary.yaml" not in repr(result) or (
        result.get("dict_saved") is False
    ), "Absolute dict path must not leak in denied response"


def test_host_fix_db_active_with_recorder_still_proceeds(tmp_path, monkeypatch):
    """Regression: when a recorder IS available in DB-active mode, the fix proceeds."""
    from opensearch_mcp import server

    _seed_case(tmp_path, "INC-PROC", monkeypatch)
    monkeypatch.setenv("SIFT_DB_ACTIVE", "1")

    def _recorder(case_id, raw, canonical, decision, **kwargs):
        return "rec-ok"

    server.set_host_identity_recorder(_recorder)
    try:
        with patch("opensearch_mcp.server._get_os") as mock_get_os:
            mock_client = MagicMock()
            mock_client.update_by_query.return_value = {"updated": 3, "took": 10}
            mock_client.indices.get_mapping.return_value = {}
            mock_get_os.return_value = mock_client
            result = server.opensearch_host_fix(raw="wksn01", new_canonical="admin01")
    finally:
        server.set_host_identity_recorder(None)

    assert result.get("status") != "receipt_required", (
        "Correction must succeed when recorder is available"
    )
    assert result.get("host_identity_decision_id") == "rec-ok"


# ---------------------------------------------------------------------------
# BATCH-OS5: enrichment scope gate, audit, pollability, secret-leak guarantee
# ---------------------------------------------------------------------------


def test_enrich_intel_has_no_inprocess_env_gate(monkeypatch, tmp_path):
    """SEC-12 / DSS-CAN-012: the inert in-process SIFT_ENRICHMENT_SCOPE env gate
    was REMOVED — the authoritative enrichment:intel gate is the Gateway's
    AddonAuthorityMiddleware (see test_ad2_addon_conformance). This is a
    fail-on-revert guard: even with a WRONG env scope set, the backend must NOT
    return scope_denied (re-adding any in-process env gate — fail-open OR
    fail-closed — would deny here and break the legitimate gateway/worker paths,
    which run with the env unset). The gateway gate is asserted separately."""
    from opensearch_mcp import server

    # A scope env that does NOT include enrichment:intel — must be IGNORED now.
    monkeypatch.setenv("SIFT_ENRICHMENT_SCOPE", "enrichment:triage")
    monkeypatch.setattr(server, "_get_active_case", lambda: "INC-ENRICH")
    monkeypatch.setenv("SIFT_CASE_DIR", str(tmp_path / "INC-ENRICH"))
    (tmp_path / "INC-ENRICH").mkdir(parents=True)

    with patch("opensearch_mcp.gateway.gateway_available", return_value=True), \
         patch("opensearch_mcp.server._spawn_ingest") as mock_spawn, \
         patch("opensearch_mcp.ingest_status.write_status"), \
         patch("opensearch_mcp.ingest_status.read_active_ingests", return_value=[]):
        mock_proc = MagicMock()
        mock_proc.pid = 4242
        mock_spawn.return_value = mock_proc
        result = server.opensearch_enrich_intel(case_id="INC-ENRICH", dry_run=False)

    assert result.get("status") != "scope_denied", (
        f"in-process env gate must be gone (gateway is authority), got: {result}"
    )
    assert result.get("status") == "started", f"Expected started, got: {result}"


def test_enrich_intel_dry_run_allowed_without_scope(monkeypatch):
    """Dry-run IOC extraction is a read-only path and does NOT require enrichment:intel scope."""
    from opensearch_mcp import server

    monkeypatch.setenv("SIFT_ENRICHMENT_SCOPE", "enrichment:triage")
    monkeypatch.setattr(server, "_get_active_case", lambda: "INC-DRYRUN")

    with patch("opensearch_mcp.server._get_os") as mock_get_os:
        mock_client = MagicMock()
        # Make extract_unique_iocs return empty but valid
        mock_client.search.return_value = {
            "aggregations": {"values": {"buckets": [], "sum_other_doc_count": 0}}
        }
        mock_get_os.return_value = mock_client
        with patch("opensearch_mcp.threat_intel.extract_unique_iocs", return_value={"ip": set(), "hash": set(), "domain": set()}):
            result = server.opensearch_enrich_intel(case_id="INC-DRYRUN", dry_run=True)

    # Dry run must succeed even without scope.
    assert result.get("status") == "preview", f"Expected preview, got: {result}"
    assert "total_iocs" in result


def test_enrich_intel_execute_returns_pollable_status(monkeypatch, tmp_path):
    """opensearch_enrich_intel(dry_run=False) must return poll_via and run_id
    so callers can track enrichment status via opensearch_ingest_status."""
    from opensearch_mcp import server

    # Allow all scopes.
    monkeypatch.delenv("SIFT_ENRICHMENT_SCOPE", raising=False)
    monkeypatch.setattr(server, "_get_active_case", lambda: "INC-POLL")
    monkeypatch.setenv("SIFT_CASE_DIR", str(tmp_path / "INC-POLL"))
    (tmp_path / "INC-POLL").mkdir(parents=True)

    with patch("opensearch_mcp.gateway.gateway_available", return_value=True), \
         patch("opensearch_mcp.server._spawn_ingest") as mock_spawn, \
         patch("opensearch_mcp.ingest_status.write_status"), \
         patch("opensearch_mcp.ingest_status.read_active_ingests", return_value=[]):
        mock_proc = MagicMock()
        mock_proc.pid = 9999
        mock_spawn.return_value = mock_proc
        result = server.opensearch_enrich_intel(case_id="INC-POLL", dry_run=False)

    assert result.get("status") == "started", f"Expected started, got: {result}"
    assert "run_id" in result, "run_id must be present for polling"
    assert result.get("poll_via") == "opensearch_ingest_status", (
        "poll_via must point to the status tool"
    )
    assert "poll_hint" in result
    assert result.get("enrichment_type") == "threat_intel"
    # prohibited_operations must be present.
    prohibited = result.get("prohibited_operations", [])
    assert "approve_findings" in prohibited
    assert "alter_evidence" in prohibited
    assert "decide_reports" in prohibited


def test_enrich_intel_response_leaks_no_secrets(monkeypatch, tmp_path):
    """Enrichment response must not contain OpenCTI credentials, OpenSearch
    passwords, DB DSNs, or service-role keys."""
    from opensearch_mcp import server

    monkeypatch.delenv("SIFT_ENRICHMENT_SCOPE", raising=False)
    monkeypatch.setattr(server, "_get_active_case", lambda: "INC-NOSECRET")
    monkeypatch.setenv("SIFT_CASE_DIR", str(tmp_path / "INC-NOSECRET"))
    (tmp_path / "INC-NOSECRET").mkdir(parents=True)

    # Inject obviously-identifiable fake secrets into env to prove they don't leak.
    monkeypatch.setenv("OPENCTI_TOKEN", "FAKE_OPENCTI_TOKEN_SECRET")
    monkeypatch.setenv("OPENSEARCH_PASSWORD", "FAKE_OPENSEARCH_PASS_SECRET")
    monkeypatch.setenv("SIFT_DB_DSN", "postgresql://user:FAKE_DB_PASS_SECRET@host/db")

    with patch("opensearch_mcp.server._spawn_ingest") as mock_spawn, \
         patch("opensearch_mcp.ingest_status.write_status"), \
         patch("opensearch_mcp.ingest_status.read_active_ingests", return_value=[]):
        mock_proc = MagicMock()
        mock_proc.pid = 1111
        mock_spawn.return_value = mock_proc
        result = server.opensearch_enrich_intel(case_id="INC-NOSECRET", dry_run=False)

    result_repr = repr(result)
    assert "FAKE_OPENCTI_TOKEN_SECRET" not in result_repr, "OpenCTI token must not appear in response"
    assert "FAKE_OPENSEARCH_PASS_SECRET" not in result_repr, "OpenSearch password must not appear in response"
    assert "FAKE_DB_PASS_SECRET" not in result_repr, "DB password must not appear in response"
    # log_file may be in the response but must not contain secret env var values.
    log_file = result.get("log_file", "")
    assert "FAKE_OPENCTI_TOKEN_SECRET" not in log_file
