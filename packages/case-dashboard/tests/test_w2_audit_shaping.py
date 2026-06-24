"""W2 — per-tier shaping of the finding audit trail (routes.get_audit_for_finding).

The DB-mode /api/audit/{finding_id} projection must shape rows by
event_type/source into the top-level fields the AuditTrailPanel reads
(tool / params / result_summary), one branch per tier:

- gateway (source == "gateway_mcp_envelope"): UNCHANGED — tool/params(arguments)/
  result_summary(dict + exit_code) still project (regression guard).
- shell (source == "shell_self_report" / finding.supporting_command): project
  details.command + details.purpose into params.
- ingest (event_type == "opensearch.ingest.artifact"): result_summary is a
  STRING — must NOT crash dict("<string>") (the panel-poisoning 500); project the
  string through and the structured context (tool/run_id/mcp_name/hostname/
  index_name) into params.

Worktree-source proof: test_w2_routes_module_is_worktree_source asserts the
imported routes module resolves under this worktree (not an installed copy), so
green here proves the edited file.
"""

from __future__ import annotations

import inspect
import secrets

from _supabase_reauth_harness import ReauthFakeSupabaseAuth, set_operator_session
from case_dashboard.routes import create_dashboard_v2_app
from starlette.testclient import TestClient

_SECRET = secrets.token_hex(32)
_CASE_ID = "33333333-3333-3333-3333-333333333333"


class FakeActiveCases:
    class _Case:
        def as_dict(self):
            return {"case_id": _CASE_ID, "name": "W2"}

    def get_active_case(self, principal=None):
        return self._Case()


class FakeInvestigationDB:
    """Returns one finding citing three ids — one per tier — and an
    audit_events catalog mirroring the real per-tier DB row shapes."""

    def list_findings(self, case_id):
        return [
            {
                "id": "F-tiers",
                "status": "APPROVED",
                "audit_ids": ["evt-gw", "evt-shell", "evt-ingest"],
                "artifacts": [],
            }
        ]

    def audit_events(self, case_id, audit_ids):
        catalog = {
            # Gateway tier — dict result_summary + paired-call arguments + detail.
            "evt-gw": {
                "id": "evt-gw",
                "audit_id": "evt-gw",
                "event_type": "mcp.tool.result",
                "source": "gateway_mcp_envelope",
                "arguments": {"command": "fls -r image.E01", "purpose": "list files"},
                "details": {
                    "tool": "run_command",
                    "result_summary": {"ok": True},
                    "detail": {"exit_code": 0, "output_file": "agent/out.txt"},
                },
            },
            # Shell tier — command + purpose, no top-level tool/params.
            "evt-shell": {
                "id": "evt-shell",
                "audit_id": "evt-shell",
                "event_type": "finding.supporting_command",
                "source": "shell_self_report",
                "details": {
                    "backend_audit_id": "shell-exam-20260624-001",
                    "command": "grep -i rdp connections.log",
                    "purpose": "confirm inbound RDP",
                },
            },
            # Ingest tier — STRING result_summary (the 500 trigger) + context.
            "evt-ingest": {
                "id": "evt-ingest",
                "audit_id": "evt-ingest",
                "event_type": "opensearch.ingest.artifact",
                "source": "opensearch-ingest",
                "details": {
                    "backend_audit_id": "opensearchingest123-sift-service-x",
                    "tool": "ingest_evtx",
                    "run_id": "run-42",
                    "mcp_name": "opensearch-mcp",
                    "hostname": "WIN-DC01",
                    "index_name": "evtx-2026",
                    "result_summary": "1280 events indexed",
                },
            },
        }
        return [catalog[i] for i in audit_ids if i in catalog]

    def audit_events_recent(self, case_id, *, limit=30):
        return []


def _client(inv):
    app = create_dashboard_v2_app(
        session_secret=_SECRET,
        active_case_service=FakeActiveCases(),
        investigation_service=inv,
        supabase_auth=ReauthFakeSupabaseAuth(),
    )
    c = TestClient(app)
    set_operator_session(c, _SECRET)
    return c


def _by_id(events):
    return {e["audit_id"]: e for e in events}


def test_w2_routes_module_is_worktree_source():
    import case_dashboard.routes as r

    path = inspect.getfile(r)
    assert "/.claude/worktrees/portal-v3-p0-foundation/" in path, path
    assert path.endswith("packages/case-dashboard/src/case_dashboard/routes.py"), path


def test_w2_endpoint_returns_200_not_500_for_ingest_row():
    # Regression: a STRING details.result_summary used to crash dict("<string>")
    # → the whole /audit response 500'd → the panel dead-ended for every id.
    resp = _client(FakeInvestigationDB()).get("/api/audit/F-tiers")
    assert resp.status_code == 200


def test_w2_gateway_tier_unchanged():
    events = _by_id(_client(FakeInvestigationDB()).get("/api/audit/F-tiers").json())
    gw = events["evt-gw"]
    assert gw["tool"] == "run_command"
    # params come from the paired-call arguments.
    assert gw["params"] == {"command": "fls -r image.E01", "purpose": "list files"}
    # dict result_summary merged with detail's exit_code/output_file.
    assert gw["result_summary"]["ok"] is True
    assert gw["result_summary"]["exit_code"] == 0
    assert gw["result_summary"]["output_file"] == "agent/out.txt"


def test_w2_shell_tier_projects_command_and_purpose():
    events = _by_id(_client(FakeInvestigationDB()).get("/api/audit/F-tiers").json())
    sh = events["evt-shell"]
    assert sh["params"]["command"] == "grep -i rdp connections.log"
    assert sh["params"]["purpose"] == "confirm inbound RDP"


def test_w2_ingest_tier_projects_context_and_string_summary():
    events = _by_id(_client(FakeInvestigationDB()).get("/api/audit/F-tiers").json())
    ing = events["evt-ingest"]
    # String result_summary carried through verbatim (frontend renders strings).
    assert ing["result_summary"] == "1280 events indexed"
    # Structured context projected into params.
    assert ing["params"]["tool"] == "ingest_evtx"
    assert ing["params"]["run_id"] == "run-42"
    assert ing["params"]["mcp_name"] == "opensearch-mcp"
    assert ing["params"]["hostname"] == "WIN-DC01"
    assert ing["params"]["index_name"] == "evtx-2026"
    # Tool name projected to top level too.
    assert ing["tool"] == "ingest_evtx"
