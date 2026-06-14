"""B-MVP-030: FK guard for ``audit_events.actor_token_id``.

``_resolve_db_token_id`` (formerly ``_legacy_token_id``) is a correctness guard:
a Supabase JWT principal reuses its principal row id as ``Identity.token_id`` for
FastMCP client attribution, but that id is NOT an ``app.mcp_tokens`` row. Writing
it to ``audit_events.actor_token_id`` would violate the foreign key. These tests
assert such a principal id resolves to None and never lands in the actor_token_id
column / the audit insert.
"""

from __future__ import annotations

from sift_gateway.audit_helpers import (
    DbAuditWriter,
    _actor_columns,
    _resolve_db_token_id,
)
from sift_gateway.identity import Identity


_SUPABASE_PRINCIPAL_ID = "33333333-3333-3333-3333-333333333333"


def _supabase_identity() -> Identity:
    """A Supabase-style agent principal whose token_id == principal_id."""
    return Identity(
        principal="hermes",
        principal_type="agent",
        token_id=_SUPABASE_PRINCIPAL_ID,  # reuses the principal row id
        agent_id="agent-1",
        created_by=None,
        role="agent",
        source_ip="127.0.0.1",
        auth_surface="mcp",
        tool_scopes=frozenset({"mcp:*"}),
        principal_id=_SUPABASE_PRINCIPAL_ID,
    )


def test_supabase_principal_id_resolves_to_none():
    # token_id matching the principal id is a Supabase principal, not an
    # mcp_tokens row -> must be dropped to protect the FK.
    assert _resolve_db_token_id(_SUPABASE_PRINCIPAL_ID, _SUPABASE_PRINCIPAL_ID) is None


def test_supabase_principal_token_not_in_actor_columns():
    _, _, _, _, token_id = _actor_columns(_supabase_identity())
    assert token_id is None


class _RecordingCursor:
    def __init__(self, store):
        self.store = store

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params):
        self.store["sql"] = sql
        self.store["params"] = list(params)

    def fetchone(self):
        return ("audit-id-1",)


class _RecordingConn:
    def __init__(self, store):
        self.store = store

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def cursor(self):
        return _RecordingCursor(self.store)

    def commit(self):
        self.store["committed"] = True


def test_supabase_principal_id_never_persisted_as_actor_token_id():
    """End-to-end through DbAuditWriter: the principal id must not appear in the
    insert column list or values for actor_token_id."""
    store: dict = {}
    writer = DbAuditWriter(connect=lambda: _RecordingConn(store))

    eid = writer.record(
        event_type="mcp.tool.call",
        actor=_supabase_identity(),
        case_id="11111111-1111-1111-1111-111111111111",
        source="gateway_mcp_envelope",
        status="requested",
    )

    assert eid == "audit-id-1"
    # actor_token_id column is omitted entirely (token_id resolved to None)...
    assert "actor_token_id" not in store["sql"]
    # ...and the Supabase principal id never appears among the inserted values.
    assert _SUPABASE_PRINCIPAL_ID not in store["params"]
    # the agent_id (the legitimate attribution) is still recorded.
    assert "agent-1" in store["params"]
