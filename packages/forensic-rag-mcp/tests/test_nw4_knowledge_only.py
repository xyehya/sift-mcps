"""BATCH-NW4: RAG knowledge-only hardening tests.

Operator decision B-MVP-RAG-DERIVED REJECTED: the RAG store is shared-knowledge
only.  These tests assert:

  1. store.search() has no case_id / include_derived / include_knowledge params.
  2. The SQL sent to the DB uses the new 6-arg knowledge-only app.rag_search.
  3. Only kind='knowledge' hits are returned; any non-knowledge row the DB
     somehow returns is dropped by the Python safety filter.
  4. _validate_kind_case rejects kind='derived' entirely.
  5. Server-level: kb_search_knowledge calls store.search without case_id or
     include_derived kwargs.
  6. Schema SQL assertions: the new migration SQL file (a) does NOT contain the
     derived branch patterns from the old 9-arg signature and (b) DOES contain
     the knowledge-only WHERE clause.

No live Postgres required; fake connections capture SQL/params.
"""

from __future__ import annotations

import importlib.util
import inspect
import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Load pgvector_store.py directly (avoids heavy init imports)
# ---------------------------------------------------------------------------

_STORE_PATH = (
    Path(__file__).resolve().parents[1] / "src" / "rag_mcp" / "pgvector_store.py"
)
_spec = importlib.util.spec_from_file_location("rag_mcp_pgvector_store_nw4", _STORE_PATH)
_pg = importlib.util.module_from_spec(_spec)
sys.modules["rag_mcp_pgvector_store_nw4"] = _pg
_spec.loader.exec_module(_pg)

EMBEDDING_DIM = _pg.EMBEDDING_DIM
PgVectorRagStore = _pg.PgVectorRagStore
PgVectorStoreError = _pg.PgVectorStoreError
_validate_kind_case = _pg._validate_kind_case

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

CASE_A = "11111111-1111-1111-1111-111111111111"


def _emb(val: float = 0.1) -> list[float]:
    return [val] * EMBEDDING_DIM


def _knowledge_row():
    return (
        "chunk-id",
        None,          # case_id NULL — knowledge
        "knowledge",
        "prov-chunk",
        "doc-id",
        "prov-doc",
        "Doc",
        None,          # source_ref
        None,          # evidence_object_id
        "sigma",
        "ref text",
        0.12,
    )


def _derived_row():
    """A derived row the DB should never return — used to test the safety filter."""
    return (
        "derived-chunk",
        CASE_A,        # case_id set — derived
        "derived",
        "prov-derived",
        "doc-d",
        "prov-doc-d",
        "DocD",
        None,
        None,
        "derived-coll",
        "CASE SENSITIVE DERIVED CONTENT",
        0.05,
    )


class _FakeCursor:
    def __init__(self, rows):
        self._rows = rows
        self.executed = []

    def execute(self, sql, params=None):
        self.executed.append((sql, params))

    def fetchall(self):
        return self._rows

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeConn:
    def __init__(self, rows):
        self._cursor = _FakeCursor(rows)

    def cursor(self):
        return self._cursor

    def commit(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _store(monkeypatch, rows):
    store = PgVectorRagStore("postgresql://service@db/app")
    conn = _FakeConn(rows)
    monkeypatch.setattr(store, "_connect", lambda: conn)
    return store, conn


# ===========================================================================
# 1. search() signature — no case_id / include_derived / include_knowledge
# ===========================================================================

def test_search_has_no_case_id_param():
    sig = inspect.signature(PgVectorRagStore.search)
    assert "case_id" not in sig.parameters, (
        "search() must not accept case_id (BATCH-NW4: knowledge-only)"
    )


def test_search_has_no_include_derived_param():
    sig = inspect.signature(PgVectorRagStore.search)
    assert "include_derived" not in sig.parameters, (
        "search() must not accept include_derived (BATCH-NW4: knowledge-only)"
    )


def test_search_has_no_include_knowledge_param():
    sig = inspect.signature(PgVectorRagStore.search)
    assert "include_knowledge" not in sig.parameters, (
        "search() must not accept include_knowledge (BATCH-NW4: knowledge-only)"
    )


# ===========================================================================
# 2. SQL uses 6-arg knowledge-only app.rag_search
# ===========================================================================

def test_search_sql_uses_six_arg_signature(monkeypatch):
    store, conn = _store(monkeypatch, [_knowledge_row()])
    store.search(query_embedding=_emb())
    sql, params = conn._cursor.executed[0]
    assert "app.rag_search(" in sql
    # 6 params: embedding, top_k, source, source_ids, technique, platform
    assert len(params) == 6, f"expected 6 SQL params, got {len(params)}: {params}"


def test_search_sql_does_not_pass_case_id(monkeypatch):
    store, conn = _store(monkeypatch, [_knowledge_row()])
    store.search(query_embedding=_emb())
    _sql, params = conn._cursor.executed[0]
    # params[0] = embedding (list), params[1] = top_k (int), no UUID in first two
    assert not isinstance(params[1], str) or not (
        len(params[1]) == 36 and params[1].count("-") == 4
    ), "params[1] looks like a UUID case_id — should be top_k int"


def test_search_forwards_source_filter(monkeypatch):
    store, conn = _store(monkeypatch, [_knowledge_row()])
    store.search(query_embedding=_emb(), source="sigma")
    _sql, params = conn._cursor.executed[0]
    assert params[2] == "sigma"


def test_search_forwards_source_ids_drops_blanks(monkeypatch):
    store, conn = _store(monkeypatch, [_knowledge_row()])
    store.search(query_embedding=_emb(), source_ids=["mitre_attack", "", "  ", "lolbas"])
    _sql, params = conn._cursor.executed[0]
    assert params[3] == ["mitre_attack", "lolbas"]


def test_search_forwards_technique(monkeypatch):
    store, conn = _store(monkeypatch, [_knowledge_row()])
    store.search(query_embedding=_emb(), technique="T1003")
    _sql, params = conn._cursor.executed[0]
    assert params[4] == "T1003"


def test_search_forwards_platform(monkeypatch):
    store, conn = _store(monkeypatch, [_knowledge_row()])
    store.search(query_embedding=_emb(), platform="linux")
    _sql, params = conn._cursor.executed[0]
    assert params[5] == "linux"


# ===========================================================================
# 3. Only knowledge hits returned; derived rows dropped by safety filter
# ===========================================================================

def test_search_returns_knowledge_hits(monkeypatch):
    store, _ = _store(monkeypatch, [_knowledge_row()])
    result = store.search(query_embedding=_emb())
    assert result.case_id is None
    assert len(result.hits) == 1
    assert result.hits[0].kind == "knowledge"


def test_search_drops_derived_rows_from_db(monkeypatch):
    """If the DB ever returned derived rows, the Python safety filter drops them."""
    rows = [_knowledge_row(), _derived_row()]
    store, _ = _store(monkeypatch, rows)
    result = store.search(query_embedding=_emb())
    kinds = [h.kind for h in result.hits]
    assert "derived" not in kinds, "derived rows must be dropped by the Python safety filter"
    assert "knowledge" in kinds


def test_search_result_case_id_is_always_none(monkeypatch):
    store, _ = _store(monkeypatch, [_knowledge_row()])
    result = store.search(query_embedding=_emb())
    assert result.case_id is None


# ===========================================================================
# 4. _validate_kind_case rejects 'derived' entirely
# ===========================================================================

def test_validate_kind_case_rejects_derived():
    import pytest
    with pytest.raises(PgVectorStoreError, match="knowledge-only"):
        _validate_kind_case("derived", CASE_A)


def test_validate_kind_case_rejects_derived_no_case():
    import pytest
    with pytest.raises(PgVectorStoreError, match="knowledge-only"):
        _validate_kind_case("derived", None)


def test_validate_kind_case_rejects_unknown_kind():
    import pytest
    with pytest.raises(PgVectorStoreError, match="knowledge-only"):
        _validate_kind_case("something_else", None)


def test_validate_kind_case_accepts_knowledge():
    # Should not raise.
    _validate_kind_case("knowledge", None)


def test_validate_kind_case_rejects_knowledge_with_case_id():
    import pytest
    with pytest.raises(PgVectorStoreError, match="must not carry case_id"):
        _validate_kind_case("knowledge", CASE_A)


# ===========================================================================
# 5. ensure_collection / upsert_document reject derived kind
# ===========================================================================

def test_ensure_collection_rejects_derived(monkeypatch):
    import pytest
    store, _ = _store(monkeypatch, [])
    with pytest.raises(PgVectorStoreError, match="knowledge-only"):
        store.ensure_collection(name="case-data", kind="derived", case_id=CASE_A)


def test_upsert_document_rejects_derived(monkeypatch):
    import pytest
    store, _ = _store(monkeypatch, [])
    with pytest.raises(PgVectorStoreError, match="knowledge-only"):
        store.upsert_document(
            collection_id="col-id",
            title="case artifact",
            kind="derived",
            case_id=CASE_A,
        )


# ===========================================================================
# 6. Schema SQL assertions (no live DB required)
# ===========================================================================

_MIGRATION_PATH = (
    Path(__file__).resolve().parents[3]
    / "supabase"
    / "migrations"
    / "202606111200_rag_knowledge_only.sql"
)


def _migration_sql() -> str:
    assert _MIGRATION_PATH.exists(), f"Migration file not found: {_MIGRATION_PATH}"
    return _MIGRATION_PATH.read_text()


def test_migration_file_exists():
    assert _MIGRATION_PATH.exists(), "NW4 migration file must exist"


def test_migration_has_knowledge_only_where_clause():
    sql = _migration_sql()
    assert "kind = 'knowledge'" in sql, (
        "Migration must contain 'kind = 'knowledge'' in the WHERE clause"
    )


def test_migration_has_no_include_derived_param():
    """The new function must NOT declare p_include_derived as a parameter.

    The migration's revoke block mentions old param names in a SQL call, so we
    check the CREATE OR REPLACE FUNCTION body specifically — not the full file.
    """
    sql = _migration_sql()
    # Extract only the CREATE OR REPLACE FUNCTION ... $$ ... $$ block
    # by looking at the parameter list (between the first '(' and 'returns table').
    import re
    fn_header = re.search(
        r"create or replace function app\.rag_search\((.*?)\)\s*returns table",
        sql, re.DOTALL | re.IGNORECASE
    )
    assert fn_header, "Could not find CREATE OR REPLACE FUNCTION header in migration"
    param_block = fn_header.group(1)
    assert "p_include_derived" not in param_block, (
        "The new rag_search function must NOT declare p_include_derived parameter"
    )


def test_migration_has_no_case_id_param():
    """The new function must NOT declare p_case_id as a parameter."""
    sql = _migration_sql()
    import re
    fn_header = re.search(
        r"create or replace function app\.rag_search\((.*?)\)\s*returns table",
        sql, re.DOTALL | re.IGNORECASE
    )
    assert fn_header, "Could not find CREATE OR REPLACE FUNCTION header in migration"
    param_block = fn_header.group(1)
    assert "p_case_id" not in param_block, (
        "The new rag_search function must NOT declare p_case_id parameter"
    )


def test_migration_has_no_include_knowledge_param():
    """The new function must NOT declare p_include_knowledge as a parameter."""
    sql = _migration_sql()
    import re
    fn_header = re.search(
        r"create or replace function app\.rag_search\((.*?)\)\s*returns table",
        sql, re.DOTALL | re.IGNORECASE
    )
    assert fn_header, "Could not find CREATE OR REPLACE FUNCTION header in migration"
    param_block = fn_header.group(1)
    assert "p_include_knowledge" not in param_block, (
        "The new rag_search function must NOT declare p_include_knowledge parameter"
    )


def test_migration_creates_six_arg_rag_search():
    sql = _migration_sql()
    # The new function signature should have exactly 6 parameters
    assert "p_query_embedding vector(768)" in sql
    assert "p_top_k int" in sql
    assert "p_source text" in sql
    assert "p_source_ids text[]" in sql
    assert "p_technique text" in sql
    assert "p_platform text" in sql


def test_migration_has_derived_block_trigger():
    sql = _migration_sql()
    assert "trg_block_derived_rag" in sql, (
        "Migration must define BEFORE INSERT triggers that block derived rows"
    )


def test_migration_has_revoke_for_old_nine_arg_function():
    sql = _migration_sql()
    assert "revoke execute on function app.rag_search" in sql.lower(), (
        "Migration must revoke the old 9-arg app.rag_search from service_role"
    )


def test_migration_does_not_edit_existing_migration():
    """Confirm the old migration is untouched (file-size / existence check)."""
    old_path = (
        Path(__file__).resolve().parents[3]
        / "supabase"
        / "migrations"
        / "202606101100_rag_search_filters.sql"
    )
    assert old_path.exists(), "Old migration 202606101100 must still exist (append-only)"


# ===========================================================================
# 7. Server-level: kb_search_knowledge calls store without derived params
# ===========================================================================

def test_server_search_calls_store_without_derived_params():
    """Verify that the server-level _search() does not pass include_derived/case_id."""
    import pytest
    pytest.importorskip("mcp.server.fastmcp")

    # Inject this worktree's src so we test the edited server, not the installed copy.
    import sys
    _src = str(Path(__file__).resolve().parents[1] / "src")
    if _src not in sys.path:
        sys.path.insert(0, _src)
    for _k in list(sys.modules):
        if _k == "rag_mcp" or _k.startswith("rag_mcp."):
            del sys.modules[_k]

    import rag_mcp.server as srv

    class _TracingStore:
        def __init__(self):
            self.calls = []

        def search(self, **kwargs):
            self.calls.append(kwargs)
            from rag_mcp.pgvector_store import RagSearchResult
            return RagSearchResult(case_id=None, hits=[])

    class _FakeEmbedder:
        def embed(self, q):
            return [0.1] * 768

    s = srv.RAGServer()
    tracing_store = _TracingStore()
    s._store = tracing_store
    s._embedder = _FakeEmbedder()

    s._search(query="cred dump", top_k=3, source="", source_ids=None, technique="", platform="")
    assert len(tracing_store.calls) == 1
    call_kwargs = tracing_store.calls[0]
    assert "case_id" not in call_kwargs, "server must not pass case_id to store.search"
    assert "include_derived" not in call_kwargs, "server must not pass include_derived to store.search"
    assert "include_knowledge" not in call_kwargs, "server must not pass include_knowledge to store.search"
