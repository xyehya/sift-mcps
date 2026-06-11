-- BATCH-NW4: RAG store is SHARED-KNOWLEDGE ONLY.
--
-- Operator decision B-MVP-RAG-DERIVED REJECTED: there must be NO per-case RAG.
-- Case-sensitive derived text must NEVER enter or exit the vector store (privacy /
-- leak prevention).  The RAG store is SHARED-KNOWLEDGE ONLY from this migration
-- forward.
--
-- What this migration does (append-only, does NOT touch prior migrations):
--
--   1. Replaces app.rag_search with a knowledge-only variant that:
--      - Drops the p_include_knowledge / p_include_derived / p_case_id
--        parameters (no caller can request derived content).
--      - Hard-codes kind = 'knowledge' in the WHERE clause — no derived path
--        exists in the SQL, not even behind a dead flag.
--      - Retains the source / source_ids / technique / platform filters
--        (knowledge corpus filters, unchanged semantics).
--      - Returns the same column set so the Python adapter (_row_to_hit) still
--        maps cleanly; case_id / evidence_object_id will always be NULL for
--        knowledge rows.
--
--   2. Revokes execute on the OLD 9-arg signature and grants execute on the NEW
--      6-arg signature to service_role (both wrapped in role-existence guards).
--
--   3. Adds a database-level policy that makes it impossible to INSERT a
--      kind='derived' row into rag_collections, rag_documents, or rag_chunks
--      even via a direct Postgres connection (belt-and-suspenders; the Python
--      layer also rejects derived kind after this migration).
--      Note: We cannot add CHECK constraints if the tables already have 'derived'
--      rows from prior test runs, so we use a BEFORE INSERT trigger instead.
--      The trigger raises an exception so the INSERT is aborted cleanly.
--
-- This migration is APPEND-ONLY. It does NOT edit 202606081400_rag_pgvector.sql
-- or 202606101100_rag_search_filters.sql.

create schema if not exists app;

-- ---------------------------------------------------------------------------
-- 1. knowledge-only app.rag_search (6 args; removes case_id / include_* params)
-- ---------------------------------------------------------------------------

create or replace function app.rag_search(
  p_query_embedding vector(768),
  p_top_k int default 5,
  p_source text default null,
  p_source_ids text[] default null,
  p_technique text default null,
  p_platform text default null
)
returns table (
  chunk_id uuid,
  case_id uuid,
  kind text,
  provenance_id uuid,
  document_id uuid,
  document_provenance_id uuid,
  document_title text,
  source_ref text,
  evidence_object_id uuid,
  collection_name text,
  content text,
  distance double precision
)
language sql
stable
as $$
  select
    p.chunk_id,
    p.case_id,
    p.kind,
    p.provenance_id,
    p.document_id,
    p.document_provenance_id,
    p.document_title,
    p.source_ref,
    p.evidence_object_id,
    p.collection_name,
    p.content,
    (ch.embedding <=> p_query_embedding)::double precision as distance
  from app.rag_chunk_public p
  join app.rag_chunks ch on ch.id = p.chunk_id
  where ch.embedding is not null
    -- KNOWLEDGE ONLY — no derived branch exists in this function.
    and p.kind = 'knowledge'
    -- source_ids (exact) takes precedence over source (substring).
    and (
      p_source_ids is null
      or coalesce(ch.metadata->>'source', '') = any (p_source_ids)
    )
    and (
      p_source_ids is not null
      or p_source is null
      or lower(coalesce(ch.metadata->>'source', '')) like '%' || lower(p_source) || '%'
      or lower(p_source) like '%' || lower(coalesce(ch.metadata->>'source', '')) || '%'
    )
    and (
      p_technique is null
      or upper(coalesce(ch.metadata->>'mitre_techniques', '')) like '%' || upper(p_technique) || '%'
    )
    and (
      p_platform is null
      or lower(coalesce(ch.metadata->>'platform', '')) like '%' || lower(p_platform) || '%'
    )
  order by ch.embedding <=> p_query_embedding
  limit greatest(1, least(coalesce(p_top_k, 5), 50));
$$;

comment on function app.rag_search(vector, int, text, text[], text, text) is
  'BATCH-NW4 knowledge-only RAG retrieval (B-MVP-RAG-DERIVED REJECTED). '
  'Returns ONLY kind=''knowledge'' shared-reference chunks — no derived case '
  'data is reachable. Supports source / source_ids / technique / platform '
  'filters on the chunk metadata jsonb. Output is provenance-linked and path-free.';

-- ---------------------------------------------------------------------------
-- 2. Grant / revoke (role-existence guards)
-- ---------------------------------------------------------------------------

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'service_role') then
    -- Grant new 6-arg signature.
    grant execute on function app.rag_search(
      vector, int, text, text[], text, text
    ) to service_role;

    -- Revoke old 9-arg signature that carried case/derived params.
    -- (The old function still exists as a separate overload; revoking its
    -- execute right ensures service_role cannot call the derived-capable path.)
    begin
      revoke execute on function app.rag_search(
        vector, uuid, int, boolean, boolean, text, text[], text, text
      ) from service_role;
    exception when undefined_function then
      -- Old overload may not exist (clean install); ignore.
      null;
    end;
  end if;
end
$$;

-- ---------------------------------------------------------------------------
-- 3. Block derived inserts at the DB level via BEFORE INSERT triggers
-- ---------------------------------------------------------------------------
-- These triggers fire before any INSERT that sets kind='derived' on the three
-- RAG tables, raising an exception.  They complement (not replace) the Python-
-- layer guard (_validate_kind_case raises PgVectorStoreError for 'derived').

create or replace function app._block_derived_rag_insert()
returns trigger
language plpgsql
as $$
begin
  if NEW.kind = 'derived' then
    raise exception
      'BATCH-NW4: derived RAG data is rejected (B-MVP-RAG-DERIVED REJECTED). '
      'The RAG store is shared-knowledge only. kind=''derived'' inserts are '
      'blocked at the database level.';
  end if;
  return NEW;
end;
$$;

comment on function app._block_derived_rag_insert() is
  'BATCH-NW4: trigger function that rejects INSERT of kind=''derived'' rows on '
  'all RAG tables.  Enforces the B-MVP-RAG-DERIVED REJECTED privacy decision at '
  'the database level.';

-- rag_collections
do $$
begin
  if not exists (
    select 1 from pg_trigger
    where tgname = 'trg_block_derived_rag_collections'
      and tgrelid = 'app.rag_collections'::regclass
  ) then
    create trigger trg_block_derived_rag_collections
      before insert on app.rag_collections
      for each row execute function app._block_derived_rag_insert();
  end if;
exception when undefined_table then null;
end
$$;

-- rag_documents
do $$
begin
  if not exists (
    select 1 from pg_trigger
    where tgname = 'trg_block_derived_rag_documents'
      and tgrelid = 'app.rag_documents'::regclass
  ) then
    create trigger trg_block_derived_rag_documents
      before insert on app.rag_documents
      for each row execute function app._block_derived_rag_insert();
  end if;
exception when undefined_table then null;
end
$$;

-- rag_chunks
do $$
begin
  if not exists (
    select 1 from pg_trigger
    where tgname = 'trg_block_derived_rag_chunks'
      and tgrelid = 'app.rag_chunks'::regclass
  ) then
    create trigger trg_block_derived_rag_chunks
      before insert on app.rag_chunks
      for each row execute function app._block_derived_rag_insert();
  end if;
exception when undefined_table then null;
end
$$;
