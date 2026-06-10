-- BATCH-OSX-RAG: extend app.rag_search with knowledge metadata filters.
--
-- OSX-RAG restores forensic-rag-mcp's ORIGINAL tool surface (kb_search_knowledge
-- with source / source_ids / technique / platform filters) on top of the BATCH-G1
-- pgvector store. Those filters operate on the per-chunk `metadata` jsonb that the
-- Chroma->pgvector importer copies 1:1 from the original release bundle
-- (keys: "source", "mitre_techniques", "platform").
--
-- This migration is APPEND-ONLY and additive. It does NOT touch the schema added
-- in 202606081400_rag_pgvector.sql; it only CREATE OR REPLACEs the app.rag_search
-- function, adding the new filter parameters with defaults so every existing
-- caller (5-arg signature) keeps working unchanged. The case-isolation contract,
-- the dormant `derived` branch, and the path-free / provenance-linked output model
-- are preserved exactly as in 202606081400.
--
-- Filter semantics mirror the original ChromaDB index.search:
--   - source     : case-insensitive bidirectional substring match on metadata->>'source'.
--   - source_ids : exact match on metadata->>'source'; takes precedence over `source`.
--   - technique  : case-insensitive substring match on metadata->>'mitre_techniques'.
--   - platform   : case-insensitive substring match on metadata->>'platform'.
-- All filters default to NULL = "no filter" (original unfiltered behavior).

create schema if not exists app;

create or replace function app.rag_search(
  p_query_embedding vector(768),
  p_case_id uuid default null,
  p_top_k int default 5,
  p_include_knowledge boolean default true,
  p_include_derived boolean default true,
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
    and (
      -- shared knowledge (case-less reference)
      (p_include_knowledge and p.kind = 'knowledge')
      or
      -- this case's derived chunks ONLY; cross-case derived is unreachable
      (p_include_derived and p.kind = 'derived'
        and p_case_id is not null and p.case_id = p_case_id)
    )
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

comment on function app.rag_search(vector, uuid, int, boolean, boolean, text, text[], text, text) is
  'BATCH-OSX-RAG case-scoped RAG retrieval with knowledge metadata filters '
  '(source / source_ids / technique / platform on the chunk metadata jsonb). '
  'Returns shared knowledge chunks UNION only the querying case''s derived chunks; '
  'another case''s derived data is unreachable. Output is provenance-linked '
  '(provenance_id + document/collection labels + content) and path-free.';

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'service_role') then
    grant execute on function app.rag_search(
      vector, uuid, int, boolean, boolean, text, text[], text, text
    ) to service_role;
  end if;
end
$$;
