-- BATCH-G1: RAG pgvector target with case/provenance filters.
--
-- This migration adds the Supabase pgvector schema that is the authoritative
-- metadata + embedding store for the forensic RAG plane. It introduces:
--   - rag_collections : a named grouping of documents (knowledge OR derived).
--   - rag_documents    : one row per ingested source unit, with provenance.
--   - rag_chunks       : embeddable text chunks + pgvector embedding + provenance.
-- plus a case-scoped retrieval RPC (app.rag_search) and a sanitized public
-- read model (app.rag_chunk_public).
--
-- Authority model (Migration-Spec invariants):
--   - RAG is a DERIVED / REFERENCE plane. It has NO authority over evidence
--     seal, approvals, jobs, findings, or reports. Nothing here mutates those
--     tables; there are no transitions exposed for them.
--   - Two data classes coexist:
--       * knowledge (reference)  -> case_id IS NULL, kind = 'knowledge'.
--         Forensic methodology / cheatsheets. Read by every case, owned by none.
--       * derived (case context) -> case_id IS NOT NULL, kind = 'derived'.
--         Derived text/artifact summaries produced by parsers/enrichers for a
--         specific case. Strictly case-isolated.
--   - A retrieval query is ALWAYS bound to exactly one querying case. It returns
--     that case's derived chunks UNION the shared knowledge chunks, and can
--     NEVER return another case's derived chunks (enforced in app.rag_search and
--     by RLS).
--   - Provenance: every chunk carries an opaque provenance_id (and an optional
--     evidence_object_id link). The agent-visible output exposes provenance_id,
--     document/source labels, and the chunk text only. It NEVER exposes absolute
--     evidence/case/mount paths. Text-bearing columns reject absolute OS paths so
--     a path can never be persisted as derived RAG content.
--
-- This migration is additive, idempotent, and rollback-safe inside a
-- transaction. It stores no raw evidence bytes and no secret material.

create schema if not exists app;
create extension if not exists pgcrypto;
-- pgvector provides the `vector` type + ANN index operators. Supabase ships it
-- under the `vector` extension name.
create extension if not exists vector;

-- ---------------------------------------------------------------------------
-- 0. Embedding dimension contract
-- ---------------------------------------------------------------------------
-- The bundled embedding model (BAAI/bge-base-en-v1.5) emits 768-dim vectors.
-- The column is fixed at 768 so the ANN index and distance ops are well typed.
-- A model change that alters the dimension is a schema change (new migration),
-- never a silent drift.

-- ---------------------------------------------------------------------------
-- 1. Collections
-- ---------------------------------------------------------------------------
-- A collection groups documents. Knowledge collections (e.g. "SANS",
-- "AppliedIR") are shared reference data with case_id NULL. Derived collections
-- belong to exactly one case. `kind` and the case_id nullability are kept in
-- lockstep by a CHECK so a knowledge row can never carry a case and a derived
-- row can never be case-less.
create table if not exists app.rag_collections (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  kind text not null,
  -- NULL for shared knowledge/reference collections; set for derived/case data.
  case_id uuid null references app.cases(id) on delete cascade,
  description text null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint rag_collections_kind_check
    check (kind in ('knowledge', 'derived')),
  constraint rag_collections_name_check
    check (length(btrim(name)) > 0),
  constraint rag_collections_metadata_object_check
    check (jsonb_typeof(metadata) = 'object'),
  -- knowledge => case_id NULL ; derived => case_id NOT NULL. No mixing.
  constraint rag_collections_kind_case_check
    check (
      (kind = 'knowledge' and case_id is null)
      or (kind = 'derived' and case_id is not null)
    )
);

-- One active collection name per case scope (NULL case = shared namespace).
create unique index if not exists rag_collections_case_name_key
  on app.rag_collections (coalesce(case_id, '00000000-0000-0000-0000-000000000000'::uuid), lower(name));
create index if not exists rag_collections_case_id_idx
  on app.rag_collections (case_id);
create index if not exists rag_collections_kind_idx
  on app.rag_collections (kind);

-- ---------------------------------------------------------------------------
-- 2. Documents
-- ---------------------------------------------------------------------------
-- One row per ingested source unit (a knowledge file/source, or a derived text
-- artifact for a case). case_id is denormalized from the collection so every
-- retrieval filter and RLS check can be expressed on the document/chunk rows
-- directly. source_ref is a RELATIVE, display-only label (e.g. a knowledge
-- source name or "evidence/<id>#summary"); absolute case/mount paths are
-- rejected by a CHECK so a path can never be persisted here.
create table if not exists app.rag_documents (
  id uuid primary key default gen_random_uuid(),
  collection_id uuid not null references app.rag_collections(id) on delete cascade,
  -- Mirrors the collection's case scope; NULL = shared knowledge.
  case_id uuid null references app.cases(id) on delete cascade,
  kind text not null,
  title text not null,
  -- Stable provenance handle for the whole document (opaque, agent-safe).
  provenance_id uuid not null default gen_random_uuid(),
  -- Optional link to a sealed evidence item when the derived text was produced
  -- from evidence. This is an opaque id only; it never resolves to a path here.
  evidence_object_id uuid null references app.evidence_objects(id) on delete set null,
  -- Knowledge source label (e.g. "SANS") or relative derived ref. Never a path.
  source_ref text null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint rag_documents_kind_check
    check (kind in ('knowledge', 'derived')),
  constraint rag_documents_title_check
    check (length(btrim(title)) > 0),
  constraint rag_documents_metadata_object_check
    check (jsonb_typeof(metadata) = 'object'),
  constraint rag_documents_kind_case_check
    check (
      (kind = 'knowledge' and case_id is null)
      or (kind = 'derived' and case_id is not null)
    ),
  -- A derived document MUST NOT exist without an evidence/job provenance anchor
  -- beyond its own provenance_id is optional; the evidence link is optional, but
  -- source_ref, when present, must be relative (no absolute OS/mount path).
  constraint rag_documents_source_ref_relative_check
    check (
      source_ref is null
      or (
        left(source_ref, 1) <> '/'
        and source_ref !~ '(^|/)\.\.(/|$)'
        and source_ref !~ '^[a-zA-Z]:[\\/]'
      )
    )
);

create index if not exists rag_documents_collection_id_idx
  on app.rag_documents (collection_id);
create index if not exists rag_documents_case_id_idx
  on app.rag_documents (case_id);
create index if not exists rag_documents_provenance_id_idx
  on app.rag_documents (provenance_id);
create index if not exists rag_documents_evidence_object_id_idx
  on app.rag_documents (evidence_object_id);

-- ---------------------------------------------------------------------------
-- 3. Chunks + embeddings
-- ---------------------------------------------------------------------------
-- One row per embeddable chunk. case_id is denormalized again so the ANN scan
-- can be pre-filtered by case scope without a join. Each chunk carries a stable
-- provenance_id (defaults to the parent document's at insert time via the
-- ingest RPC) so retrieved context is always provenance-linked.
create table if not exists app.rag_chunks (
  id uuid primary key default gen_random_uuid(),
  document_id uuid not null references app.rag_documents(id) on delete cascade,
  collection_id uuid not null references app.rag_collections(id) on delete cascade,
  case_id uuid null references app.cases(id) on delete cascade,
  kind text not null,
  chunk_index int not null,
  -- Embeddable / returnable text. Reference or derived summary text only.
  content text not null,
  -- Opaque provenance handle for THIS chunk (agent-safe; never a path).
  provenance_id uuid not null,
  -- 768-dim embedding (bge-base-en-v1.5). Nullable until the embedder runs.
  embedding vector(768) null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint rag_chunks_kind_check
    check (kind in ('knowledge', 'derived')),
  constraint rag_chunks_chunk_index_check
    check (chunk_index >= 0),
  constraint rag_chunks_content_check
    check (length(btrim(content)) > 0),
  constraint rag_chunks_metadata_object_check
    check (jsonb_typeof(metadata) = 'object'),
  constraint rag_chunks_kind_case_check
    check (
      (kind = 'knowledge' and case_id is null)
      or (kind = 'derived' and case_id is not null)
    ),
  -- Derived chunk text must not embed an absolute OS/mount path. Knowledge text
  -- is curated reference material and is exempt (it legitimately contains
  -- example command paths in cheatsheets), but a case's derived text — which is
  -- the only thing that could leak a real local path — is path-guarded.
  constraint rag_chunks_derived_no_abs_path_check
    check (
      kind <> 'derived'
      or (
        content !~ '(^|\s)/(home|root|mnt|media|evidence|cases?|var|opt|srv)/'
        and content !~ '[a-zA-Z]:\\'
      )
    )
);

create unique index if not exists rag_chunks_document_chunk_key
  on app.rag_chunks (document_id, chunk_index);
create index if not exists rag_chunks_case_id_idx
  on app.rag_chunks (case_id);
create index if not exists rag_chunks_collection_id_idx
  on app.rag_chunks (collection_id);
create index if not exists rag_chunks_provenance_id_idx
  on app.rag_chunks (provenance_id);

-- ANN index for cosine similarity. IVFFlat is created opportunistically; on an
-- empty table it is still valid and is populated as rows land. Cosine ops match
-- the normalized bge embeddings used by the ingest path.
do $$
begin
  if not exists (
    select 1 from pg_indexes
    where schemaname = 'app' and indexname = 'rag_chunks_embedding_cosine_idx'
  ) then
    create index rag_chunks_embedding_cosine_idx
      on app.rag_chunks
      using ivfflat (embedding vector_cosine_ops)
      with (lists = 100);
  end if;
exception
  when others then
    -- IVFFlat may be unavailable in some minimal pgvector builds; the table and
    -- exact-scan retrieval still work without the ANN index.
    raise notice 'rag_chunks ANN index not created: %', sqlerrm;
end
$$;

-- ---------------------------------------------------------------------------
-- 4. Sanitized public read model
-- ---------------------------------------------------------------------------
-- The agent/portal-visible projection. Exposes provenance + labels + text only.
-- It deliberately omits collection internals and any raw embedding. case_id is
-- present so the Gateway can assert the scope it requested matches what it got.
create or replace view app.rag_chunk_public as
select
  ch.id as chunk_id,
  ch.case_id,
  ch.kind,
  ch.provenance_id,
  d.id as document_id,
  d.provenance_id as document_provenance_id,
  d.title as document_title,
  d.source_ref,
  d.evidence_object_id,
  c.name as collection_name,
  ch.chunk_index,
  ch.content,
  ch.metadata
from app.rag_chunks ch
join app.rag_documents d on d.id = ch.document_id
join app.rag_collections c on c.id = ch.collection_id;

comment on view app.rag_chunk_public is
  'Sanitized RAG chunk read model: provenance_id, document/collection labels, '
  'and chunk text only. No embeddings, no absolute paths. case_id is exposed so '
  'the Gateway can verify the returned scope.';

-- ---------------------------------------------------------------------------
-- 5. Ingest RPC (service-only)
-- ---------------------------------------------------------------------------
-- Upsert a chunk. The Gateway worker connects with a service DSN; agents never
-- call this directly. case_id consistency with `kind` is enforced by the table
-- CHECKs. provenance_id defaults to the document's provenance_id when omitted.
create or replace function app.rag_upsert_chunk(
  p_document_id uuid,
  p_chunk_index int,
  p_content text,
  p_embedding vector(768) default null,
  p_provenance_id uuid default null,
  p_metadata jsonb default '{}'::jsonb
)
returns uuid
language plpgsql
as $$
declare
  v_doc app.rag_documents%rowtype;
  v_chunk_id uuid;
  v_prov uuid;
begin
  select * into v_doc from app.rag_documents where id = p_document_id;
  if not found then
    raise exception 'rag_upsert_chunk: unknown document_id %', p_document_id
      using errcode = 'foreign_key_violation';
  end if;

  v_prov := coalesce(p_provenance_id, v_doc.provenance_id);

  insert into app.rag_chunks (
    document_id, collection_id, case_id, kind,
    chunk_index, content, provenance_id, embedding, metadata
  )
  values (
    v_doc.id, v_doc.collection_id, v_doc.case_id, v_doc.kind,
    p_chunk_index, p_content, v_prov, p_embedding,
    coalesce(p_metadata, '{}'::jsonb)
  )
  on conflict (document_id, chunk_index) do update
    set content = excluded.content,
        embedding = excluded.embedding,
        provenance_id = excluded.provenance_id,
        metadata = excluded.metadata
  returning id into v_chunk_id;

  return v_chunk_id;
end;
$$;

-- ---------------------------------------------------------------------------
-- 6. Case-scoped retrieval RPC (the only query surface)
-- ---------------------------------------------------------------------------
-- Returns the top-k nearest chunks for a query embedding, HARD-bound to one
-- querying case. The scope is:
--     (kind = 'knowledge')                         -- shared reference
--   UNION
--     (kind = 'derived' AND case_id = p_case_id)   -- THIS case only
-- There is no code path that returns another case's derived chunk. When
-- p_case_id is NULL, only shared knowledge is searched (no derived leakage).
-- Output is provenance-linked and path-free: it returns provenance_id,
-- document/collection labels, content, and a distance. It never returns the
-- embedding or any absolute path.
create or replace function app.rag_search(
  p_query_embedding vector(768),
  p_case_id uuid default null,
  p_top_k int default 5,
  p_include_knowledge boolean default true,
  p_include_derived boolean default true
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
  order by ch.embedding <=> p_query_embedding
  limit greatest(1, least(coalesce(p_top_k, 5), 50));
$$;

comment on function app.rag_search(vector, uuid, int, boolean, boolean) is
  'Case-scoped RAG retrieval. Returns shared knowledge chunks UNION only the '
  'querying case''s derived chunks; another case''s derived data is unreachable. '
  'Output is provenance-linked (provenance_id + document/collection labels + '
  'content) and path-free (no embedding, no absolute paths).';

-- ---------------------------------------------------------------------------
-- 7. RLS + grants
-- ---------------------------------------------------------------------------
-- Mirror the D1/D22A pattern: enable RLS, add a case-member read policy that
-- also lets every member read shared knowledge (case_id NULL). No broad direct
-- GRANT to authenticated; the Gateway/worker uses a service DSN and the portal
-- reads through the Gateway.
alter table app.rag_collections enable row level security;
alter table app.rag_documents enable row level security;
alter table app.rag_chunks enable row level security;

do $$
begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'app' and tablename = 'rag_chunks'
      and policyname = 'rag_chunks_case_member_or_knowledge_select'
  ) then
    create policy rag_chunks_case_member_or_knowledge_select
      on app.rag_chunks
      for select
      using (
        case_id is null
        or exists (
          select 1
          from app.case_members cm
          join app.operator_profiles op on op.id = cm.operator_profile_id
          where cm.case_id = app.rag_chunks.case_id
            and cm.status = 'active'
            and op.auth_user_id = auth.uid()
        )
      );
  end if;

  if not exists (
    select 1 from pg_policies
    where schemaname = 'app' and tablename = 'rag_documents'
      and policyname = 'rag_documents_case_member_or_knowledge_select'
  ) then
    create policy rag_documents_case_member_or_knowledge_select
      on app.rag_documents
      for select
      using (
        case_id is null
        or exists (
          select 1
          from app.case_members cm
          join app.operator_profiles op on op.id = cm.operator_profile_id
          where cm.case_id = app.rag_documents.case_id
            and cm.status = 'active'
            and op.auth_user_id = auth.uid()
        )
      );
  end if;

  if not exists (
    select 1 from pg_policies
    where schemaname = 'app' and tablename = 'rag_collections'
      and policyname = 'rag_collections_case_member_or_knowledge_select'
  ) then
    create policy rag_collections_case_member_or_knowledge_select
      on app.rag_collections
      for select
      using (
        case_id is null
        or exists (
          select 1
          from app.case_members cm
          join app.operator_profiles op on op.id = cm.operator_profile_id
          where cm.case_id = app.rag_collections.case_id
            and cm.status = 'active'
            and op.auth_user_id = auth.uid()
        )
      );
  end if;
end
$$;

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'service_role') then
    grant usage on schema app to service_role;
    grant select, insert, update, delete on app.rag_collections to service_role;
    grant select, insert, update, delete on app.rag_documents to service_role;
    grant select, insert, update, delete on app.rag_chunks to service_role;
    grant select on app.rag_chunk_public to service_role;
    grant execute on function app.rag_upsert_chunk(uuid, int, text, vector, uuid, jsonb) to service_role;
    grant execute on function app.rag_search(vector, uuid, int, boolean, boolean) to service_role;
  end if;
end
$$;

-- ---------------------------------------------------------------------------
-- 8. Comments (single source of fact for the schema contract)
-- ---------------------------------------------------------------------------
comment on table app.rag_collections is
  'BATCH-G1 RAG collections. kind=knowledge => shared reference (case_id NULL); '
  'kind=derived => case-owned (case_id NOT NULL). Reference plane only; no '
  'authority over evidence/approvals/reports.';
comment on table app.rag_documents is
  'RAG source documents with provenance_id and optional opaque evidence link. '
  'source_ref is a relative display label only; absolute paths are rejected.';
comment on table app.rag_chunks is
  'RAG embeddable chunks (vector(768)) with per-chunk provenance_id. Derived '
  'chunk text is path-guarded so no absolute OS/mount path is persisted. '
  'case_id is denormalized for case-scoped ANN filtering.';
comment on column app.rag_chunks.provenance_id is
  'Opaque, agent-safe provenance handle returned with retrieved context. Never '
  'an evidence/case/mount path.';
comment on function app.rag_upsert_chunk(uuid, int, text, vector, uuid, jsonb) is
  'Service-only chunk upsert. Inherits case_id/kind/collection from the parent '
  'document so a chunk can never be mis-scoped relative to its document.';
