-- BATCH-K2 binding: core investigation DB authority cutover.
--
-- 202606081500_report_metadata.sql introduced app.investigation_findings,
-- app.investigation_timeline_events, app.investigation_iocs, and
-- app.investigation_todos as the read model / transition target. K2 promotes
-- those tables to authority for DB-active cases:
--
--   * a monotonic `version` column gives the portal/store an optimistic lock so a
--     stale approve/edit (raced against another writer) is rejected instead of
--     silently clobbering newer content;
--   * `reauth_audit_event_id` records the operator re-auth audit event that
--     authorized an approval/rejection/edit, so human decisions are provenance
--     linked in the same row (AGENTS.md: sensitive human actions require re-auth);
--   * `app.investigation_human_locked(status)` is the canonical predicate for
--     "an agent may not overwrite this row" (approved or rejected by a human).
--
-- This migration is additive. Existing rows default to version 1 and a null
-- re-auth id. The JSON case files (findings.json/timeline.json/iocs.json/
-- approvals.jsonl) are bridge/export artifacts only in DB-active mode.

create schema if not exists app;

alter table app.investigation_findings
  add column if not exists version integer not null default 1,
  add column if not exists reauth_audit_event_id uuid null
    references app.audit_events(id) on delete set null;

alter table app.investigation_timeline_events
  add column if not exists version integer not null default 1,
  add column if not exists reauth_audit_event_id uuid null
    references app.audit_events(id) on delete set null;

alter table app.investigation_iocs
  add column if not exists version integer not null default 1,
  add column if not exists reauth_audit_event_id uuid null
    references app.audit_events(id) on delete set null;

alter table app.investigation_todos
  add column if not exists version integer not null default 1;

-- Canonical "human decision is final" predicate. Agents (and artifact sync) must
-- not downgrade or overwrite a row a human has approved or rejected.
create or replace function app.investigation_human_locked(p_status text)
  returns boolean
  language sql
  immutable
as $$
  select upper(coalesce(p_status, '')) in ('APPROVED', 'REJECTED');
$$;

comment on function app.investigation_human_locked(text) is
  'True when an investigation row status is a final human decision (APPROVED/REJECTED) that agents and artifact sync must not overwrite.';

comment on column app.investigation_findings.version is
  'Optimistic-lock counter; bumped on every authoritative mutation. Approval/edit transitions pass the observed version and fail closed on a stale value.';
comment on column app.investigation_findings.reauth_audit_event_id is
  'Audit event id of the operator re-auth that authorized the latest approve/reject/edit transition.';
comment on column app.investigation_timeline_events.version is
  'Optimistic-lock counter for timeline event authority mutations.';
comment on column app.investigation_iocs.version is
  'Optimistic-lock counter for IOC authority mutations.';
comment on column app.investigation_todos.version is
  'Optimistic-lock counter for TODO authority mutations.';
