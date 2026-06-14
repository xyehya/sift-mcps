-- OpenSearch worker decoupling (feat/opensearch-workers)
-- ---------------------------------------------------------------------------
-- Realtime per-job / per-worker status for the dedicated OpenSearch ingest
-- workers. The decoupled ingest pipeline runs as durable ``ingest``/``enrich``
-- jobs claimed by N parallel ``sift-opensearch-worker@`` units (FOR UPDATE SKIP
-- LOCKED). The agent polls ``job_status`` for live progress, so the sanitized
-- read model must surface:
--   * which worker currently holds the job (a non-sensitive liveness LABEL,
--     e.g. ``osw-1-ab12cd``), so the operator/agent can see N-way parallelism
--     and that a long ingest is actually being worked, not stuck; and
--   * the latest step (phase name + status + path-free detail counts such as
--     indexed docs / hosts complete / hayabusa alerts) so progress is visible
--     without waiting for the terminal result_public.
--
-- This is a DELIBERATE, scoped widening of ``app.job_status_public``: the prior
-- contract excluded ``worker_id`` as a "lease internal". The worker LABEL is not
-- a secret (no host path, no DSN, no token) and ``current_step.detail`` is
-- written only by handlers that persist sanitized, path-free counts. Both new
-- columns are appended (CREATE OR REPLACE VIEW keeps the existing column order).
-- The Gateway adapter (sift_gateway/jobs.py) still returns an explicit
-- allow-list, so this view change cannot silently widen the agent surface beyond
-- the two fields added to that allow-list in the same change.

create or replace view app.job_status_public as
select
  j.id as job_id,
  j.job_type,
  j.status,
  j.case_id,
  j.evidence_id,
  j.priority,
  j.attempts,
  j.max_attempts,
  j.spec_public,
  j.result_public,
  j.error_summary,
  j.provenance_id,
  j.created_at,
  j.started_at,
  j.finished_at,
  j.updated_at,
  (select count(*) from app.job_steps s where s.job_id = j.id) as step_count,
  (select count(*) from app.job_steps s where s.job_id = j.id and s.status = 'succeeded') as steps_succeeded,
  -- Non-sensitive worker liveness label; null when the job is not currently
  -- leased (queued or terminal). Cleared by complete_job/fail_job.
  j.worker_id as worker_label,
  -- Latest step for realtime progress (path-free detail by handler contract).
  (
    select jsonb_build_object(
             'step_index', s.step_index,
             'name', s.name,
             'status', s.status,
             'detail', s.detail,
             'updated_at', s.updated_at
           )
    from app.job_steps s
    where s.job_id = j.id
    order by s.step_index desc, s.updated_at desc
    limit 1
  ) as current_step
from app.jobs j;
