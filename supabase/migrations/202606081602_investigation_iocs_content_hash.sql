-- BATCH-K2 fixup: keep IOC authority rows hash-guarded like findings/timeline.
--
-- app.investigation_store approves and reports IOC rows through the same
-- content-hash contract as findings and timeline events. The initial metadata
-- migration created content_hash on findings/timeline but not IOCs; this
-- additive migration aligns the live/fresh schema without changing row data.

alter table app.investigation_iocs
  add column if not exists content_hash text null;

comment on column app.investigation_iocs.content_hash is
  'Content hash recorded at human approval for DB-authority report verification.';
