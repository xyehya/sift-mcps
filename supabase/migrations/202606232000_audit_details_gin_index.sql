-- §9.8 (D2): GIN index on app.audit_events(details) to accelerate the
-- §9.6 superset resolver.  The resolver matches 6 predicates against details
-- jsonb fields (backend_audit_id, audit_aliases, envelope_event_id, audit_id)
-- which are seq-scan-ish without an index on large cases.
--
-- jsonb_path_ops supports @>, @?, and @@ operators only — adequate for the
-- resolver's ->> equality and ?| containment checks via GIN partial scans.
-- For completeness we also add an expression index on the two most-queried
-- scalar fields so equality scans on large tables stay fast.
--
-- Note: migrations run inside a transaction — CONCURRENTLY is not allowed.
-- All statements use IF NOT EXISTS for idempotency.

-- Primary GIN index: covers ?| (audit_aliases containment) and most ->> scans.
create index if not exists audit_events_details_gin
    on app.audit_events
    using gin (details jsonb_path_ops);

-- Expression index on backend_audit_id for direct equality lookups.
create index if not exists audit_events_backend_audit_id_idx
    on app.audit_events
    ((details->>'backend_audit_id'))
    where details->>'backend_audit_id' is not null;

-- Expression index on envelope_event_id (links result→call rows).
create index if not exists audit_events_envelope_event_id_idx
    on app.audit_events
    ((details->>'envelope_event_id'))
    where details->>'envelope_event_id' is not null;
