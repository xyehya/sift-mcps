-- PR03B: active-case DB authority comments/helpers only.
-- No historical case data is imported by this migration.

comment on column app.cases.legacy_case_dir is
  'Optional filesystem artifact path for transition/runtime data. It is not active-case authority; app.active_case_state is authoritative.';

comment on column app.cases.legacy_case_yaml_path is
  'Optional legacy CASE.yaml artifact path. CASE.yaml is not active-case authority or metadata authority for PR03B request paths.';

comment on column app.active_case_state.compat_export_status is
  'Historical compatibility status only. PR03B does not generate active-case env, pointer, or gateway.yaml exports.';

create or replace view app.deployment_active_case as
select
  s.scope,
  s.active_case_id,
  c.case_key,
  c.title,
  c.description,
  c.status,
  c.legacy_case_dir as artifact_path,
  c.metadata,
  s.set_by_user_id,
  s.set_at,
  s.updated_at
from app.active_case_state s
left join app.cases c on c.id = s.active_case_id
where s.scope = 'deployment';

comment on view app.deployment_active_case is
  'Read helper for the single deployment active case. Authority remains app.active_case_state.';
