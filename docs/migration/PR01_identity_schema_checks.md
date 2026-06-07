# PR01 Identity Schema Checks

PR01 adds the Phase ID-1 control-plane identity foundation schema only. It does
not wire Gateway token validation, Supabase Auth runtime behavior, portal auth,
active-case propagation, workers, jobs, evidence behavior, OpenSearch, parsers,
or frontend code.

## Deterministic Repo Checks

Run from the repository root:

```bash
.venv/bin/python -m pytest tests/db/test_pr01_identity_schema.py
git diff --check
```

These tests inspect the migration SQL structure directly. They are the PR01
fallback because this repository did not have an existing Supabase migration
test harness before the first identity migration.

## Optional Supabase Syntax Check

If a local self-hosted Supabase/Postgres stack is available, the migration can
be syntax-checked inside a rollback-only transaction:

```bash
(
  printf 'begin;\n'
  cat supabase/migrations/202606070101_identity_foundation.sql
  printf '\nrollback;\n'
) | docker compose exec -T db psql -U postgres -d postgres -v ON_ERROR_STOP=1
```

Run that command from the directory containing the Supabase `docker-compose.yml`.
It validates PostgreSQL/Supabase compatibility without leaving the PR01 tables
behind.
