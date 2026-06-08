# SIFT MVP Sprint Claude Instructions

Follow `AGENTS.md`. This file is intentionally short so Claude sessions do not
start from duplicated or stale migration state.

Load order:

1. `docs/migration/Migration-Spec.md`
2. `docs/migration/task-batches.md`
3. `docs/migration/Session-Notes.md`
4. `AGENTS.md`

Core rules:

- Work in the active batch scope.
- Use a separate worktree for parallel implementation batches.
- Resolve dependent blockers before coding past them.
- Keep agents behind Gateway MCP and never expose absolute evidence/case paths.
- Keep Supabase/Postgres as authority and OpenSearch/RAG/add-ons as derived or
  reference planes.
- Update `Session-Notes.md`, update the batch checkbox when accepted, and run
  `python3 scripts/validate_docs.py` before landing governance/doc changes.
