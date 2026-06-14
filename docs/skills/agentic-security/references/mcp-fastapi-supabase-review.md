# MCP, FastAPI, Supabase, and OpenSearch review checklist

## MCP and FastMCP tools

- [ ] Each tool has a stable name, narrow description, typed input schema, typed output schema, risk tier, owner, and audit category.
- [ ] Descriptions are instruction-neutral. They do not contain hidden instructions, policy overrides, examples that encourage unsafe behavior, or secrets.
- [ ] Tool results are structured and include source/provenance. Free-text results are clearly marked as untrusted evidence content.
- [ ] Tool invocation passes through a central policy or intent gate before execution.
- [ ] High-risk tools require explicit approval with exact arguments shown to the human.
- [ ] Tools cannot call other tools recursively without a depth and budget limit.
- [ ] Tool errors do not leak secrets, stack traces, absolute sensitive paths, tokens, or service-role keys.

## FastAPI and gateway layer

- [ ] All routes that expose case, evidence, job, or tool data require authentication dependency.
- [ ] Authorization is enforced per route and per action, not only in the UI.
- [ ] Pydantic models validate path, case ID, tool args, query bounds, and enum values.
- [ ] CORS is not wildcarded for credentialed routes.
- [ ] Request IDs, actor IDs, case IDs, and audit IDs are propagated.
- [ ] Rate limits exist for search, parser, command, and tool endpoints.
- [ ] Streaming/SSE/WebSocket events validate session and authorization on every connection and sensitive event.

## Supabase/Postgres

- [ ] RLS is enabled on every case-scoped table exposed to client or agent contexts.
- [ ] Policies filter on `case_id` and membership/role, not only `auth.uid()` alone.
- [ ] Inserts and updates use `WITH CHECK` policies that prevent cross-case writes.
- [ ] Service-role key is only used in trusted backend/worker contexts and never shipped to UI or model.
- [ ] Functions using `SECURITY DEFINER` set `search_path` safely and validate caller authority.
- [ ] Job claims use row locks or atomic status transitions to prevent duplicate execution.
- [ ] Audit events are append-only and include previous hash or event chain where practical.

## OpenSearch

- [ ] All index names, aliases, queries, and vector searches are case-scoped or tenant-scoped.
- [ ] Search builder enforces `case_id` filters even when the model asks broad questions.
- [ ] Query DSL is not accepted raw from the model or user without allowlisting.
- [ ] Query timeouts, size limits, highlight limits, and result caps are enforced.
- [ ] Scripts, painless queries, or dynamic templates are disabled unless explicitly reviewed.
- [ ] Documents contain provenance: evidence hash, parser version, source path, ingest job ID, trust level.
- [ ] OpenSearch credentials are not default `admin/admin` outside local demo mode.
- [ ] TLS/cert verification is enabled outside local demo mode.

## Worker runtime

- [ ] Jobs include `case_id`, `artifact_id`, input hash, tool/parser version, actor ID, and policy decision ID.
- [ ] Worker validates authorization independently; it does not trust job rows blindly.
- [ ] Parsers run with timeouts, output size limits, and restricted filesystem access.
- [ ] Job retries are bounded; dead-letter jobs are visible in UI.
- [ ] Worker writes derived artifacts rather than mutating raw evidence.
