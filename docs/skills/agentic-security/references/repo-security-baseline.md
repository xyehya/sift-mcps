# Repo security baseline (living)

The current, enforced security posture of Protocol SIFT Gateway, with the exact
code/migration that enforces each control. This is the **regression oracle**: a
new assessment should confirm each ENFORCED control still holds (grep the anchor)
and triage each OPEN item. When a control changes, update this file in the same
change — that is what keeps the skill "living."

How to use: for each control, (a) verify the anchor still exists and does what the
status claims, (b) flag any new code path that bypasses it, (c) move items between
ENFORCED/OPEN as the code changes. Date your edits.

Last synced: 2026-06-14.

## Legend
`✅ ENFORCED` control is live + has a code anchor (and ideally a test).
`🟡 PARTIAL` enforced in the primary path, gap in a secondary path.
`🟥 OPEN` known gap / deployment-phase / deferred.

---

## A. Policy boundary & tool surface (ASI01/ASI05/ASI06)

- ✅ Gateway is the sole policy boundary; add-on tools are proxied and subject to
  the same middleware. Anchor: `policy_middleware.py` middleware stack +
  `mcp_server.py` mount path.
- ✅ Aggregated `outputSchema` is MCP-spec compliant (root `type:object`, hoisted
  `$defs`) so a strict client loads the full surface. Anchor:
  `opensearch-mcp/registry.py:_output_schema`,
  `mcp_server.py:_normalize_output_schema`. (Regressions here silently drop the
  whole tool list — high impact, easy to reintroduce.)
- ✅ Reference-plane add-ons declared `default_case_scoped:false` so global tools
  aren't denied or mis-scoped. Anchor: `forensic-rag-mcp/sift-backend.json`,
  `server.py:is_case_scoped_tool`.
- 🟡 Add-on authority contract (prohibited_operations / required_scopes) enforced
  by `AddonAuthorityMiddleware`, but only opencti/rag exercise it; windows-triage
  unbuilt. Anchor: `policy_middleware.py`, `app.mcp_backends.authority_contract`.

## B. run_command host execution (ASI05 — highest risk)

- ✅ shell=False, single parser+policy, parsed argv executed (no parser
  differential). Anchor: `execute/security.py`, `execute/worker.py`.
- ✅ Deny-floor: interpreters (sh/bash/python/perl/ruby/node), awk
  system()/getline, pagers/editors, media-destroyers blocked. Anchor:
  `execute/security_policy.py` DENY_FLOOR.
- ✅ Path-shadow defense: resolves + executes the real binary, not a
  case-dir-planted file named after an allowed tool. Anchor: `security.py`
  (`argv[0]=resolved`).
- ✅ Privilege drop to `agent_runtime` via `sudo -n -u`; needs CAP_SETUID/SETGID/
  SETPCAP/AUDIT_WRITE in the unit `CapabilityBoundingSet` (omitting them silently
  kills run_command). Anchor: `configs/systemd/sift-gateway.service`,
  `execute/executor.py`.
- ✅ Pipes/redirects work as staged argv with per-stage exit codes (NOT a shell).
  Anchor: `execute/security.py` redirect sentinel.
- 🟥 Containment is systemd-run cgroup + rlimits only — same user/fs/net; not a
  real sandbox. bwrap/nsjail is a deployment-phase item.

## C. Evidence chain of custody (ASI09 / integrity)

- ✅ Evidence gate: every agent tool blocked unless evidence registered + sealed +
  chain OK. Anchor: `evidence_gate.py`, `policy_middleware.py`.
- ✅ Sealed evidence is filesystem-immutable: `chattr +i` (and `+a`) via
  CAP_LINUX_IMMUTABLE on the venv python; agent_runtime (no cap) cannot
  overwrite/delete it; hashing clears +i only transiently. Anchor:
  `install.sh:configure_immutable_capability`, `sift-core/evidence_chain.py`.
- ✅ Custody chain is DB-authoritative, append-only, hash-linked
  (prev_hash/event_hash) with mutation-blocking triggers + TRUNCATE guards.
  Anchor: `supabase/migrations/202606081000_evidence_custody.sql` +
  `202606141400_harden_append_only_chains.sql`.
- ✅ Content-hash authority for findings/timeline/iocs in DB; file JSON are
  mirrors. Anchor: `202606081600_investigation_authority.sql`,
  `investigation_store.compute_content_hash`.

## D. Audit trail (ASI07)

- ✅ Every tool call (core + add-on) writes mcp.tool.call + mcp.tool.result to
  `app.audit_events` (identity/access/outcome). Mutating tools fail-closed if the
  pre-dispatch audit write fails. Anchor: `policy_middleware.py
  AuditEnvelopeMiddleware`, `audit_helpers.py DbAuditWriter`.
- ✅ run_command DETAIL (command, input/output sha256, exit code, stages,
  privilege events) captured into `app.audit_events.details`, redacted+bounded.
  The legacy file ledger is retired in DB mode (no misleading warning). Anchor:
  `audit_helpers.py`, `sift-core/agent_tools.py`, `SIFT_DB_ACTIVE` in
  `control-plane.env` (set by `install.sh`).

## E. Redaction / data egress (ASI02/ASI07)

- ✅ Agent-facing output + audit details routed through `response_guard`
  redactors with `override_active=False` (operator override can't re-expose):
  secrets → `[REDACTED:...]`, sensitive abs paths → `[REDACTED:absolute_path]`,
  in-case abs paths → relative display. Then size-bounded. Anchor:
  `response_guard.py`, `audit_helpers.redact_for_audit`.
- 🟡 Dict KEYS are not redacted (only values); an attacker-controlled map key in a
  nested arg could survive into `details`. Confirm no arg schema lets secrets land
  in keys.
- 🟡 Evidence mounts outside the sensitive-prefix list (e.g. a custom mount path)
  pass unredacted — documented AUT2 autonomy tradeoff.

## F. Re-auth for sensitive actions (ASI06)

- ✅ Case activation, evidence seal/ignore/retire, finding approval, report
  include/export, agent credential issuance require Supabase password re-verify.
  Anchor: `supabase_auth._supabase_reverify`, `case-dashboard/routes.py`.
- ✅ Approval-commit ledger attests ONLY authority-approved items
  (request-approved minus skipped), binds DB content_hash + re-auth event;
  append-only hash chain, no secret key. Anchor:
  `case-dashboard/routes.py:_apply_delta_db`,
  `202606141200_approval_ledger_db.sql`.
- 🟥 Keyed-MAC detached approval-ledger verification (party that doesn't trust the
  DB) — open operator fork; not implemented.

## G. Control-plane / tenant isolation (ASI03/ASI08)

- ✅ FORCE ROW LEVEL SECURITY on the app.* tables (applies to table owner too);
  gateway service_role has BYPASSRLS, so the gateway path is unaffected but
  0-policy tables default-deny everyone else. Anchor:
  `202606131000_force_rls_app_tables.sql`.
- ✅ USAGE on schema `app` is service_role-only (public/authenticated/anon = none),
  and SECURITY DEFINER functions revoke EXECUTE from public + grant service_role.
  Anchor: `202606141400_harden_append_only_chains.sql`,
  `202606141200_approval_ledger_db.sql`. (Verify any NEW SECURITY DEFINER function
  adds the revoke — easy to forget.)
- ✅ Service-role DSN / Supabase keys backend-only in `control-plane.env`/
  `supabase.env` (0600, sift-service), referenced by env, never in gateway.yaml,
  logs, or agent output.

## H. Supply chain / deployment (ASI04/ASI10)

- ✅ Pinned + SHA-gated: uv, Hayabusa (SHA verified), BGE model
  (name+revision), OpenSearch image (digest), Supabase CLI. `SIFT_OFFLINE`
  skips fetches. Anchor: `install.sh` (HR3 block).
- ✅ auditd installed with SIFT rules; OpenSearch container CapDrop=ALL +
  no-new-privileges + digest-pinned. Anchor: `install.sh`, `docker-compose.yml`.
- 🟥 BATCH-SB1 self-managed Supabase compose (generated secrets) — required before
  any non-lab deploy; deferred.
- 🟥 AppArmor COMPLAIN-only until post-LV1 enforce pass.

---

## Quick regression sweep (run these greps on a new assessment)

- `rg "shell=True" packages/` → must be EMPTY.
- `rg -n "security definer" supabase/migrations/<new>.sql` → each must have a
  matching `revoke execute ... from public`.
- New append-only table → must have BOTH a row trigger AND a BEFORE TRUNCATE
  trigger (see control C / `202606141400`).
- `rg -n "override_active\s*=\s*True" packages/sift-gateway` → suspicious; audit
  path must use `override_active=False`.
- New add-on `sift-backend.json` → must declare `authority_contract` +
  `default_case_scoped`; reference planes set `query_only`.
- New agent-facing tool returning data → confirm it routes through
  `response_guard` redaction and caps output size.
