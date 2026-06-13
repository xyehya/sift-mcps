# Case Directory Layout & Audit Authority (Operator Reference)

What every file and folder under a case directory is, who writes it, and whether
it is **authoritative** or a **non-authoritative mirror/export**. For the
system-wide authority table (every mutable fact → its single source of truth)
see [`state-authority-map.md`](./state-authority-map.md); this document is the
case-directory-scoped companion and does not restate that table.

## Authority model in one paragraph

In DB-active deployments the **Supabase/Postgres control plane is the sole
authority** for case state. The files under a case directory fall into three
classes: (1) **evidence bytes** (operator-owned, sealed, the only file class that
is itself primary data); (2) **working data** the agent/tools produce
(`agent/`, `tmp/`, `extractions/`, `reports/`); and (3) **mirrors/exports** of
DB-authoritative state (`CASE.yaml`, `findings.json`, `evidence-ledger.jsonl`,
`audit/*.jsonl`, …) kept for offline proof and legacy fallback. A mirror is never
read as truth when the control plane is reachable.

## Directory tree (live)

```
<case>/
├── CASE.yaml                 # case header — mirror of app.cases / app.active_case_state
├── findings.json             # mirror of app.investigation_findings
├── timeline.json             # mirror of app.investigation_timeline_events
├── iocs.json                 # mirror of app.investigation_iocs
├── todos.json                # mirror of app.investigation_todos
├── evidence.json             # mirror of app.evidence_objects
├── evidence/                 # SEALED evidence bytes (operator-owned, read-only after seal)
├── extractions/              # tool-extracted artifacts (indexed copy is DB-authoritative)
├── reports/                  # generated report exports (PDF/MD)
├── tmp/                      # ephemeral tool scratch
│   ├── cache/                #   tool caches
│   ├── home/                 #   per-run HOME for tools that need one
│   └── vol-symbols/          #   Volatility3 symbol cache
├── agent/                    # agent working dir (tool output spillage)
│   ├── outputs/              #   named saved outputs
│   └── run_commands/         #   per-run_command output dirs (one dir per call)
└── audit/                    # legacy per-MCP JSONL audit mirror (empty in DB-active mode)
```

`_CASE_SUBDIRS` (the canonical subdir set the core creates) is
`{evidence, extractions, reports, tmp, agent}` — see
`packages/sift-core/src/sift_core/case_io.py`. `audit/` is created by the legacy
file-audit path and stays empty when the DB is the audit authority.

## Per-directory roles

| Dir | Written by | Authority | Notes |
|---|---|---|---|
| `evidence/` | Operator (mount/copy on the SIFT VM) | **File = primary data** | Sealed; made read-only (`0444` / immutable) at seal. Must be registered + sealed + chain-OK before any agent tool runs. |
| `extractions/` | Ingest adapters / tools | DB (`app.opensearch_indices`) for the indexed copy | On-disk extraction is working data; the searchable copy lives in OpenSearch. |
| `reports/` | Portal reporting | File = export | Generated artifacts only; report *contents/approvals* are DB-authoritative. |
| `tmp/` | Core tools | Ephemeral | Safe to purge between runs. `vol-symbols/` is a shared Volatility cache. |
| `agent/` | Gateway/core tools | Working data | `run_commands/<id>/` holds per-call stdout when `save_output:true`; large output spills here and the tool returns a path + hash, not the bytes. |
| `audit/` | Legacy file audit | **Mirror only** (empty in DB-active) | See "Audit trail" below — `app.audit_events` is authoritative. |

## Per-file roles (metadata mirrors & exports)

| File | Authority (DB) | Class |
|---|---|---|
| `CASE.yaml` | `app.cases`, `app.active_case_state` | mirror / legacy fallback |
| `findings.json` | `app.investigation_findings` (`content_hash`) | mirror |
| `timeline.json` | `app.investigation_timeline_events` | mirror |
| `iocs.json` | `app.investigation_iocs` | mirror |
| `todos.json` | `app.investigation_todos` | mirror |
| `evidence.json` | `app.evidence_objects` | mirror |
| `evidence-manifest.json` *(on export)* | `app.evidence_objects` / `app.evidence_versions` | export/proof |
| `evidence-ledger.jsonl` *(on export)* | `app.evidence_custody_events` (append-only hash chain) | export/proof |
| `approvals.jsonl` *(legacy)* | `app.investigation_*` approvals + `app.approval_commit_events` | proof; no longer a write authority |
| `audit/*.jsonl` | `app.audit_events` | mirror (empty in DB-active) |

Load/save helpers: `packages/sift-core/src/sift_core/case_io.py`.

## Audit trail (authoritative: `app.audit_events`)

Every MCP tool call is recorded in `app.audit_events` by the gateway envelope
middleware (`AuditEnvelopeMiddleware`, source `gateway_mcp_envelope`) — one
`mcp.tool.call` (pre-dispatch) and one `mcp.tool.result` (post-dispatch) row per
call, for **core and add-on (proxied) tools alike**. The columns carry identity /
access / outcome (`actor_*`, `case_id`, `event_type`, `status`, `summary`,
`created_at`, `job_id`, `request_id`); the per-call *detail* lives in `details`
(jsonb), shaped by `source`/phase:

| Row | `details` keys (high level) |
|---|---|
| `mcp.tool.call` (requested) | `tool`, `backend`, `principal`, `principal_type`, `role`, `token_id`, `case_key`, `source_ip`, **`arguments`** (redacted + bounded) |
| `mcp.tool.result` (success/failure) | `tool`, `backend`, `status`, `elapsed_ms`, `backend_audit_id`, `envelope_event_id`, **`result_summary`** (bounded); for `run_command` also **`detail`** = `provenance` (input/output `sha256`s, `evidence_refs`), `stages`/`failed_stages`, `privilege_escalation`, `exit_code` |

**Redaction is mandatory and reuses the gateway response-guard primitives**
(`redact_structured` + `redact_paths_structured`, then bounding): no JWT, DSN,
service key, password, or full case/evidence/mount/state absolute path is stored
in `details`; in-case absolute paths collapse to relative display paths; values
are size-bounded with truncation markers. See
`packages/sift-gateway/src/sift_gateway/audit_helpers.py`.

The older per-MCP file ledger (`audit/<mcp>.jsonl`, `sift_common.audit`) is a
**mirror only**: in DB-active mode `AuditWriter.log()` is a no-op success, so a
tool no longer emits a misleading "Audit write failed — action not recorded"
warning when the authoritative envelope record was written.

## Approval-commit ledger (authoritative: `app.approval_commit_events`)

The post-approval commit ledger — which records, per approved finding/timeline/
IOC item, a tamper-evident event bound to the item's DB `content_hash` at the
moment of operator approval — is **DB-only**. It is an append-only, per-case
SHA-256 **hash chain** (`prev_hash`/`event_hash`), with the chain tip in
`app.approval_commit_heads`, appended atomically by the SECURITY DEFINER RPC
`app.approval_append_commit_event(...)`, and made immutable by an append-only
trigger that blocks `UPDATE`/`DELETE`. This mirrors the locked evidence custody
chain (`app.evidence_custody_events`) and provides equivalent tamper-evidence
**without a secret key**. Migration:
`supabase/migrations/202606141200_approval_ledger_db.sql`.

This **retires** the former file HMAC verification ledger at
`/var/lib/sift/verification/{case_id}.jsonl` (`sift_core.verification.
write_ledger_entry` + `compute_hmac`, deleted). A pre-existing legacy `.jsonl`
may still be copied into a backup as a read-only artifact, but it is no longer a
write authority. (Keyed-MAC detached verification by a party who does not trust
the DB remains an open operator fork — not implemented here.)

## Quick rule of thumb

- Need the truth? Read the **DB**.
- Holding court-facing proof? Use the **export** files (evidence manifest/ledger,
  report exports) — they are signed/hash-chained snapshots of DB authority.
- A case file disagrees with the DB? The **DB wins**; the file is a stale mirror.
- The only files that are themselves primary data are the **sealed evidence
  bytes** under `evidence/`.
