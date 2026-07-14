# Operator Manual

## 1. First Login

If this is your first login after installation, you have a temporary password from the installer handoff.

1. Open `https://<host>:4508/portal` in a browser.
2. Enter your email and temporary password at the login form.
   → `POST /portal/api/auth/login` (`routes.py:3852`, `post_auth_login`)
   Supabase GoTrue is the sole credential authority. On success the portal
   sets a `sift_portal_session` cookie (HMAC-SHA256 signed envelope
   containing Supabase access/refresh tokens).
3. If the login response includes `must_reset: true`, you are using a
   temporary installer password and must set a permanent one. You will be
   prompted for a new password.
   → `POST /portal/api/auth/forced-reset` (`routes.py:3798`,
   `post_supabase_forced_reset`)
   The operator status transitions from "invited" to "active" in Supabase.
4. You are now authenticated with a `sift_portal_session` cookie. The
   session has a 12-hour absolute ceiling with an 8-hour sliding window and
   transparent refresh via Supabase refresh tokens.

## 2. Create a Case

1. In the Portal, navigate to the **Cases** panel.
2. Fill in the form fields: **casename** (lowercase slug, required),
   **title** (required), and **description** (optional, max 10,000 chars).
   → `POST /portal/api/case/create` (`routes.py:4526`, `post_case_create`)
3. What happens under the hood:
   - A case directory is created under the configured cases root
     (symlink-traversal guarded — `R5` check).
   - `CASE.yaml` is written with the case metadata.
   - An `app.cases` row is inserted in Postgres (the DB authority).
   - Postgres initialises the case's version-0 evidence-chain head. Any local
     manifest or ledger material is export/compatibility output, never authority.

## 3. Activate the Case

The agent cannot work until a case is active.

1. Select the case from the case list.
2. Click **Activate**.
   → `POST /portal/api/case/activate` (`routes.py:4446`, `post_case_activate`)
3. You will be prompted to re-enter your password. This is **step-up
   re-authentication** (`_supabase_reverify` at
   `routes.py:4473`/`routes.py:4505`) — Supabase GoTrue password grant
   leaves no local file-HMAC fallback. The action **fails closed** if
   Supabase is unreachable.
4. On success, `app.active_case_state` is set. The Gateway is now scoped to
   this case. Every agent MCP tool call is gated to the active case and
   blocked if no case is active.

## 4. Mount and Register Evidence

Before the agent can investigate, evidence must be registered and sealed.
Until sealed, the `EvidenceGate` middleware blocks **all** MCP tool calls
for the case.

1. Make evidence available at `<case_dir>/evidence/`. In the Portal, authorize
   either `LOCAL_IMMUTABLE` or `EXTERNALLY_READ_ONLY` with a reason and fresh
   re-authentication. External storage must be mounted read-only; SIFT records opaque
   source and mount-instance identities and never repairs or mutates its metadata.
2. In the Portal, open the **Evidence** panel.
3. View the chain status.
   → `GET /portal/api/evidence/chain/status` (`routes.py:1010`,
   `get_evidence_chain_status`)
   The response shows:
   - `status` — one of `unsealed`, `sealed`, `ledger_error`, `violated`.
   - `issues` — tamper warnings (hash mismatch, missing/modified files).
   - `manifest_version` — current sealed manifest version.
   - `ok_count` — count of verified ACTIVE entries.
   - `unregistered` — files present on disk but not yet registered.
4. Files in `evidence/` that are not registered appear as "unregistered".
   These must be either registered (next step) or explicitly ignored.
5. If there are stray files you do not want in the evidence chain (e.g.
   `.DS_Store`, thumbnails), mark them as intentionally ignored.
   → `POST /portal/api/evidence/chain/ignore` (`routes.py:1131`,
   `post_evidence_chain_ignore`)
   Ignored entries are carried forward in future manifest versions and do
   not trigger chain violations.

## 5. Seal the Evidence Chain

Sealing commits evidence versions and custody events to Postgres and verifies the
selected storage profile.

1. In the **Evidence** panel, select the files to register and click
   **Seal**.
   → `POST /portal/api/evidence/chain/seal` (`routes.py:1040`,
   `post_evidence_chain_seal`)
2. You will be prompted to re-enter your password (step-up re-auth).
3. What happens under the hood:
   - Each descriptor-pinned file is hashed with streaming SHA-256.
   - File metadata (path, hash, size, mtime) is recorded.
   - A row is inserted into `app.evidence_objects` (Postgres DB
     authority, `202606081000_evidence_custody.sql:30`).
   - A `MANIFEST_SEALED` event is appended to `app.evidence_custody_events`
     — append-only, hash-linked, no UPDATE/DELETE (trigger-enforced,
     `202606081000_evidence_custody.sql:24`).
   - `LOCAL_IMMUTABLE` applies and reads back protected local posture.
     `EXTERNALLY_READ_ONLY` instead verifies descriptor, VFS, and mount/superblock
     read-only agreement and never changes external bytes or metadata.
   - The manifest version increments by 1. Postgres appends the custody event
     and advances the hash-linked chain from `prev_hash` to `event_hash`.
   - `app.evidence_chain_heads` is updated (gate read model).
4. After seal: the evidence gate passes and authorized MCP evidence reads become
   available for the agent.

For the first seal of an empty `EXTERNALLY_READ_ONLY` case, use this exact order:
authorize the profile, mount the source read-only, Rescan Inventory, select every
DETECTED pending object, then **Add & Seal**. Full Verify is intentionally disabled
until Manifest Version 1 exists because there is no sealed active set to verify; a
direct API attempt returns `full_verify_requires_sealed_evidence` (409) and creates no
verification receipt. The storage warning and MCP admission block remain until Add &
Seal commits the full target set atomically. A violation with prior custody authority,
an unsafe finding, a stale mount generation, or a violated object is recovery work and
must not be treated as virgin bootstrap.
Add & Seal also requires every current selected, sealed, and ignored path to remain present as a
direct regular single-link entry on the authorized source/mount. Retired historical bytes may remain
or be absent, but are never selected or added to the new receipt. Symlinks, directories, hardlinks,
unknown names, omitted required files, pathname swaps, replacements, or entries appearing during
verification keep the gate blocked and create no custody version or successful storage receipt.
Remove or disposition unsafe pending entries through the supported operator workflow, then Rescan.

If external storage disconnects, the gate reports it as unavailable rather than
tampering. Reconnecting the same authorized source requires **Full Verify Evidence**;
a different source requires an explicit re-authorized profile transition. Full Verify
is an authenticated examiner action with no password prompt: it hashes every ACTIVE
mounted object, verifies storage posture, records an append-only success/failure
receipt, and only a successful current receipt can reopen MCP admission.

> **DB authority only (C1).** Sealing requires the Postgres custody broker
> to be wired. Without it the seal returns a 404 "no case" response — there
> is no file-backed fallback.

## 6. Agent Investigation Phase

With evidence sealed, the AI agent can call the tools authorized by current policy (see
[MCP Tool Catalog](12%20-%20MCP%20Tool%20Catalog.md)). Common workflow:

- `case_info` — retrieve active case metadata and summary.
- `evidence_info` — list sealed evidence items with hashes and status.
- `opensearch_search` / `opensearch_aggregate` / `opensearch_timeline` —
  query indexed forensic data scoped to the active case.
- `run_command` — execute forensic tools inside an AppArmor-sandboxed jail.
- `record_finding` — stage a finding in DRAFT status.
- `record_timeline_event` — stage a timeline event in DRAFT status.

All tool calls are audited, redacted, and scoped to the active case. The
agent backend has **no DB credentials** — it can only write through the
Gateway's brokered paths.

## 7. Review Findings and Timeline

After the agent has staged findings and timeline events, the operator
reviews and approves or rejects each item.

1. Open the **Findings** tab to see all staged findings.
   → `GET /portal/api/findings` (`routes.py:2396`, `get_findings`)
2. Open the **Delta** panel (review queue).
   → `GET /portal/api/delta` (`routes.py:2706`, `get_delta`)
   Displays pending items from `pending-reviews.json` — findings to
   approve/reject and timeline events to review.
3. For each item, decide: **Approve**, **Reject**, or **Edit** (with
   examiner corrections to title, description, severity, or status).
4. Stage your decisions.
   → `POST /portal/api/delta` (`routes.py:3307`, `post_delta`)
   The delta body is size-limited to 1 MB (`_MAX_DELTA_SIZE`).

## 8. Apply Review Decisions

Once you have staged all your decisions, commit them to apply.

1. Click the **Commit** button.
   → `POST /portal/api/commit` (`routes.py:3526`, `post_commit`)
2. You will be prompted to re-enter your password (step-up re-auth).
   Supabase password grant is re-checked; the action fails closed if
   Supabase is unreachable (`routes.py:3558`, `_supabase_reverify`).
3. In DB-active mode, the approve/reject/edit transitions are applied to
   Postgres authority atomically with content-hash and version guards
   (`routes.py:3568`, `_apply_delta_db`). The case JSON files are **not**
   the report-eligibility authority.
4. What happens:
   - **APPROVED** findings: status → `APPROVED`, eligible for reports.
   - **REJECTED** findings: status → `REJECTED`, excluded from reports.
   - **EDITED** findings: updated with examiner corrections, content-hash
     recomputed.
   - An audit trail is appended recording who approved/rejected what and
     when.

> **Reports contain ONLY items with `status == "APPROVED"`.** DRAFT and
> REJECTED items are excluded from all report profiles. The operator
> controls what goes into the final report.

## 9. Generate Report

1. Navigate to **Reports** → **Generate**.
   → `POST /portal/api/reports/generate` (`routes.py:5155`,
   `generate_report_route`)
2. Choose a profile. Six are available (`report_profiles.py:40`):

   | Profile | Description | What's included |
   |---|---|---|
   | **full** | Comprehensive IR report | All approved findings, timeline, IOCs, MITRE mapping, evidence, todos, summary |
   | **executive** | Management briefing (1-2 pages) | Top 5 findings, summary, todos; timeline count only |
   | **timeline** | Chronological event narrative | All approved timeline events; filterable by date range |
   | **ioc** | Structured IOC export | IOCs with MITRE mapping; no timeline |
   | **findings** | Detailed findings | All approved findings; filterable by finding IDs |
   | **status** | Quick status for standups | Summary + open todos only |

3. You will be prompted to re-enter your password (step-up re-auth,
   `routes.py:5208`, `_report_reauth`). The re-auth event ID is stamped
   into the report's custody appendix.
4. Report generation requires at least one approved finding
   (`routes.py:5163`, `_report_eligibility`). If none exist, generation
   returns HTTP 409.
5. What happens under the hood (`reporting.py:391`, `generate_report_data`):
   - Loads findings and timeline. In DB-active mode, reads approved items
     from Postgres authority, **never** from the case JSON
     (`reporting.py:427`).
   - Filters to only `status == "APPROVED"` items
     (`reporting.py:490-491`). DRAFT, REJECTED, and other states are
     dropped irrevocably.
   - Builds MITRE ATT&CK mapping from approved findings
     (`reporting.py:542`, `build_mitre_mapping`).
   - Generates custody appendix with approval hashes and evidence
     provenance (`reporting.py:175`, `build_custody_appendix`).
   - Reconciles DB content-hash verification
     (`reporting.py:713`, `reconcile_verification_db`).
   - Returns structured report data keyed by profile sections.

## 10. Export and Archive

- **Download as Markdown:**
  `GET /portal/api/reports/{id}/download` (`routes.py:5365`,
  `download_report`)
  Serialises the stored report JSON to Markdown. Returns a downloadable
  `.md` file named `report_{profile}_{id_prefix}.md`. Recorded as
  non-authoritative provenance — the DB row is the authoritative record.

- **Export findings/timeline bundle** (for sharing with other analysts):
  `sift_core.case_io.export_bundle()` (`case_io.py:554`) — produces a JSON
  bundle of `{case_id, examiner, exported_at, findings, timeline}`.
  Optionally filtered by modification date with the `since` parameter.

- **Evidence chain proof export:**
  `POST /portal/api/evidence/chain/proof-export`
  (`routes.py:1650`, `post_evidence_chain_proof_export`)
  Generates a DB-derived proof bundle (sealed object snapshot, custody
  event chain, chain head) from Postgres custody authority. Mounted
  evidence is re-verified by full re-hash and the verify outcome + content
  hash are recorded via `app.evidence_record_proof_export`. Requires DB
  evidence authority — returns 503 without it.

- **Optional — Solana blockchain anchoring:**
  `POST /portal/api/evidence/chain/anchor` (`routes.py:1614`,
  `post_evidence_chain_anchor`)
  Anchors the DB-derived proof material on Solana if
  `SIFT_SOLANA_KEYPAIR` is configured. Records external proof but does
  **not** fail the export if anchoring is unavailable or fails. The anchor
  status (transaction ID, confirmation, cluster, explorer URL) is surfaced
  in evidence chain status and seal responses.

## Key Concepts

> [!important] **Evidence MUST be sealed before the agent can work.**
> Until evidence is registered and sealed, the `EvidenceGate` middleware
> blocks ALL MCP tool calls for the case. The agent sees nothing until you
> seal. The seal is the load-bearing integrity property — files are hashed,
> custody events and versions are recorded in the append-only Postgres chain, and the
> selected local-protected or external-read-only posture is verified before use.

> [!important] **Reports contain ONLY APPROVED items.**
> DRAFT, REJECTED, and other statuses are excluded. Report generation
> requires at least one approved finding (HTTP 409 otherwise). In DB-active
> mode, approved items come from Postgres authority, not case files —
> tampering with case JSON cannot inject or alter report content.

> [!important] **Re-authentication is required for sensitive actions.**
> Case activation, evidence sealing, review commit, report generation,
> report download, and metadata edits all require Supabase password
> re-verification. This is by design — it prevents unauthorized portal
> access from modifying evidence chains or generating reports. All
> re-authentication is fail-closed: if Supabase is unreachable, the action
> is denied with no state change and no audit artifact.

> [!note] **DB authority throughout.**
> Evidence custody, case metadata, and investigation data are
> authoritative in Postgres. File artifacts (CASE.yaml,
> evidence-manifest.json, findings.json, reports) are **exports** — they
> are mirrors, not the source of truth. The Portal never reads case files
> for report eligibility or evidence chain status when DB authority is
> wired.

## Related
- [MCP Tool Catalog](12%20-%20MCP%20Tool%20Catalog.md) — All 42 tools the agent uses
- [Configuration Reference](16%20-%20Configuration%20Reference.md) — Tune evidence gate, output caps
- [Troubleshooting](18%20-%20Troubleshooting.md) — Evidence gate blocks, auth failures
- [Authentication](11%20-%20Authentication%20for%20API%20and%20MCP.md) — Token formats, identity resolution, session details
- [Portal](06%20-%20Portal.md) — Frontend architecture and full endpoint reference
