# Configuration, Secrets, and Variable Dictionary

**BATCH-OR3** — variable dictionary for an installed SIFT VM.
Last updated: 2026-06-12.

Companion to `docs/operator/maintenance-guide.md`. This file is the single
reference for **every environment file, installer variable, Supabase project
export, Gateway env reference, DB-backed setting, OpenSearch config, RAG/FK/
Hayabusa setting, Docker compose variable, and systemd unit environment file**,
plus the authoritative **"do not hand-edit"** list.

Derived from `install.sh`, the systemd units (verified live), and the discovery
docs `sift-tool-inventory.md`, `state-authority-map.md`, and
`reference-data-provenance.md`.

> Secret **values are never recorded here.** Only paths, modes, owners, and key
> **names** appear. `<redacted>` marks any place a value would be.

---

## 1. Secret/config files on disk (key names + modes)

Primary service config dir: `/var/lib/sift/.sift/` — mode `0700`, owner
`sift-service`. Referenced by the systemd units' `EnvironmentFile=` lines and by
`--config`.

| File | Mode | Owner | Keys (names only) | Secret? |
| --- | --- | --- | --- | --- |
| `gateway.yaml` | `0600` | `sift-service` | gateway / case / execute / trust / auth / control_plane / token_registry / api_keys / portal / opensearch / enrichment / backends sections; `portal.session_secret` is **inline** | yes (inline session secret) |
| `control-plane.env` | `0600` | `sift-service` | `SIFT_CONTROL_PLANE_DSN=<redacted>`, `SIFT_TOKEN_PEPPER=<redacted>` | yes |
| `supabase.env` | `0600` | `sift-service` | `SUPABASE_URL`, `SUPABASE_ANON_KEY=<redacted>`, `SUPABASE_SERVICE_ROLE_KEY=<redacted>`, `SIFT_CONTROL_PLANE_DSN=<redacted>` | yes |
| `opensearch.env` | `0600` | `sift-service` | `OPENSEARCH_CONFIG`, `OPENSEARCH_HOST` | low |
| `opensearch.yaml` | `0600` | `sift-service` | `host`, `user`, `password=<redacted>`, `verify_certs` | yes (password) |
| `forensic-knowledge.env` | `0644` | `sift-service` | `FK_DATA_DIR` (non-secret pointer) | no |
| `opencti-connector-mitre-id` | `0600` | `sift-service` | add-on connector id `<redacted>` | yes (add-on) |
| `opencti-connector-cisa-kev-id` | `0600` | `sift-service` | add-on connector id `<redacted>` | yes (add-on) |

TLS / CA material — `/var/lib/sift/.sift/tls/` (dir `0700`, `sift-service`).
Profile: internal/local CA (BATCH-TLS1 / B-MVP-001). CA RSA-4096 / 10y
(`critical,CA:TRUE`); leaf RSA-4096 / 2y (`serverAuth`, SANs derived from the
VM's primary IP + loopback + hostname). Renew the leaf with
`scripts/rotate-tls.sh --renew-leaf` (keeps CA — no client re-trust); rotate the
CA only with `--rotate-ca --i-understand-clients-lose-trust`. See
maintenance-guide §11.

| File | Mode | Role |
| --- | --- | --- |
| `ca-cert.pem` | `0644` | local CA cert (public — import into client trust store) |
| `ca-key.pem` | `0600` | CA private key — **secret** |
| `gateway-cert.pem` | `0644` | gateway TLS leaf cert (public) |
| `gateway-key.pem` | `0600` | gateway TLS private key — **secret** |

Token / handoff and legacy fallback:

| File | Mode | Owner | Notes |
| --- | --- | --- | --- |
| `/var/lib/sift/tokens/installer-handoff.txt` | `0600` | `sift-service` | temporary operator password + endpoints; stale after first reset |
| `/var/lib/sift/passwords/examiner.json` | `0600` | `sift-service` | legacy PBKDF2 fallback hash+salt; fallback only |

Operator-owned Supabase project export — `~/.sift/supabase-project/`
(`/home/sansforensics/.sift/supabase-project/`, owner `sansforensics:docker`):

| File | Mode | Keys (names only) |
| --- | --- | --- |
| `sift-supabase.env` | `0600` | `SUPABASE_URL`, `SUPABASE_ANON_KEY=<redacted>`, `SUPABASE_SERVICE_ROLE_KEY=<redacted>`, `SIFT_CONTROL_PLANE_DSN=<redacted>` |

> `gateway.yaml` references `opensearch.ca_cert_path:
> /var/lib/sift/.sift/tls/ca-cert.pem` and `opensearch.url:
> http://127.0.0.1:9200`. The inline `portal.session_secret` is a noted posture
> difference vs the env-indirected DSN/pepper (hardening fork F-OR1-1).

---

## 2. systemd unit environment files

Both units run as `User=sift-service` / `Group=sift-service`,
`WorkingDirectory=/opt/sift-mcps`. `EnvironmentFile=-...` (the `-` means
"optional; ignore if absent"). **Verified live 2026-06-12:**

| Unit | ExecStart | EnvironmentFile (in order) |
| --- | --- | --- |
| `sift-gateway.service` | `/opt/sift-mcps/.venv/bin/sift-gateway --config /var/lib/sift/.sift/gateway.yaml` | `supabase.env`, `control-plane.env`, `opensearch.env`, `forensic-knowledge.env` |
| `sift-job-worker.service` | `/opt/sift-mcps/.venv/bin/sift-job-worker` | `supabase.env`, `control-plane.env`, `forensic-knowledge.env` |

All `EnvironmentFile` paths are under `/var/lib/sift/.sift/`. The worker does not
load `opensearch.env` (it does not serve the OpenSearch backend directly).
Inspect live with:
`sudo systemctl show sift-gateway.service -p EnvironmentFiles -p ExecStart`.

---

## 3. Gateway runtime config (`gateway.yaml`) sections

`gateway.yaml` (mode `0600`) is read at gateway startup. Sections present
(values redacted): `gateway`, `case`, `execute`, `trust`, `auth`,
`control_plane`, `token_registry`, `api_keys`, `portal` (incl. inline
`session_secret`), `opensearch` (`url`, `ca_cert_path`), `enrichment`, and
`backends`. It also holds legacy fallback tokens / PBKDF2 references for the
non-Supabase auth path. Edit only via the installer (`write_gateway_config`) plus
a gateway restart; see §"Do not hand-edit".

---

## 4. Installer variables (`install.sh`)

These shape an install. All have defaults; set them in the environment before
running `./install.sh` (or in the sourced `sift-supabase.env`). Path variables
rarely need changing.

### 4.1 Behavior / profile flags

| Variable | Default | Effect |
| --- | --- | --- |
| `SIFT_RAG_ENABLED` | `true` | seed + register the `forensic-rag-mcp` backend; `false` skips RAG (no `kb_*` tools) |
| `SIFT_RAG_IMPORT_SOURCE` | `direct` | RAG seed source: `direct` (bundled JSONL) or `chroma` (legacy GitHub bundle) |
| `SIFT_OPENSEARCH_ENABLED` | `true` (implied) | enable the OpenSearch backend path |
| `SIFT_OPENCTI_ENABLED` | off unless set | prepare OpenCTI add-on secrets (external add-on; not core) |
| `SIFT_CORE_ONLY` | `0` | `1` skips OpenSearch, Docker, and forensic-tool/Hayabusa downloads (`uv sync` extra = `core`) |
| `SIFT_EXTERNAL_SUPABASE` | `0` | `1` = operator supplies external Supabase; installer does not provision local Supabase |

### 4.2 Python / uv constraints (do not change on the SIFT VM)

| Variable | Value | Why |
| --- | --- | --- |
| `UV_NO_MANAGED_PYTHON` | `1` | forbid uv from installing its own Python; use `/usr/bin/python3.12` |
| `UV_PYTHON_DOWNLOADS` | `never` | no managed-Python downloads on the VM |

### 4.3 Path variables (defaults — change only with reason)

| Variable | Default | Holds |
| --- | --- | --- |
| `SIFT_STATE_DIR` | `/var/lib/sift` | service state root (also `sift-service` home) |
| `SIFT_HOME` | `$SIFT_STATE_DIR/.sift` (`/var/lib/sift/.sift`) | secrets + `gateway.yaml` + TLS + backups + hayabusa |
| `SIFT_TLS_DIR` | `$SIFT_HOME/tls` | CA + gateway cert/key |
| `SIFT_BACKUP_DIR` | `$SIFT_HOME/backups` | installer backup area |
| `SIFT_CONFIG` | `$SIFT_HOME/gateway.yaml` | gateway config path (`--config`) |
| `SIFT_PASSWORDS_DIR` | `$SIFT_STATE_DIR/passwords` | legacy PBKDF2 examiner hash |
| `SIFT_VERIFICATION_DIR` | `$SIFT_STATE_DIR/verification` | file-mode HMAC verification ledger (fallback) |
| `SIFT_TOKENS_DIR` | `$SIFT_STATE_DIR/tokens` | installer handoff |
| `SIFT_SNAPSHOTS_DIR` | `$SIFT_STATE_DIR/snapshots` | operator forensic snapshots |
| `SIFT_ENRICHMENT_DIR` | `$SIFT_STATE_DIR/enrichment` | FK/RAG enrichment symlinks |
| `MATERIALS_FILE` | `$SIFT_TOKENS_DIR/installer-handoff.txt` | handoff path |
| `SIFT_CASES_ROOT` / `SIFT_CASE_ROOT` | `/cases` | evidence root |
| `SIFT_EXAMINER` | `examiner` | examiner short name (`examiner@operators.sift.local`) |
| `SIFT_BIN_DIR` | operator-supplied | where pre-staged binaries (e.g. supabase) may be placed |

### 4.4 Resolved at runtime / consumed from env

| Variable | Source | Used by |
| --- | --- | --- |
| `SIFT_CONTROL_PLANE_DSN` | `control-plane.env` / `supabase.env` | gateway + worker DB connect; RAG seed CLIs |
| `SIFT_TOKEN_PEPPER` | `control-plane.env` | MCP token hashing (peppered hash in `app.mcp_tokens`) |
| `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY` | `supabase.env` / project env | Supabase Auth + REST |
| `RAG_MODEL_NAME` | env override | RAG embedding model (allowlisted) |
| `HAYABUSA_RULES_DIR` | env override | point Hayabusa at an alternate rules dir |
| `HF_HOME` / `TRANSFORMERS_CACHE` | HF default (unset by installer) | embedding model cache location |

---

## 5. Supabase project export (`sift-supabase.env`)

`~/.sift/supabase-project/sift-supabase.env` (operator-owned, `0600`) is sourced
**before** `./install.sh` to feed Supabase coordinates into the install. It is an
installer **input/handoff artifact**, regenerated by `scripts/setup-supabase.sh`.
Keys: `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`,
`SIFT_CONTROL_PLANE_DSN` (all values redacted). See §"Do not hand-edit".

The handoff records `supabase_provision_mode` as `external`,
`auto_provisioned` (with `supabase_project_env` path), or `not_provisioned`.

### 5.1 Supabase secret posture and rotation (B-MVP-012)

**Finding (HR2/HR3, 2026-06-12).** When the local control plane is provisioned by
`scripts/setup-supabase.sh` (the default lab path), the three Supabase secrets are
the **publicly known Supabase CLI demo values**:

- `SUPABASE_ANON_KEY` / `SUPABASE_SERVICE_ROLE_KEY` are demo JWTs with
  `iss=supabase-demo`, signed by the CLI's fixed demo `GOTRUE_JWT_SECRET`
  (`super-secret-jwt-token-with-at-least-32-characters-long`).
- The control-plane DSN uses the default `postgres` database password.

These are safe **only** because the entire stack is bound to `127.0.0.1` and only
`sift-service` processes reach it (the Gateway is the sole policy boundary). If the
DSN or keys ever leave the host they are trivially reusable.

**Why automatic rotation is not yet wired (remainder).** The `supabase start`
local development stack does **not** expose a supported way (in CLI v2.105.0) to
set a custom symmetric JWT secret with matching anon/service-role keys, nor a
custom Postgres password, via `config.toml`. The CLI injects `GOTRUE_JWT_SECRET`
and the demo keys directly into the managed containers; the db/auth/rest/kong
containers all share the demo DB password through CLI-managed wiring. Rotating any
one of them in isolation breaks the others. Real rotation therefore requires
**replacing the CLI-managed local stack with a self-managed compose** that owns
`GOTRUE_JWT_SECRET`, regenerates the anon/service-role JWTs from it, and sets a
non-default `POSTGRES_PASSWORD` consistently across db/auth/rest/kong — a control-
plane redesign beyond an installer hardening delta. Tracked as a backlog item.

**Operator rotation procedure available today (manual, for an external/production
Supabase project, not the local demo stack):**

1. In the Supabase project, generate a new JWT secret and regenerate the anon and
   service-role keys (Project Settings -> API), and rotate the database password
   (Project Settings -> Database).
2. Update `~/.sift/supabase-project/sift-supabase.env` with the new
   `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, and DSN password.
3. Re-run `./install.sh` so it rewrites `supabase.env` / `control-plane.env`
   (`0600`, `sift-service`-owned), then restart the services.
4. Re-issue any agent/service credentials whose JWTs were signed with the old
   secret (old tokens are invalidated by the secret change).

Until rotation lands, treat the demo-keyed local stack as **lab-only**: never
expose `:54321`/`:54322` beyond loopback, never copy the DSN/keys off-host, and
never reuse them in a production-framed deployment.

---

## 6. DB-backed settings (authority lives in Postgres, not files)

These are **not** config files — they are control-plane rows. Manage them
through the portal/MCP or supported RPCs, never by editing a file. (Full table in
`state-authority-map.md`.)

| Setting / state | DB object | How to change |
| --- | --- | --- |
| Cases + metadata + lifecycle | `app.cases` | portal REST (create/activate is re-auth gated) |
| Active case pointer | `app.active_case_state` / view `app.deployment_active_case` | portal/MCP case activation |
| Operator identity + role | `app.operator_profiles` (+ Supabase `auth.users`) | Supabase Auth path |
| Agent / service identities | `app.agents`, `app.service_identities` | issue/revoke via portal/MCP (re-auth) |
| MCP token registry | `app.mcp_tokens` (hash-only) | issue/revoke via token tools |
| Per-principal tool scopes | `app.principal_tool_scopes` | credential issuance |
| Evidence registry + seal | `app.evidence_objects`, `app.evidence_chain_heads` | portal evidence flow (re-auth) |
| Custody ledger | `app.evidence_custody_events` (append-only) | service RPC only |
| Findings / timeline / IOCs / TODOs | `app.investigation_*` | portal/MCP (approve = re-auth) |
| Report metadata + export | `app.report_metadata` | portal Reports (re-auth) |
| Durable jobs | `app.jobs` (+ `job_steps`, `job_logs`, `worker_heartbeats`) | enqueue via tools; restart worker to recover |
| MCP backend registry | `app.mcp_backends` | `scripts/setup-addon.sh` + gateway restart |
| RAG knowledge | `app.rag_chunks` / `rag_documents` / `rag_collections` | RAG seed CLIs (knowledge-only) |
| OpenSearch index registry/provenance | `app.opensearch_indices`, `app.opensearch_ingest_provenance` | ingest jobs |
| Audit log | `app.audit_events` | append-only; never edit |

---

## 7. OpenSearch config

| Item | Location / value |
| --- | --- |
| Client config file | `/var/lib/sift/.sift/opensearch.yaml` (`host`, `user`, `password=<redacted>`, `verify_certs`) |
| Env pointer | `/var/lib/sift/.sift/opensearch.env` (`OPENSEARCH_CONFIG`, `OPENSEARCH_HOST`) |
| Gateway reference | `opensearch.url: http://127.0.0.1:9200`, `opensearch.ca_cert_path: .../tls/ca-cert.pem` in `gateway.yaml` |
| Container | `sift-opensearch` (`opensearchproject/opensearch:3.5.0`), published `127.0.0.1:9200` |
| Lab posture | default `admin/admin`-class credentials (hardening item B-MVP-005) |

Index mappings/templates are static reference data in the repo
(`packages/opensearch-mcp/.../mappings/*.json`) — file-authoritative by design.

---

## 8. RAG / FK / Hayabusa settings (pointers)

Full provenance in `reference-data-provenance.md`; full maintenance in
`rag-and-search-maintenance.md`. Settings summary:

| Plane | Key setting | Location |
| --- | --- | --- |
| RAG | `SIFT_RAG_ENABLED`, `SIFT_RAG_IMPORT_SOURCE`, `RAG_MODEL_NAME` (allowlisted) | install env / runtime env |
| RAG store | `app.rag_chunks` etc. | Supabase pgvector |
| RAG corpus | `/opt/sift-mcps/packages/forensic-rag-mcp/knowledge/` | repo (read-only) |
| RAG model cache | `~/.cache/huggingface/hub/` (service user `/var/lib/sift/.cache/...`) | derived/rebuildable |
| FK | `FK_DATA_DIR=/var/lib/sift/enrichment/forensic-knowledge` | `forensic-knowledge.env` (`0644`) |
| FK data | `/opt/sift-mcps/packages/forensic-knowledge/data/` (symlinked) | repo (static) |
| Hayabusa binary | `/var/lib/sift/.sift/bin/hayabusa` (symlink `/usr/local/bin/hayabusa`) | installer-bundled |
| Hayabusa rules | `/var/lib/sift/.sift/hayabusa-rules/` (or `HAYABUSA_RULES_DIR`) | installer-bundled |

---

## 9. Docker compose / container variables

The control plane and search engine run as containers (verified live). Published
ports bind to `127.0.0.1` except the gateway's own `0.0.0.0:4508`.

| Container | Image | Published port | Belongs to |
| --- | --- | --- | --- |
| `sift-opensearch` | `opensearchproject/opensearch:3.5.0` | `127.0.0.1:9200` | core |
| `supabase_db_sift-mcps` | `supabase/postgres:15.8.1.085` | `127.0.0.1:54322->5432` | core (control plane) |
| `supabase_kong_sift-mcps` | `supabase/kong:2.8.1` | `127.0.0.1:54321->8000` | core (Supabase gateway) |
| `supabase_auth_sift-mcps` | `supabase/gotrue` | internal `9999` | core (auth) |
| `supabase_rest_sift-mcps` | `supabase/postgrest` | internal `3000` | core (REST) |

Networks: `sift-net`, `sift-supabase-local`. Volumes:
`sift-mcps_opensearch-data`, `supabase_db_sift-mcps`. Supabase compose/env is
managed by the Supabase CLI (`supabase start` via `scripts/setup-supabase.sh`),
not hand-written compose. OpenCTI add-on images may be present but not running
(B-OR1-a) — they are add-on, not core.

---

## 10. Do not hand-edit (generated files)

These are **generated by the installer** (or by the Supabase CLI). Editing them
by hand risks startup failure, silent drift from the DB authority, a broken
handoff, or lost TLS trust. Change them through the installer, the supported
operator path, or the DB — then restart services.

| File | Why not | Correct way to change |
| --- | --- | --- |
| `~/.sift/supabase-project/sift-supabase.env` | installer **input/handoff** artifact; regenerated by `setup-supabase.sh` | re-run `scripts/setup-supabase.sh` |
| `/var/lib/sift/.sift/supabase.env` | rendered from project env; consumed by both units | rotate in Supabase, re-run installer env write |
| `/var/lib/sift/.sift/control-plane.env` | holds DSN + token pepper; hand-edit breaks DB connect / token hashing | rotate DSN/pepper, let installer rewrite, restart |
| `/var/lib/sift/.sift/opensearch.env` / `opensearch.yaml` | rendered client config | rotate OS creds, re-run installer, restart |
| `/var/lib/sift/.sift/forensic-knowledge.env` | `FK_DATA_DIR` pointer; wrong value silently disables enrichment | change the data dir then re-run installer |
| `/var/lib/sift/.sift/gateway.yaml` | startup config incl. inline session secret + fallback tokens; malformed YAML fails startup | edit via `write_gateway_config` (installer) + gateway restart |
| `/var/lib/sift/tokens/installer-handoff.txt` | generated summary; stale after first reset; editing does not change real creds | do not edit; rotate via Supabase |
| `/var/lib/sift/passwords/examiner.json` | legacy PBKDF2 fallback hash | rotate via Supabase path; do not edit the hash |
| `/var/lib/sift/.sift/tls/*.pem` | installer-generated local CA + leaf | renew leaf: `scripts/rotate-tls.sh --renew-leaf` (keeps CA); rotate CA: `--rotate-ca --i-understand-clients-lose-trust`; never hand-edit keys |
| `app.mcp_backends` rows (DB) | backend registry; hand-DB-edits bypass manifest validation/hashing | register via `scripts/setup-addon.sh` |
| OpenSearch index data | derived/rebuildable | re-run ingest, not manual index writes |

> The DB is the source of truth for cases, custody, findings, jobs, audit, RAG,
> backends, and tokens. File mirrors (`CASE.yaml`, `findings.json`,
> `evidence-manifest.json`, `evidence-ledger.jsonl`, per-case `audit/*.jsonl`)
> are **export/proof only** — editing them changes nothing authoritative and can
> mislead a later reader.
