# Operator Maintenance Guide (Protocol SIFT Gateway)

**BATCH-OR3** — operator manual for a real installed SIFT VM.
Last updated: 2026-06-12.

This guide lets a new operator run, inspect, recover, and maintain an installed
deployment **without reading source code**. It is derived from the verified
discovery docs:

- `docs/inventory/sift-tool-inventory.md` — live paths, services, Docker, modes.
- `docs/operator/state-authority-map.md` — what the DB owns vs files/exports.
- `docs/operator/reference-data-provenance.md` — RAG/FK/Hayabusa provenance.

Companion docs in this set (split for size, same batch):

- `docs/operator/config-and-secrets.md` — the full variable dictionary, every
  environment file / installer variable / DB-backed setting, and the
  **"what not to edit manually"** list.
- `docs/operator/rag-and-search-maintenance.md` — RAG, OpenSearch, and Hayabusa
  day-to-day maintenance.

## Safety conventions used in this guide

- Commands are **safe (read-only / non-destructive) by default.**
- A block marked **`DANGER`** performs an irreversible or service-affecting
  action; its line states exactly what it destroys or changes.
- Secret **values are never printed here.** Paths, file modes, and key **names**
  appear; any value is shown as `<redacted>`.
- Replace `<VM_IP>` with the VM address (the live lab VM is `192.168.122.81`).
- Service-owned files under `/var/lib/sift/.sift/` are mode `0600`/`0700` and
  owned by `sift-service`; read them with `sudo` as the login user.

## Quick reference (verified live 2026-06-12)

| Fact | Value |
| --- | --- |
| Portal URL | `https://<VM_IP>:4508/portal/` |
| MCP endpoint | `https://<VM_IP>:4508/mcp` |
| Operator login email | `examiner@operators.sift.local` |
| Services | `sift-gateway.service`, `sift-job-worker.service` (both run as `sift-service`) |
| Runtime root | `/opt/sift-mcps` (services' `WorkingDirectory`) |
| Service config dir | `/var/lib/sift/.sift/` (mode `0700`, `sift-service`) |
| Gateway config | `/var/lib/sift/.sift/gateway.yaml` |
| Handoff (temp creds) | `/var/lib/sift/tokens/installer-handoff.txt` (mode `0600`) |
| Evidence root | `/cases` |
| Health | `GET https://127.0.0.1:4508/health` -> `status=ok` |

---

## 1. First login, password discovery, forced reset, rotation

### 1.1 Discover the first-login password

The installer writes a one-time operator password into the handoff file. Read it
with `sudo` (it is `0600` and owned by `sift-service`):

```bash
# Read-only: lists the handoff key/value pairs.
sudo cat /var/lib/sift/tokens/installer-handoff.txt
```

The keys you care about for first login (key **names** only — values are
secret):

| Key | Meaning |
| --- | --- |
| `portal_login_email` | the email to sign in with (normally `examiner@operators.sift.local`) |
| `supabase_operator_temp_password` | one-time portal password (Supabase Auth path) |
| `supabase_forced_reset` | `required_on_first_login` when a reset is pending |
| `temporary_examiner_password` | legacy local-auth fallback password (only if Supabase was not bootstrapped) |
| `portal_url`, `gateway_mcp_url`, `ca_cert`, `gateway_config` | endpoints / paths |

The installer's own end-of-run summary also points here:
`Secrets: /var/lib/sift/tokens/installer-handoff.txt (read with: sudo cat)`.

### 1.2 First login and the forced reset

1. Browse to `https://<VM_IP>:4508/portal/` (accept the lab CA / import the CA
   cert — see §11).
2. Sign in with `portal_login_email` and `supabase_operator_temp_password`.
3. The account is created with `status=invited` /
   `supabase_forced_reset=required_on_first_login`, so the portal **forces a
   password reset on first login** (`must_reset=true`). Set a new password.

After the reset succeeds, the temporary password is dead.

### 1.3 Password recoverability — read this carefully

> **The operator password is recoverable from the handoff file ONLY before the
> first forced reset. After you reset it, the new password is NOT stored in any
> file on the VM and cannot be recovered from the handoff or any config.**

After reset, the handoff file is stale: on a re-run the installer rewrites
`supabase_operator_temp_password=already-reset` (or `existing-supabase-user`)
rather than a usable password. Treat the post-reset operator password like any
production credential.

### 1.4 Rotating / resetting the operator password later

Supabase Auth is the authority for operator credentials
(`app.operator_profiles.auth_user_id` maps to Supabase `auth.users`; there is no
file-backed session store). Rotate or reset through the **supported operator /
Supabase path**, not by editing a file:

- **Operator-initiated (knows current password):** change it in the portal
  account flow (the portal calls Supabase Auth password update).
- **Lost password (admin reset):** re-issue a temporary password through the
  Supabase Auth admin path so the operator gets another forced-reset login. This
  is the same mechanism the installer uses to bootstrap the invited operator.

Do **not** try to recover a password by editing `gateway.yaml`,
`supabase.env`, or the handoff file — those do not hold the live operator
password, and editing generated config can break startup (see §1.5 and the
"what not to edit" list in `config-and-secrets.md`).

### 1.5 Login is Supabase-only (legacy fallback removed)

Since BATCH-PT1 (2026-06-12), portal login is **Supabase Auth only**. The
legacy `examiner.json` PBKDF2 login fallback and its local setup/challenge/
reset endpoints were removed. If the control plane is unreachable, login fails
closed with HTTP 503 ("Control plane unavailable") — the fix is to restore
Supabase/control-plane health (see §12), never a local credential. The forced
first-login reset (§1.2) is the only in-portal password-reset path; the
temporary password is the installer handoff value and is unrecoverable after
reset (rotate via the Supabase path in §1.4). A stale
`/var/lib/sift/passwords/` directory may remain from older installs; it is no
longer consulted for login (sensitive-action re-auth challenges under file
authority still use the local HMAC bridge — retirement is tracked in
Session-Notes).

### 1.6 Creating additional cases

Operators (examiner role) create new cases from the portal Header
case-selector -> "New case". Case activation re-auth depends on authority
mode: under DB/Supabase authority the activation is gated by the Supabase
session (no separate password challenge); under file authority a password
HMAC challenge is required.

---

## 2. Service status and restarts

Both are **system** services (run as `sift-service`, start at boot via
`multi-user.target`). Confirmed live: both `active running`.

### 2.1 Status (read-only)

```bash
# Status of both core services.
sudo systemctl status sift-gateway.service sift-job-worker.service

# Confirm identity, working dir, and which env files they load.
sudo systemctl show sift-gateway.service \
  -p User -p Group -p WorkingDirectory -p ExecStart -p EnvironmentFiles
```

Expected: `User=sift-service`, `WorkingDirectory=/opt/sift-mcps`,
`ExecStart=/opt/sift-mcps/.venv/bin/sift-gateway --config /var/lib/sift/.sift/gateway.yaml`.

### 2.2 Restart (service-affecting, not destructive)

```bash
# Restarting drops in-flight MCP/portal connections briefly. No data loss:
# durable jobs are in app.jobs and are reclaimed by the worker on restart.
sudo systemctl restart sift-gateway.service sift-job-worker.service
```

Restart the **gateway** after changing `gateway.yaml`, TLS material, env files,
or after registering/disabling a backend. Restart the **worker** to recover a
wedged job-processing loop (`app.expire_stale_jobs()` reclaims leases).

### 2.3 Enable/disable at boot

```bash
sudo systemctl is-enabled sift-gateway.service sift-job-worker.service   # read-only
# DANGER: the following stops the platform until re-enabled/started.
# sudo systemctl disable --now sift-gateway.service sift-job-worker.service
```

---

## 3. Health checks

### 3.1 Gateway health (authoritative liveness)

```bash
curl -sk https://127.0.0.1:4508/health
```

A healthy response (verified live) is `{"status":"ok", ...}` with:

- `backends.forensic-rag-mcp` and `backends.opensearch-mcp` -> `status:"ok"`,
  `state:"idle"`, `mounted_proxy:true` (stdio backends mount idle and start on
  demand — idle is healthy, not degraded).
- `supabase.status:"ok"` with the control-plane URL.
- `tools_count` > 0 (live count was 17 aggregate tools).

If `status` is not `ok`, check the failing backend's `detail`, then service logs
(§9). `app.mcp_backends.health_status` is recomputed by the gateway probe — it is
not authoritative state, so a restart re-derives it.

Since BATCH-PT1, the same data is visible in the portal: the **System Health
panel** on the Backends tab (`/portal/api/health`, auto-refreshing) shows
Gateway, Supabase, evidence root, and every backend; idle mounted stdio
backends display as `ok`. The Backends tab also has per-backend
Enable/Disable controls (re-auth gated; a `restart_required` notice means the
change applies to the served `/mcp` catalog after restart). The portal root is
ergonomic: `https://<VM_IP>:4508/` redirects to `/portal/`.

### 3.2 OpenSearch health and indices

```bash
# Cluster health. Single-node clusters report "yellow" (unassigned replicas) —
# that is expected and healthy here, NOT an error.
curl -s http://127.0.0.1:9200/_cluster/health

# List indices (read-only).
curl -s 'http://127.0.0.1:9200/_cat/indices?v'
```

Verified live: `status=yellow`, 1 node, 15 active primaries, 2 unassigned
replicas, 9 indices. See `rag-and-search-maintenance.md` for index/template
detail.

### 3.3 RAG and control-plane row counts (redacted)

The RAG knowledge plane lives in Supabase pgvector. Check population by **row
count only** (never select content). Run inside the Supabase Postgres container:

```bash
# Read-only counts. Key NAMES/counts only; never dump rows.
docker exec supabase_db_sift-mcps psql -U postgres -d postgres -tA -c \
  "select 'rag_chunks', count(*) from app.rag_chunks
   union all select 'mcp_backends', count(*) from app.mcp_backends
   union all select 'cases', count(*) from app.cases
   union all select 'evidence_objects', count(*) from app.evidence_objects
   union all select 'jobs', count(*) from app.jobs;"
```

Expected shape (OR1 baseline): `rag_chunks` populated (~26,586 on the reference
VM), `mcp_backends` = 2 (the two core stdio backends). A `rag_chunks` count of 0
means RAG was never seeded — see `rag-and-search-maintenance.md` §1.

> Do not paste the DSN on the command line. The container's `psql` already
> authenticates locally; if you must connect from outside the container, read
> the DSN from `/var/lib/sift/.sift/control-plane.env` into a shell variable and
> never echo it.

---

## 4. Backup and restore

Authority lives in two places: **Supabase/Postgres** (the control plane — almost
all mutable state) and **operator-managed evidence bytes** under `/cases`. The
file mirrors (`CASE.yaml`, `findings.json`, `evidence-manifest.json`,
`evidence-ledger.jsonl`, per-case `audit/*.jsonl`) are **export/proof, not
authority** — restoring them does not restore truth; restore the database.

### 4.1 What to back up

| Target | Why | Authority class |
| --- | --- | --- |
| Supabase Postgres database | cases, evidence custody/hashes, findings, jobs, audit, RAG vectors, backends, tokens | **db (primary backup target)** |
| Supabase Auth users | operator/agent login identities | db (Supabase Auth) |
| `/var/lib/sift/.sift/` (0700) | gateway.yaml, env files, TLS keys, hayabusa, backups | secret/config |
| `/var/lib/sift/passwords/`, `/var/lib/sift/tokens/` (0700) | legacy fallback hash, handoff | secret/config |
| `/cases/*` evidence bytes + `/var/lib/sift/snapshots` | the actual forensic data the DB only hashes | **operator-managed file (out-of-band)** |

Caches and rebuildables you do **not** need to back up: `.venv`,
`/opt/sift-mcps` checkout (rebuild via reinstall / `uv sync`),
`/var/cache/sift/volatility-symbols`, OpenSearch index data (rebuildable by
re-ingesting sealed evidence), Hugging Face model cache.

### 4.2 Database backup (read-only dump)

```bash
# Logical dump of the control plane. Writes a dump file; does not alter the DB.
docker exec supabase_db_sift-mcps pg_dump -U postgres -d postgres -Fc \
  > "sift-control-plane-$(date -u +%Y%m%dT%H%M%SZ).dump"
```

Store the dump securely (it contains hashed secrets and case metadata). The
RAG pgvector data is included in this dump.

### 4.3 Secret/config backup

```bash
# Read-only archive of the secret/config tree. Treat the archive as SECRET
# (it contains TLS private keys and env files with credentials).
sudo tar -C /var/lib/sift -czf "sift-config-$(date -u +%Y%m%dT%H%M%SZ).tgz" \
  .sift passwords tokens
```

### 4.4 Restore (service-affecting)

> **DANGER (DB restore):** restoring the database **overwrites all current
> control-plane state** — cases, custody chain, findings, jobs, audit. Do this
> only onto an intended target.

```bash
# DANGER: overwrites the control-plane database with the dump's contents.
# docker exec -i supabase_db_sift-mcps pg_restore -U postgres -d postgres \
#   --clean --if-exists < sift-control-plane-<stamp>.dump
sudo systemctl restart sift-gateway.service sift-job-worker.service
```

Restore order: (1) Supabase DB + Auth, (2) `/var/lib/sift/.sift` secrets/TLS,
(3) evidence bytes into `/cases`, (4) restart services, (5) re-verify with §3.
Evidence integrity is re-provable because the DB holds the sealed
`current_sha256` / chain head hashes; re-hash the restored bytes and compare.

---

## 5. Evidence mount and seal workflow

**Invariant:** evidence bytes are **mounted or copied by the operator on the VM**
and must be **registered and sealed before analysis.** The DB
(`app.evidence_objects`, `app.evidence_chain_heads`,
`app.evidence_custody_events`) owns custody metadata and hashes; the
`evidence-manifest.json` / `evidence-ledger.jsonl` files are export/proof only.

### 5.1 Operator steps

1. **Activate a case** (re-auth gated). In the portal: create/select a case and
   activate it. Activation requires password re-auth and is recorded in
   `app.audit_events`.
2. **Place evidence bytes — service-owned.** Copy or mount the disk/memory image
   into the active case's evidence directory `/cases/<case>/evidence/`. This is a
   manual VM-side operation by the operator; agents never place bytes. The portal
   does **not** upload bytes — it detects files placed here in-place. The evidence
   directory is owned by the gateway service user (`sift-service`, `0755`), and
   **seal requires each evidence file to be owned by `sift-service`** (it sets the
   immutable flag in-process and deliberately never chowns for you). A plain
   `sudo cp` lands the file `root`-owned and the seal then fails closed with
   `evidence_immutability_failed`. Stage the bytes so they land service-owned:

   ```bash
   # Helper: resolves the active case, copies the bytes in, sets sift-service
   # ownership + 0644 (run on the VM as a sudo-capable operator):
   scripts/stage-evidence.sh /mnt/source/IMAGE.e01            # active case
   scripts/stage-evidence.sh /mnt/source/IMAGE.e01 --case case-<key>

   # …or by hand:
   sudo install -o sift-service -g sift-service -m 0644 \
     /mnt/source/IMAGE.e01 /cases/<case>/evidence/
   # already copied root-owned? just fix ownership:
   sudo chown sift-service:sift-service /cases/<case>/evidence/IMAGE.e01
   ```
3. **Register** the evidence object (portal evidence flow). The placed file
   surfaces as `unregistered` in the evidence chain (use **Rescan** if it does
   not appear); registering records the object and computes its hash.
4. **Seal** the evidence (re-auth gated -> `app.evidence_seal`). Sealing is the
   gate: analysis tools treat sealed evidence as read-only. On seal each byte file
   is set read-only (`chmod 0444`) **and immutable (`chattr +i`)** and the custody
   chain head advances. Seal **fails closed** (`evidence_immutability_failed`) if a
   file is not `sift-service`-owned or the interpreter lacks `CAP_LINUX_IMMUTABLE`
   (granted to the venv interpreter by `install.sh`) — fix ownership per step 2 and
   retry.

Re-auth is required for **case activation, evidence seal/ignore/retire, finding
approval, report inclusion/export, and agent credential issuance.** These are
sensitive human actions and each records a re-auth audit event.

### 5.2 Verifying custody (read-only)

```bash
# Row counts / status only — never dump custody event content here.
docker exec supabase_db_sift-mcps psql -U postgres -d postgres -tA -c \
  "select status, seal_status, count(*) from app.evidence_objects
   group by status, seal_status order by 1,2;"
```

The exported `evidence-ledger.jsonl` (HMAC chain) and
`evidence-anchor-v{N}.json` are offline court-proof artifacts; the gate consults
the DB (`app.evidence_gate_status` via `evidence_gate.check_evidence_gate_db`),
not the files.

> **DANGER (seal/ignore/retire):** sealing makes bytes read-only and advances an
> append-only custody chain; ignore/retire change evidence usability. These are
> re-auth-gated and append-only — they cannot be silently undone.

---

## 6. RAG maintenance (summary)

Full procedures are in `docs/operator/rag-and-search-maintenance.md` §1. RAG is
**knowledge/reference-only** in pgvector; case-derived embedding is blocked by
design (Python layer + DB trigger). Quick operator facts:

- Check population: §3.3 row count of `app.rag_chunks`.
- Re-seed from the bundled JSONL corpus (idempotent): see the search-maintenance
  doc. Requires the control-plane DSN and may download the embedding model on
  first run.
- Disable: `SIFT_RAG_ENABLED=false` at install time, or disable the backend row
  and restart the gateway.

---

## 7. OpenSearch index checks (summary)

Full procedures in `rag-and-search-maintenance.md` §2. Quick checks:

```bash
curl -s 'http://127.0.0.1:9200/_cat/indices?v'                  # indices + doc counts
curl -s 'http://127.0.0.1:9200/_index_template?pretty' | less   # templates present
curl -s 'http://127.0.0.1:9200/_cat/indices/case-*-hayabusa-*?v' # hayabusa detections
```

OpenSearch index data is **derived/rebuildable**; the registry
(`app.opensearch_indices`) and provenance (`app.opensearch_ingest_provenance`)
are the DB authority. To rebuild, re-run ingest against sealed evidence.

---

## 8. Backends & add-ons (install model, integration, status)

A backend becomes usable in **two independent steps** that operators routinely
conflate:

1. **Python package on disk** — installed by a uv *extra* (`full` = core +
   opensearch + rag; `windows-triage` and `opencti` are *separate* extras, NOT in
   `full`). Installing an extra registers nothing.
2. **Registered in the control plane** — a row in `app.mcp_backends`. Only
   registered **and** enabled backends are aggregated by the gateway and exposed
   on `/mcp`.

A **default `./install.sh`** registers exactly two backends: `opensearch-mcp`
(when the cluster comes up healthy) and `forensic-rag-mcp`. `windows-triage-mcp`
and `opencti-mcp` are **never** registered by the installer — they are add-ons
you integrate yourself (§8.2).

### 8.1 Installer flags (`./install.sh`)

Run from a clone; the installer stages itself into `/opt/sift-mcps` and is
re-run-safe (idempotent). No flags are required for a normal install.

| Flag | Effect | Env equivalent |
|---|---|---|
| (none) | Full native stack: gateway + portal + core tools + OpenSearch + RAG + Supabase + Hayabusa. Registers `opensearch-mcp` + `forensic-rag-mcp`. | — |
| `--core-only` | Gateway + portal + in-process core tools only. Skips OpenSearch, RAG, Docker, and forensic-tool downloads. Registers **no** add-on backends. | `SIFT_CORE_ONLY=1` |
| `--no-rag` | Do not register `forensic-rag-mcp`. | `SIFT_RAG_ENABLED=false` |
| `--no-opencti` | Accepted for compatibility only; OpenCTI is never installed by `install.sh`. Use `setup-addon.sh`. | `SIFT_OPENCTI_ENABLED` (ignored) |
| `--external-supabase` | Skip Supabase auto-provisioning. Requires `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`, `SIFT_CONTROL_PLANE_DSN` already exported. | `SIFT_EXTERNAL_SUPABASE=1` |
| `--offline` | Air-gapped: attempt **no** network downloads; each download step fails loudly pointing at the staged-artifact path it expects (uv, hayabusa, HF model cache, Supabase CLI). | `SIFT_OFFLINE=1` |
| `--enable-geoip` | Enable the OpenSearch ip2geo datasource (off by default; it fetches from a live endpoint). | `SIFT_GEOIP_ENABLED=1` |
| `--apparmor-enforce` | Load the SIFT AppArmor profiles in **enforce** mode (default is complain). Same posture as `./harden.sh`. | `SIFT_APPARMOR_ENFORCE=1` |
| `--uninstall` / `--remove` | Reverse the **software** install. Delegates to `scripts/uninstall.sh` (the single, gated teardown): removes the service + service users, venv, `~/.sift` (config/TLS/secrets/hayabusa), and auditd/AppArmor configs. **Preserves all data** — `/var/lib/sift` state, docker volumes, and `/cases` EVIDENCE are never touched. Dry-run unless `-y`. | — |
| `-y`, `--yes` | Proceed non-interactively (otherwise `--uninstall` is a dry-run). | — |

> **D5 invariant (evidence is append-only / immutable):** `install.sh` has **no**
> code path that can delete case evidence. The old `--purge-data` flag was removed
> (issue #16). To remove forensic **state** or docker data, run
> `scripts/uninstall.sh` directly with non-evidence components, e.g.
> `scripts/uninstall.sh --components state,cache,opensearch,supabase --yes --i-understand`.
> Removing `/cases` evidence is only ever possible by invoking `scripts/uninstall.sh`
> itself with its multi-gated evidence-removal flags + a typed `DELETE EVIDENCE`
> confirmation (§14) — never through `install.sh`.

> OpenSearch has no dedicated install flag: it is on by default and registered
> only if the cluster comes up healthy. Disable it with
> `SIFT_OPENSEARCH_ENABLED=false` or `--core-only`. `--apparmor-enforce` is also
> available post-install via `./harden.sh` (and `./harden.sh --complain` reverts).

### 8.2 Integrating an add-on end-to-end (VM → Portal)

Every add-on — `windows-triage-mcp`, `opencti-mcp`, or a third-party backend —
uses the **same single door**: prepare on the VM, Register in the portal, then
restart. Worked example: **windows-triage-mcp**.

**Step 1 — Prepare on the VM (`scripts/setup-addon.sh`).** Interactive helper; it
provisions prerequisites and writes a ready-to-submit register payload, but
**registers nothing itself**.

```bash
# On the VM, from the repo checkout. Interactive menu (no positional args).
./scripts/setup-addon.sh
#   1) opensearch-mcp   2) opencti-mcp   3) forensic-rag-mcp
#   4) windows-triage-mcp   5) custom/community   a) all reference (1-4)
# Select e.g. "4". It stages the windows-triage extra into /opt/sift-mcps/.venv,
# offers to download the baseline DBs, and writes the payload to
#   ~/.sift/addon-register/windows-triage-mcp.json
```

**Step 2 — (windows-triage only) baseline databases.** The known-good/known-bad
DBs download separately; the optional registry baseline is ~12 GB (opt-in):

```bash
# Default dest is /var/lib/sift/windows-triage (the add-on's default DB dir).
python -m windows_triage_mcp.scripts.download_databases             # known-good + context only
python -m windows_triage_mcp.scripts.download_databases \
  --with-registry --yes                                             # ALSO the ~12 GB registry baseline
```

**Step 3 — Register in the Portal.** `Portal -> Backends -> Register New Backend`.
Submit the payload `setup-addon.sh` wrote, or fill the form:

- **Transport** `stdio`, **Name** `windows-triage-mcp`
- **Manifest path** `packages/windows-triage-mcp/sift-backend.json` (a
  `manifest_path` is **required** — inline manifests are validate-only)
- **Command** `/opt/sift-mcps/.venv/bin/windows-triage-mcp` (the staged console
  script the `sift-service` user can exec)
- **Env var references** only if the DB dir differs from the default; never raw
  secrets — only `CHILD_ENV = GATEWAY_ENV` name pairs.

Click **Validate** (checks manifest schema + contract; shows provided tools and
requirements), then **Register** (re-auth: examiner password). This persists the
`app.mcp_backends` row and returns `restart_required`.

**Step 4 — Apply (restart-to-apply, D34).** Registering does not hot-load into the
running gateway:

```bash
sudo systemctl restart sift-gateway.service
```

**Step 5 — Verify.** On `Portal -> Backends` the row should read
**ENABLED · Ready · on-demand · OK** (§8.5). Or from the VM:

```bash
curl -sk https://127.0.0.1:4508/health | python3 -m json.tool | grep -A3 windows-triage
```

### 8.3 `scripts/setup-addon.sh` reference

Interactive only (`./scripts/setup-addon.sh`, or `--help`). Per backend you
select it (1) optionally provisions prerequisites (downloads / Docker stacks /
index bootstrap), (2) prompts for and echoes every config + env var, then (3)
writes `~/.sift/addon-register/<name>.json`. It **never** registers a backend and
**never** edits `gateway.yaml` — you drive Validate → Register → restart yourself
(Steps 3-4). Menu: `1` opensearch-mcp, `2` opencti-mcp, `3` forensic-rag-mcp,
`4` windows-triage-mcp, `5` custom/community, `a` all reference backends (1-4).

### 8.4 windows-triage databases (`download_databases`)

| Flag | Meaning |
|---|---|
| `--dest DIR` | Target dir. Default `/var/lib/sift/windows-triage` (the add-on's default DB dir; no env-ref needed when used). |
| `--tag TAG` | Release tag to pull (defaults to the pinned baseline release). |
| `--with-registry` | ALSO download the ~12 GB `known_good_registry.db` baseline (opt-in; gated on a disk-space check). |
| `--yes` | Assume yes to the registry confirmation (non-interactive installs). |

### 8.5 Reading backend status on the Portal Backends page

The Backends tab shows two views that answer different questions — read the right
one:

- **System Health panel** (`/portal/api/health`, auto-refreshing): is the backend
  *mounted and reachable* right now? Proxy-mounted stdio backends show `ok` even
  while idle. This is the trustworthy liveness signal (§3.1).
- **DB Registry table** (`/api/backends`): the registry view — `enabled`,
  requirements, and lifecycle status.

DB Registry **STATUS** column:

| Shown | Meaning |
|---|---|
| `ENABLED` / `DISABLED` | The `app.mcp_backends.enabled` flag (registry row on/off). |
| `Ready · on-demand` | Proxy-mounted add-on, healthy; the subprocess spawns per call (no persistent process). Normal resting state — **not** an error. |
| `Started` | A persistently-started backend process is running. |
| `Stopped` | Registered + enabled but neither mounted nor started (e.g. a non-proxy backend that failed to mount). |
| `Pending restart` | The row was registered/changed but is not yet loaded — restart to apply. |

**HEALTH** column: `OK` (healthy / mounted on-demand), `Gated` (unmet
requirements — see REQUIREMENTS), `Disabled`, or `Invalid Manifest`.

Notes:

- On-demand rows show an **`on-demand`** tag instead of Start/Stop/Restart. Do
  **not** try to "Start" them — for a proxy-mounted backend that spawns a
  redundant subprocess nothing consumes. Use Disable/Unregister to manage them.
- When any row is pending, a **restart-to-apply banner** prompts you to run
  `sudo systemctl restart sift-gateway`.
- A fresh install with no add-ons shows opensearch + rag only; the empty-state
  reminds you that add-ons come via `setup-addon.sh → Register → restart`.

### 8.6 List / disable / unregister backends

```bash
# List registered backends (names/namespace/enabled/health only).
docker exec supabase_db_sift-mcps psql -U postgres -d postgres -tA -c \
  "select name, namespace, transport, enabled, health_status from app.mcp_backends order by name;"
```

To disable an add-on: `Portal -> Backends -> Disable` (re-auth), or set
`app.mcp_backends.enabled=false`, then restart. To remove it entirely:
`Unregister` in the portal (re-auth), or delete the row. Core backend rows should
not be removed casually. The manifest is validated against the backend JSON
schema, hashed (`manifest_sha256`), and stored in `app.mcp_backends`; raw secrets
are rejected by a DB CHECK + validators. Register payloads land transiently under
`$SIFT_HOME/addon-register/*.json` — authority is the DB row.

> **Add-on image lifecycle note (B-OR1-a):** OpenCTI + redis/rabbitmq/minio
> Docker images (~4.4 GB) can linger on a core VM with no OpenCTI containers
> running. They are add-on artifacts; `docker image rm` them if the add-on is
> not in use (does not affect core). Verify nothing is running first:
> `docker ps`.

---

## 9. Logs

### 9.1 systemd journal (primary)

```bash
# Live tail of the gateway. Read-only.
sudo journalctl -u sift-gateway.service -f
# Last 200 lines, both services, since boot.
sudo journalctl -u sift-gateway.service -u sift-job-worker.service -n 200 --no-pager
```

### 9.2 Service JSONL logs

Verified present under `/var/lib/sift/.sift/logs/` (mode `0700` dir):

| File | Contents |
| --- | --- |
| `sift-gateway.jsonl` | gateway structured log |
| `forensic-rag-mcp.jsonl` | RAG backend structured log |

```bash
# Read-only. Pretty-print the last lines with jq.
sudo tail -n 50 /var/lib/sift/.sift/logs/sift-gateway.jsonl | jq .
```

Logs are redacted by `response_guard` / audit redaction in code; still, do not
copy log lines containing tokens, DSNs, or full case paths into shared docs.

---

## 10. Audit checks

The audit log is **DB-authoritative**: `app.audit_events`. Per-case
`audit/*.jsonl` files are a labelled file-mirror (`legacy-file-mirror` vs
`db-audit-events`), not the authority.

```bash
# Recent audit activity by action type (counts only — no payloads).
docker exec supabase_db_sift-mcps psql -U postgres -d postgres -tA -c \
  "select action, count(*) from app.audit_events
   group by action order by count(*) desc limit 25;"
```

Sensitive-action audit trail to expect: re-auth events for case activation,
evidence seal/ignore/retire, finding approval, report inclusion/export, and
agent credential issuance (`reauth.<action>` rows written by
`record_reauth_event`). A required audit write that fails raises
`AuditPersistError` (fail-closed) — if tool calls start failing with that, the
DB is unreachable; see §12.

---

## 11. TLS / CA trust

**Profile: internal/local CA (BATCH-TLS1 / B-MVP-001).** The IP-only lab VM uses
a long-lived local certificate authority that signs the gateway's serving
certificate. This is the right profile for a libvirt VM reachable only by IP —
public ACME/Let's Encrypt certs require a DNS name and a reachable challenge
(see "Deferred: ACME / domain profile" below).

The installer (`generate_tls` in `install.sh`) creates the material under
`/var/lib/sift/.sift/tls/` (dir `0700`, `sift-service`):

| File | Mode | Role |
| --- | --- | --- |
| `ca-cert.pem` | `0644` | local CA certificate (public — give to clients) |
| `ca-key.pem` | `0600` | CA private key — **secret, never distribute** |
| `gateway-cert.pem` | `0644` | gateway TLS certificate / leaf (public) |
| `gateway-key.pem` | `0600` | gateway TLS private key — **secret** |

Certificate facts:

- **CA** `CN=Protocol SIFT Gateway local CA`, RSA-4096, valid **10 years**,
  `basicConstraints=critical,CA:TRUE`, `keyUsage=keyCertSign,cRLSign`.
- **Leaf** RSA-4096, valid **2 years**, `CA:FALSE`,
  `extendedKeyUsage=serverAuth` (required by Chrome/modern clients), and a
  **derived** SAN list: the VM's primary IP (from `hostname -I`) + `127.0.0.1` +
  the hostname + `localhost`. SANs are not hardcoded; they follow the VM's IP.
- The CA outlives every leaf it signs, so the leaf can be renewed without
  re-trusting the CA.

### 11.1 Trust the CA on a client (do this ONCE)

Copy the **CA cert** to the client (`ca-cert.pem`, also in the handoff as
`ca_cert=`). Never copy `ca-key.pem` or `gateway-key.pem`.

```bash
# On the VM: stage a copy you can scp off-box.
sudo cp /var/lib/sift/.sift/tls/ca-cert.pem /tmp/sift-ca.pem
sudo chmod 644 /tmp/sift-ca.pem
# Then from the client:  scp sansforensics@<VM_IP>:/tmp/sift-ca.pem ./sift-ca.pem
```

- **Firefox:** Settings → Privacy & Security → Certificates → View Certificates →
  Authorities → Import → select `sift-ca.pem` → trust for websites.
- **Chrome/Chromium:** Settings → Privacy and security → Security → Manage
  certificates → Authorities → Import → `sift-ca.pem`.
- **Python / MCP clients (requests, httpx, etc.):**
  `export REQUESTS_CA_BUNDLE=/path/to/sift-ca.pem`
  and `export SSL_CERT_FILE=/path/to/sift-ca.pem`.
- **curl:** `curl --cacert /path/to/sift-ca.pem https://<VM_IP>:4508/health`.

On-box checks use loopback, which is in the SAN list, so
`curl --cacert /var/lib/sift/.sift/tls/ca-cert.pem https://127.0.0.1:4508/health`
verifies without `-k`. (Operator runbooks still use `curl -sk` for brevity.)

### 11.2 Renewing the leaf (safe — no client re-trust)

When the leaf nears expiry, or the VM's primary IP changed, renew the leaf
against the **existing** CA. Clients that already trust the CA keep working.

```bash
sudo ./scripts/rotate-tls.sh --renew-leaf
```

This issues a fresh `gateway-key.pem`/`gateway-cert.pem` with SANs re-derived
from the current IP, installs them `sift-service`-owned (`0600`/`0644`), restarts
`sift-gateway.service`, verifies `/health`, and prints a sanitized cert summary.
No private key material is printed. The CA fingerprint is unchanged.

### 11.3 Rotating the CA (DANGER — all clients lose trust)

Only if the CA key is compromised or expiring. **Every** client must re-import
the new `ca-cert.pem` afterward, or TLS fails closed.

```bash
sudo ./scripts/rotate-tls.sh --rotate-ca --i-understand-clients-lose-trust
```

The confirmation flag is mandatory; the script refuses `--rotate-ca` without it.
After rotation, redistribute the new `ca-cert.pem` (§11.1) to every client.

> The same CA also backs the gateway's OpenSearch client trust
> (`gateway.yaml` → `opensearch.ca_cert_path: .../tls/ca-cert.pem`). A CA
> rotation is picked up by the gateway restart that `rotate-tls.sh` performs.

### 11.4 Deferred: ACME / domain profile (future)

A public ACME/Let's Encrypt certificate is **not** built in this profile and is
deferred (B-MVP-001). Prerequisites before it could be adopted:

- a real DNS name pointing at the gateway (not an IP-only libvirt VM);
- a reachable ACME challenge path (HTTP-01 on port 80, or DNS-01 with API access);
- a renewal daemon (`certbot`/`acme.sh`) writing into `SIFT_TLS_DIR` with the
  same `certfile`/`keyfile` names `gateway.yaml` already references, plus a
  deploy hook that restarts `sift-gateway.service`.

Until those exist, the local-CA profile above is the supported path.

---

## 12. Failure recovery

| Symptom | Likely cause | Action |
| --- | --- | --- |
| `/health` not `status=ok`; a backend `degraded` | stdio backend failed to mount / crashed | check `journalctl -u sift-gateway`; restart gateway (§2.2) |
| `/health` shows `supabase.status` not ok; tools fail with `AuditPersistError` | Supabase/Postgres down | `docker ps` (expect `supabase_db_sift-mcps` healthy); `docker compose` / `supabase start` per setup; restart gateway |
| Portal login fails for the temp password | already reset, or wrong key read | use the post-reset password; if lost, admin-reset via Supabase (§1.4) — not recoverable from files |
| Jobs stuck / not progressing | worker wedged or lease held | restart `sift-job-worker.service`; `app.expire_stale_jobs()` reclaims stale leases |
| OpenSearch `red` (not `yellow`) | container down / disk | `docker ps` for `sift-opensearch`; check container logs; restart container |
| `hayabusa` looks "missing" to the login user | symlink target only traversable as `sift-service` | not a fault; verify as `sift-service`/root (OR1 §6), do not "fix" |
| MCP `/mcp` rejects an operator Supabase token (`invalid_token`) | expected — operator login token is not an MCP credential | issue a portal agent/service credential for MCP; operator REST is human-only |
| Service restart but config change ignored | edited a generated file the wrong way / wrong file | re-check the path in `config-and-secrets.md`; some values are inline in `gateway.yaml`, some are env-indirected |

### Recovery order of operations

1. `curl -sk https://127.0.0.1:4508/health` — narrow to gateway vs backend vs DB.
2. `docker ps` — confirm `supabase_db_sift-mcps` and `sift-opensearch` are up
   and healthy.
3. `sudo journalctl -u sift-gateway.service -n 200` — read the actual error.
4. Restart the affected service (§2.2). Durable jobs survive restarts.
5. If state looks corrupt, restore from backup (§4.4) onto an intended target.
6. Record sanitized proof of the recovery in `docs/migration/Session-Notes.md`.

---

## 13. "What not to edit manually" (pointer)

Several files are **generated by the installer** and must not be hand-edited —
doing so risks startup failure, drift from the DB, or a broken handoff. The full
list with reasons is in `docs/operator/config-and-secrets.md` §"Do not hand-edit"
and includes:
`~/.sift/supabase-project/sift-supabase.env`,
`/var/lib/sift/.sift/*.env`,
`/var/lib/sift/.sift/gateway.yaml`,
`/var/lib/sift/.sift/opensearch.yaml`,
`/var/lib/sift/.sift/forensic-knowledge.env`,
`/var/lib/sift/tokens/installer-handoff.txt`, and the TLS material.

---

## 14. Uninstall / teardown (B-MVP-007, BATCH-UN1)

`scripts/uninstall.sh` removes all or a selected subset of installed components.
It is **dry-run by default** — run it without `--yes` to see exactly what would
be deleted before committing.

### `scripts/uninstall.sh` is the single canonical teardown path

`scripts/uninstall.sh` is the one supported uninstall/reset script. (The older
`scripts/reset-vm-test.sh` was a stale duplicate and has been **removed**.)
`./install.sh --uninstall` is now a thin **delegating shim** that calls
`scripts/uninstall.sh` for the software-only teardown (service, venv, `~/.sift`,
auditd/AppArmor) and **never** removes data or evidence — there is no
`--purge-data` flag on `install.sh` anymore (issue #16, D5: the installer has no
evidence-deletion code path). Use `scripts/uninstall.sh` directly for the
**comprehensive** path: it is component-selectable, dry-run by default, gated,
and tears down the OpenSearch ingest/enrich workers, the Supabase data volume,
and residual per-case state. Evidence under `/cases` is removable **only** by
`scripts/uninstall.sh` with its multi-gated evidence-removal flags + typed
`DELETE EVIDENCE` confirmation.

### Evidence is NEVER removed by default

`/cases` (the forensic evidence root) has the highest blast radius. It is **never
touched** by `--all` or any component flag. Removing evidence requires three
explicit gates on the command line:

```bash
# This is the ONLY path that can remove /cases — all three flags are required.
./scripts/uninstall.sh --remove-evidence --i-understand-evidence-loss --yes
```

An interactive "DELETE EVIDENCE" prompt is shown even then.

### 14.1 Dry-run (safe — prints what would be removed)

```bash
# Interactive menu (no flags) — select components and see what would change.
./scripts/uninstall.sh

# Non-interactive dry-run of specific add-on(s):
./scripts/uninstall.sh --components opencti
./scripts/uninstall.sh --components opencti,opensearch

# Non-interactive dry-run of a full teardown:
./scripts/uninstall.sh --all
```

### 14.2 Available components

| Token | What it removes | Core/Add-on |
| --- | --- | --- |
| `opencti` | OpenCTI Docker stack, named volumes, images (~4.4 GB), OpenCTI secret files under `/var/lib/sift/.sift/` | add-on |
| `opensearch` | OpenSearch Docker stack (`docker-compose.yml`) torn down with `down -v`, **plus an explicit `docker volume rm` fallback for the `<project>_opensearch-data` data volume**, the pinned image, the `sift-net` network, and OpenSearch config files | add-on |
| `supabase` | Supabase CLI local stack (`supabase stop`), CLI binaries, `~/.sift/supabase-project/sift-supabase.env`, **+ the project-scoped Supabase data volume** (`supabase_db_<project>` — greenfield reset, so a reinstall migrates against a fresh DB; `supabase stop` alone preserves it) | core |
| `systemd` | `sift-gateway.service` + `sift-job-worker.service` units, **plus every dynamically-discovered `sift-opensearch-worker@N.service` instance and the `sift-opensearch-worker@.service` template unit** (also stops the auto parent slice and runs `systemctl reset-failed 'sift-*'`), service user `sift-service`, groups, `agent_runtime` user, sudoers drop-ins, hayabusa symlink | core |
| `runtime` | `/opt/sift-mcps` staged tree, `.venv`, `/var/lib/sift/.sift/` (config, TLS, secrets, hayabusa, logs), enrichment symlinks | core |
| `state` | `/var/lib/sift/{verification,tokens,snapshots,enrichment,.cache}`, **plus a sweep of all other residual top-level entries under `/var/lib/sift`** — per-case audit/ledger sidecars (`<case_key>/evidence-ledger.jsonl`, `evidence-manifest.json`, `audit/`), the service user's `.local/share/fastmcp`, and add-on baseline DB trees (e.g. windows-triage `*.db`, up to ~17 GB incl. the registry baseline). A canonical-path guard **never** removes `/cases` (the evidence root) or an ancestor of it | core |
| `cache` | `/var/cache/sift/` (Volatility3 symbols), Hugging Face model cache | core |
| `auditd` | `/etc/audit/rules.d/99-sift-evidence.rules`; reload auditd | core |
| `apparmor` | `/etc/apparmor.d/sift-gateway`; unload profile | core |
| `tls` | `/var/lib/sift/.sift/tls/` (CA key, gateway key, certs); remove `user_allow_other` from `/etc/fuse.conf` | core |

`--all` selects every token above (but never `/cases`).

### 14.3 Remove add-ons only (core stays running)

Removing `opencti` and/or `opensearch` does **not** disturb the SPG core. The
gateway and portal stay up; only those Docker stacks and their config files are
removed.

```bash
# DANGER: removes OpenCTI images + volumes (irreversible data loss for OpenCTI data).
./scripts/uninstall.sh --components opencti --yes

# DANGER: removes OpenSearch stack + indexed forensic evidence in opensearch-data.
./scripts/uninstall.sh --components opensearch --yes

# Both at once:
./scripts/uninstall.sh --components opencti,opensearch --yes
```

Neither confirmation gate (`--i-understand`) is required for add-on-only removal
because core SPG is unaffected. The `--yes` flag still required to actually delete.

### 14.4 Full teardown (all components — core + add-ons)

`--all` is the only path that tears down the SPG core. Both `--yes` and
`--i-understand` are required; otherwise the script exits with an error.

```bash
# Dry-run first (no --yes):
./scripts/uninstall.sh --all

# DANGER: removes everything except /cases.
# Services stop, units removed, user deleted, secrets wiped.
./scripts/uninstall.sh --all --yes --i-understand
```

After a full teardown, reinstall with:

```bash
./install.sh
```

### 14.5 Confirmation gates summary

| Scenario | Required flags |
| --- | --- |
| Dry-run (any selection) | none (default) |
| Add-on only (`opencti`, `opensearch`) | `--yes` |
| Core component(s) | `--yes` + `--i-understand` |
| Full teardown (`--all`) | `--yes` + `--i-understand` |
| Evidence (`/cases`) removal | `--remove-evidence` + `--i-understand-evidence-loss` + `--yes` + type "DELETE EVIDENCE" at prompt |

### 14.6 What is NOT removed

Even with `--all --yes --i-understand`, two things survive:

- `/cases` — the evidence root (forensic data; removing it requires the three
  evidence flags **plus** the typed `DELETE EVIDENCE` prompt, see above).
- The source repo clone itself (the checkout you ran the script from).

> **Changed (XYE-41):** `--all` now **does** remove the project-scoped Supabase
> data volume (`supabase_db_<project>`) so a reinstall migrates against a fresh
> database. The earlier guidance — that the Supabase Docker volume is preserved
> by `supabase stop` and recovered by `supabase start` — no longer holds for a
> full teardown. If you need the control-plane DB, take a `pg_dump` (§4.2)
> **before** running `--all` or the `supabase` component.

### 14.7 Override paths

If the install used non-default paths, override with:

```bash
./scripts/uninstall.sh --install-root /custom/path \
                       --state-dir /custom/var/lib/sift \
                       --cases-root /custom/cases \
                       --service-user my-service-user \
                       --execute-as my-runtime-user \
                       --all --yes --i-understand
```

### 14.8 Orphaned-data backup on a fresh install (XYE-42)

`scripts/uninstall.sh` preserves `/cases` (and can leave other state) by design,
so a later **fresh** install may find orphaned data that no longer matches the
new, empty control plane. To avoid both data loss and silent collisions,
`install.sh` moves that data aside before it provisions clean directories.

- **When it triggers:** only on a **fresh** install — detected by the *absence*
  of prior gateway config at `$SIFT_HOME` (`/var/lib/sift/.sift`). An idempotent
  re-run / in-place upgrade keeps `$SIFT_HOME`, so a **live/active case is never
  moved**.
- **What it moves:** `/cases` and/or `/var/lib/sift`, when present and non-empty
  (typically orphaned by a prior `scripts/uninstall.sh` run).
- **Where it goes:** a timestamped backup at
  `/var/backups/sift/preinstall-<timestamp>/`. Override the location with the
  `SIFT_PREINSTALL_BACKUP_DIR` environment variable. The installer prints a
  `WARNING` naming exactly where the data went, then proceeds with clean
  directories.
- **How:** a fast same-filesystem `mv` (a rename — works even on `chattr +i`
  sealed evidence), with a copy-then-purge fallback across filesystems.
- **Cleanup note:** the backup may contain write-protected (`chattr +i`)
  evidence — clear the immutable flag with `sudo chattr -R -i <backup>` before
  removing it.
