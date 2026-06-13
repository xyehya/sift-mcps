# Component Hardening Audit Guide (BATCH-HR2)

Status: **audit guide** — executable on the SIFT VM by an operator or reviewer.
This batch makes **no** code, config, installer, or VM change. It converts the
HR1 research matrix (`docs/hardening/research-matrix.md`) into per-component
checks, expected output, and concrete next steps with owner batches.

- Repo posture is read from the checked-in source on branch
  `batch/hr2-component-audit`.
- **Live runtime facts are verified on `sansforensics@192.168.122.81` and labelled
  `verified 2026-06-12`.** All live checks below were run read-only (no writes,
  restarts, or config changes).
- Variable/path facts are reused from OR1 (`docs/inventory/sift-tool-inventory.md`),
  OR2 (`docs/operator/state-authority-map.md`), and OR3
  (`docs/operator/config-and-secrets.md` + `maintenance-guide.md`) — see those
  docs for the source-of-truth tables; this guide does not re-derive them.

## How to use this guide

Each component section has: **Purpose**, **Current posture** (with the live
verification result where applicable), **Threats**, **Checks** (exact commands +
expected output shape), **Config paths / service names**, **DB queries**
(redacted: row counts / key names / boolean flags only), **Logs**, **Tests**,
**Remediation plan**, **Residual risk**, **Risk rating**, and **Owner batch**.

### Conventions

- **Risk ratings** reflect the **current lab framing** (localhost binds, single
  tenant, libvirt-only network). Several MEDIUMs become HIGH if the VM is exposed
  off-host or treated as production — noted inline as `MEDIUM (lab) / HIGH (exposed)`.
- **`[DANGER]`** marks a command that is destructive or service-affecting. This
  batch did **not** run any `[DANGER]` command; an auditor must understand the
  blast radius before running one.
- **Redaction rule:** never print secret values, JWTs, DSNs, private keys, DB
  password hashes, or the SSH password. DB checks emit row counts, key **names**,
  and boolean flags only. Secret-equality is proven by comparing a sha256 of the
  value against a known hash **on the VM**, emitting only `MATCH` / `NO-MATCH`.

### SSH access pattern (auditor)

```bash
# read-only remote command
sshpass -p '<vm-pw>' ssh -o StrictHostKeyChecking=accept-new sansforensics@192.168.122.81 '<cmd>'
# sudo (non-interactive)
... 'echo <vm-pw> | sudo -S <cmd> 2>/dev/null'
```

Do not paste the password into any committed artifact.

---

## Severity rollup (this audit, live-confirmed 2026-06-12)

| # | Component | Rating | Owner | Live-confirmed finding |
| --- | --- | --- | --- | --- |
| 12 | systemd hardening (no directives) | HIGH | HR3 | **exposure 9.2 UNSAFE** for both units (`systemd-analyze security`) |
| 7 | Supabase demo keys + default DB password | HIGH | HR3 (rotation) | anon/service-role keys + DB password all **MATCH demo** (B-MVP-012) |
| 11 | auditd evidence/secret watches | HIGH | HR3 | **auditd is NOT installed** on the VM — `auditctl` missing, no `/etc/audit/rules.d/` (contradicts HR1 §11) |
| 13 | AppArmor complain-only | HIGH→MED | HR3/CL1 | sift profile loaded in **complain mode** on the **correct** `/opt` path (path-mismatch from HR1 §10 is NOT present live) |
| 9 | RAG/HF offline + model identity | HIGH (offline) / MED | HR3 (B-MVP-004) | cached model is **`BAAI/bge-base-en-v1.5`**, NOT the HR1 allowlist — contradicts HR1 §13 |
| 6 | OpenSearch security plugin disabled | MED (lab, accepted) | HR3 (B-MVP-005) | security plugin off (HTTP 400), cluster yellow, 127.0.0.1 only — **accepted** per B-MVP-005 |
| 5 | Docker container hardening | MED | HR3 (B-MVP-005) | OpenSearch runs **non-root (User=1000)** but **no cap_drop / no-new-privileges / writable rootfs** |
| 8 | Postgres RLS not FORCEd | MED (reduced from HIGH) | DB1 **DONE**; HR3 (key rotation) | all 31 `app.*` tables **RLS-enabled**; FORCE adopted in DB1 (`202606131000`); service-role carries BYPASSRLS (unaffected); key rotation still open (HR3) |
| 14 | Hayabusa unpinned/unverified download | MED | HR3 (B-MVP-004) | binary present, installed from "latest", no checksum recorded |
| 3 | uv `curl\|sh` bootstrap unpinned | MED | HR3 (B-MVP-004) | install-time supply chain |
| 1 | Host firewall default-deny | MED (lab) / HIGH (exposed) | HR3/operator | **ufw inactive**; only docker-managed nft tables present |
| 4 | Gateway 0.0.0.0 bind + legacy-auth flags | MED / LOW | HR2 doc / CL1 | binds `0.0.0.0:4508`; `legacy.token` + `portal_session_enabled: true` present |
| 10 | TLS self-signed, renewal undocumented | MED | TLS1 (B-MVP-001) | cert **carries IP SAN 192.168.122.81** (resolves HR1 §12 open Q); valid to 2028 |
| 16 | Evidence custody chain | LOW (well-built) | report-only | DB-authoritative append-only ledger; live `/cases` writable, write_protected=false, 0 cases |
| 15 | Inline portal session secret | LOW | HR3 (B-MVP-010) | `session_secret` is **inline** in `gateway.yaml` (confirmed) |
| 17 | Reports / exports gate | LOW | report-only | approved-only inputs; re-auth gated |
| 2 | Add-on manifest model | LOW | AD1/AD2 | env-ref secret model sound; doc/conformance gap only |
| 18 | Worker sandbox / run_command | MED | HR3/PT-track | service user **not in docker group** (good); no OS-level sandbox on spawned tools |
| — | Secrets / file modes / PBKDF2 | INFO (strength) | regression-watch | all secret files `0600 sift-service`, TLS keys `0600`, `.sift` `0700` — verified |

**Cross-cutting decisions already locked (do not re-litigate):** B-MVP-004
(pin+checksum downloads + offline mode → HR3), B-MVP-005 (accept loopback OpenSearch
no-auth; harden container → HR3), B-MVP-010 (env-indirect session secret → HR3),
B-MVP-011 (CL1 retires legacy PBKDF2/HMAC fallbacks after read-only proof),
B-MVP-012 (this batch verifies demo keys — **confirmed in use**), B-MVP-013 (this
batch reports RLS posture read-only — **enabled but not FORCEd**).

---

# Section A — Smaller / supporting surfaces

## 1. Host OS baseline & firewall

- **Purpose.** The SANS SIFT (Ubuntu 24.04) host carries the whole stack; its
  network exposure and patch posture bound everything else.
- **Current posture.** Installer stages to `/opt/sift-mcps` and provisions system
  services; it does **not** apply a CIS host baseline (operator scope). Target
  Python `/usr/bin/python3.12`; managed-Python downloads disabled
  (`UV_NO_MANAGED_PYTHON=1`, `UV_PYTHON_DOWNLOADS=never`).
  **verified 2026-06-12:** host = `Ubuntu 24.04.4 LTS`, kernel `6.8.0-110-generic`,
  hostname `siftworkstation`. **`ufw` is inactive** (empty `ufw status`); the only
  nftables tables present are docker-managed (`ip/ip6 nat/filter/raw`), i.e. no
  host default-deny inbound policy. Listening sockets: `0.0.0.0:4508` (gateway),
  `127.0.0.1:9200/54321/54322` (OpenSearch + Supabase docker-proxy).
- **Threats.** If the VM is ever bridged/exposed, `4508` is reachable from any
  interface with only TLS+JWT in front of it; no host firewall narrows it.
- **Checks.**
  ```bash
  ss -tlnp | grep -E '4508|9200|5432'          # expect 4508 on 0.0.0.0; 9200/5432x on 127.0.0.1
  sudo ufw status                               # currently: inactive
  sudo nft list tables                          # currently: only docker-managed tables
  cat /etc/os-release | grep -E '^VERSION='     # Ubuntu 24.04.x
  systemctl is-enabled unattended-upgrades 2>/dev/null   # auditor records state
  ```
- **Expected output shape.** `4508` LISTEN on `0.0.0.0`; data stores on `127.0.0.1`;
  `ufw` either `inactive` (current) or a default-deny ruleset after remediation.
- **Logs.** `journalctl -k | grep -i nft`; `/var/log/ufw.log` if ufw enabled.
- **Tests.** From off-host, `nc -vz 192.168.122.81 9200` must fail (localhost-bound);
  `:4508` reachable (TLS).
- **Remediation plan.** HR3/operator: add an explicit default-deny inbound firewall
  allowing only `4508` (and SSH from the operator subnet); leave data-store ports
  localhost-only. Document the expected baseline; host image hardening itself stays
  operator-owned.
- **Residual risk.** Lab network trust still assumed; firewall does not protect
  against a compromised local process.
- **Risk rating.** MEDIUM (lab) / HIGH (exposed).
- **Owner batch.** HR3 (firewall, if approved safe-for-core) / operator (host image).

## 2. MCP / add-on manifest model

- **Purpose.** Defines how external add-ons (OpenCTI today) register tools through
  the Gateway without code changes; the env-ref secret model is the trust boundary.
- **Current posture.** Add-on backends declared by JSON manifest validated against
  `packages/sift-gateway/src/sift_gateway/sift-backend.schema.json`; authority is
  the DB row `app.mcp_backends` (`manifest_sha256`, `health_status`, non-secret
  `connection`). Secrets are **env-var references** (`bearer_token_env`,
  `tls_cert_env`, `env_refs`); usable values live only in the gateway process env.
  Raw secrets in a manifest are rejected by CHECK + validators
  (`202606080100_mcp_backends_registry_hardening.sql`). OpenCTI
  (`packages/opencti-mcp/sift-backend.json`) registers via `scripts/setup-addon.sh`,
  never in the core path. **verified 2026-06-12:** `/health` shows core backends
  `forensic-rag-mcp` + `opensearch-mcp` mounted (`mounted_proxy:true`), 17 tools.
- **Threats.** Duplicate/shadowed tool names; an add-on claiming authority it should
  not have; a manifest smuggling a literal secret.
- **Checks.**
  ```bash
  curl -sk https://127.0.0.1:4508/health | python3 -m json.tool   # backends + tools_count
  # manifest validates against schema (host-side):
  python3 -c "import json,jsonschema; ..."   # AD2 conformance harness owns this
  ```
- **DB query (redacted).**
  ```sql
  select name, namespace, transport, enabled, health_status from app.mcp_backends;
  -- expect: core backends enabled; add-ons only if registered; no secret columns present
  ```
- **Remediation plan.** Documentation/conformance gap only — owned by **AD1**
  (author spec + checklist) and **AD2** (conformance tests + OpenCTI external-only
  proof; Windows-triage is B-MVP-003). No core security gap in the model.
- **Residual risk.** Until AD2 lands, negative cases (missing env ref, denied scope,
  duplicate tool) are not regression-tested.
- **Risk rating.** LOW (security).
- **Owner batch.** AD1 / AD2 (not HR3).

## 3. Python / uv supply chain

- **Purpose.** uv builds the entire runtime; bootstrap integrity = build integrity.
- **Current posture.** uv-managed workspace; VM forbids managed-Python
  (`--no-managed-python --no-python-downloads`). `requires-python>=3.10`; VM target
  3.12. **uv itself is bootstrapped via `curl -LsSf https://astral.sh/uv/install.sh
  | sh`** (`install.sh`) with **no version pin / no checksum** — contrast the
  Supabase CLI which is pinned + SHA256-verified (the model to copy).
- **Threats.** Compromised or moved install script silently changes the toolchain
  that builds the venv.
- **Checks.**
  ```bash
  /opt/sift-mcps/.venv/bin/python --version        # 3.12.x
  uv --version                                     # auditor records the version
  grep -n 'astral.sh/uv/install.sh' install.sh     # confirm unpinned bootstrap
  ```
- **Remediation plan.** HR3 (B-MVP-004): pin a uv version + verify checksum before
  exec, mirroring the Supabase CLI pattern, or pre-stage uv as an operator artifact
  under the offline policy.
- **Residual risk.** First-ever bootstrap still trusts TLS to astral.sh unless
  fully offline.
- **Risk rating.** MEDIUM.
- **Owner batch.** HR3 (ties B-MVP-004).

## 4. Gateway bind + legacy-auth flags

- **Purpose.** The Gateway is the **sole** policy boundary for portal + agent ops.
- **Current posture.** Strong app-layer headers and CORS:
  `Strict-Transport-Security`, `X-Frame-Options: DENY`, CSP, restricted CORS
  allow-list (not `*`) in `packages/sift-gateway/src/sift_gateway/server.py`.
  Unified Supabase JWT auth (D30/PR03A). **verified 2026-06-12:** `/health` returns
  HSTS `max-age=31536000; includeSubDomains` and `X-Frame-Options: DENY`; gateway
  binds **`0.0.0.0:4508`**; `gateway.yaml` carries `auth.legacy.token` (redacted)
  and `portal_session_enabled: true` (legacy compatibility flags still on). An
  operator Supabase login token is rejected at `/mcp` (per Session-Notes); a
  portal-issued agent token is accepted.
- **Threats.** `0.0.0.0` bind + no host firewall = listener on every interface;
  legacy fallback tokens are an additional credential surface to sunset.
- **Checks.**
  ```bash
  curl -ski https://127.0.0.1:4508/health | grep -iE 'strict-transport|x-frame'
  ss -tlnp | grep 4508                              # 0.0.0.0:4508
  sudo grep -nE 'portal_session_enabled|legacy' /var/lib/sift/.sift/gateway.yaml  # names only
  ```
- **Remediation plan.** HR2 documents the bind/firewall expectation (see §1); legacy
  flag sunset is a **CL1/RG1** concern (not a fork). Narrowing the bind to a single
  interface is HR3-only if approved safe-for-core.
- **Residual risk.** Legacy token path remains until CL1 retires it.
- **Risk rating.** MEDIUM (bind) / LOW (legacy flags — intentional bridge).
- **Owner batch.** HR2 (doc) / CL1 (legacy sunset) / HR3 (bind, if approved).

## 15. Inline portal session secret (B-MVP-010)

- **Purpose.** Signs portal sessions; should not sit in cleartext config alongside
  non-secret settings.
- **Current posture.** **verified 2026-06-12:** `gateway.yaml` holds
  `portal.session_secret` **inline** (value redacted), unlike the DSN/pepper which
  are env-indirected via `control-plane.env`. `gateway.yaml` is `0600 sift-service`.
- **Threats.** A config-file read (e.g. accidental backup with looser perms) leaks
  the session signing key.
- **Checks.**
  ```bash
  sudo grep -n 'session_secret' /var/lib/sift/.sift/gateway.yaml   # confirms inline (name only)
  sudo stat -c '%a %U' /var/lib/sift/.sift/gateway.yaml            # expect 600 sift-service
  ```
- **Remediation plan.** **B-MVP-010 DECIDED** → HR3 env-indirects
  `portal.session_secret` like the DSN/pepper. No re-litigation.
- **Residual risk.** Until HR3, the secret co-locates with config (mitigated by
  `0600`).
- **Risk rating.** LOW.
- **Owner batch.** HR3 (B-MVP-010).

---

# Section B — Data plane & search

## 5. Docker / Compose (OpenSearch container)

- **Purpose.** Runs the core search engine; container privilege posture bounds a
  container-escape blast radius.
- **Current posture.** Core `docker-compose.yml` pins
  `opensearchproject/opensearch:3.5.0`, binds `127.0.0.1:9200`, healthcheck +
  ulimits. **verified 2026-06-12 (`docker inspect sift-opensearch`):**
  `User=1000` (**non-root** — better than HR1 §3 assumed), but `CapAdd=[]`,
  **`CapDrop=[]`** (no caps dropped), **`SecurityOpt=[]`** (no `no-new-privileges`),
  **`ReadonlyRootfs=false`**, `Privileged=false`. Image pinned by **tag** 3.5.0
  (running digest `sha256:dbb016…`, not a compose-pinned digest). The Docker socket
  is `root:docker 0660`; **`sift-service` is NOT in the `docker` group** (only
  `sansforensics` is) — the service user cannot reach the Docker daemon (positive
  finding, not in HR1).
- **Threats.** Default capability set + writable rootfs widen a container-escape;
  a re-pointed `3.5.0` tag upstream is undetectable without a digest pin.
- **Checks.**
  ```bash
  sudo docker inspect sift-opensearch --format \
    'User={{.Config.User}} CapDrop={{.HostConfig.CapDrop}} SecurityOpt={{.HostConfig.SecurityOpt}} RoRootfs={{.HostConfig.ReadonlyRootfs}} Priv={{.HostConfig.Privileged}}'
  getent group docker            # confirm sift-service absent
  ls -l /var/run/docker.sock     # root:docker 0660
  ```
- **Remediation plan.** **B-MVP-005 DECIDED** → HR3 adds
  `security_opt: [no-new-privileges:true]`, `cap_drop: [ALL]` (+ any required
  add-backs), considers a digest pin, keeps non-root. No re-litigation of the
  loopback-no-auth decision.
- **Residual risk.** localhost bind limits blast radius today.
- **Risk rating.** MEDIUM.
- **Owner batch.** HR3 (B-MVP-005).

## 6. OpenSearch (security plugin / TLS / auth)

- **Purpose.** Search/evidence index plane.
- **Current posture.** Single-node, **`DISABLE_SECURITY_PLUGIN=true`**, plain HTTP
  on `127.0.0.1:9200`. **verified 2026-06-12:**
  `GET /_plugins/_security/health` → **HTTP 400** (security plugin disabled);
  `GET /_cluster/health` → `status:yellow`, 1 node, 15 active primary shards;
  socket is `127.0.0.1:9200` only (docker-proxy). Gateway reaches it on
  `http://127.0.0.1:9200` (`gateway.yaml opensearch.url`). Client config
  `/var/lib/sift/.sift/opensearch.yaml` (`0600`) carries `host/user/password/verify_certs`.
- **Threats.** No auth/TLS/audit on the store — mitigated only by the localhost bind
  and the fact that only `sift-service` processes reach it.
- **Checks.**
  ```bash
  curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9200/_plugins/_security/health  # 400/404 = disabled
  curl -s http://127.0.0.1:9200/_cluster/health | python3 -m json.tool   # status green/yellow
  ss -tlnp | grep 9200          # 127.0.0.1 only
  ```
- **DB query (redacted).**
  ```sql
  select count(*) from app.opensearch_indices;          -- index registry size
  select count(*) from app.opensearch_ingest_provenance; -- ingest provenance rows
  ```
- **Remediation plan.** **B-MVP-005 DECIDED:** accept security-plugin-disabled on
  loopback for the single-node lab (Gateway is the sole boundary); HR3 hardens the
  **container** (see §5) and documents snapshot policy + replica limits. Revisit only
  if OpenSearch leaves loopback.
- **Residual risk.** A multi-node or off-host move flips this to HIGH and requires
  re-opening B-MVP-005.
- **Risk rating.** MEDIUM (lab, accepted) / HIGH (off-loopback).
- **Owner batch.** HR3 (container) — posture decision locked.

## 7. Supabase CLI / Auth / control plane keys (B-MVP-012)

- **Purpose.** Supabase/Postgres is the authoritative control plane; its keys gate
  every DB-backed authority.
- **Current posture.** `scripts/setup-supabase.sh` pins the Supabase CLI to
  **v2.105.0** and **SHA256-verifies** the tarball — a good supply-chain model.
  Brings up only `db + auth (gotrue) + api (kong)`. Gateway reads
  `SUPABASE_URL/ANON/SERVICE_ROLE_KEY` from env (`supabase.env`, `0600`).
  **verified 2026-06-12 (B-MVP-012 — values never printed, sha256-compared on VM):**
  - `SUPABASE_ANON_KEY` JWT `iss=supabase-demo`, `role=anon`; sha256 → **MATCH** the
    known Supabase CLI demo anon key.
  - `SUPABASE_SERVICE_ROLE_KEY` JWT `iss=supabase-demo`, `role=service_role`; sha256
    → **MATCH** the known demo service-role key.
  - Control-plane DSN password sha256 → **MATCH** the default `postgres`; DSN host =
    `127.0.0.1:54322`.
  - `/health` reports `supabase.url = http://127.0.0.1:54321` (plain HTTP, localhost).

  > **Verdict:** the live VM runs **all three** Supabase CLI demo secrets (anon key,
  > service-role key, default DB password). These are publicly known values.
- **Threats.** The service-role key bypasses RLS (see §8). If the DSN/keys ever
  leave the host (backup, off-host connection, exposed `:54322`), they are
  trivially reusable because they are the documented demo values.
- **Checks (redacted — emit MATCH/NO-MATCH only).**
  ```bash
  # decode ONLY the JWT payload iss/role; never print the key:
  ANON=$(sudo grep '^SUPABASE_ANON_KEY=' /var/lib/sift/.sift/supabase.env | cut -d= -f2-)
  echo "$ANON" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | grep -oE '"iss":"[^"]*"'
  # equality test: sha256(live) vs sha256(known-demo), output MATCH/NO-MATCH only
  ```
- **Remediation plan.** **B-MVP-012 DECIDED:** because demo keys are confirmed in
  use, **HR3 adds a rotation step** (generate a fresh JWT signing secret + anon/
  service-role keys + DB password, rewrite `supabase.env`/`control-plane.env`,
  restart). This cross-cuts TLS1 and the portal reset flow.
- **Residual risk.** Until HR3 rotation, any DSN/key leak is immediately exploitable.
- **Risk rating.** HIGH (production framing) / MEDIUM (localhost lab today).
- **Owner batch.** HR3 (rotation).

## 8. Postgres RLS / pgvector posture (B-MVP-013)

- **Purpose.** RLS is defence-in-depth behind the Gateway boundary; pgvector is the
  knowledge-only RAG store.
- **Current posture (B-MVP-013, read-only — verified 2026-06-12).** Queried via
  `sudo docker exec supabase_db_sift-mcps psql -U postgres`:
  - `pg_class` over schema `app`: **31 of 31 base tables have `relrowsecurity=t`
    (RLS ENABLED)** and **0 of 31 have `relforcerowsecurity=t` (none FORCEd).**
  - `pg_policies`: most tables carry **1 policy**; a subset have RLS enabled with
    **0 policies = default-deny for ordinary roles**, namely `active_case_state`,
    `audit_events`, `evidence_custody_events`, `evidence_objects`(1),
    `evidence_versions`(1), `job_steps`, `job_logs`(1), `mcp_token_scopes`,
    `mcp_tokens`, `rag_chunks`(1), `rag_documents`(1*see note), `service_identities`,
    `worker_heartbeats`. (Tables with `|1` have one policy; the listed
    zero-policy ones rely on default-deny.)

  > **Verdict (pre-DB1):** RLS was **enabled but not FORCEd** on every `app.*`
  > table. The Gateway connects with the **service-role** credential, which
  > **bypasses RLS** (Postgres: table owners / `BYPASSRLS` / service-role bypass
  > unless `FORCE ROW LEVEL SECURITY`). So RLS is real defence-in-depth for
  > non-service roles but is **not** the live boundary — the Gateway is. This
  > matches the locked architecture (Gateway is the only policy boundary).

- **BATCH-DB1 remediation (2026-06-13) — FORCE adopted.**
  Migration `202606131000_force_rls_app_tables.sql` adds
  `ALTER TABLE app.<t> FORCE ROW LEVEL SECURITY` for all 31 RLS-ENABLED tables.
  - `FORCE ROW LEVEL SECURITY` makes RLS apply to the table OWNER role too.
  - Supabase `service_role` carries `BYPASSRLS` (Postgres privilege) and is
    **NOT affected** by FORCE — the gateway's own queries are unchanged.
  - The several zero-policy tables now also deny the owner role by default.
  - The migration is idempotent (re-FORCEing a FORCEd table is a no-op).

  Operator verification query (emit count only; expect 0):
  ```sql
  select count(*) from pg_class
  where relkind='r'
    and relnamespace='app'::regnamespace
    and relrowsecurity=true
    and relforcerowsecurity=false;
  -- expected after DB1: 0
  ```

- **Threats.** If the service-role DSN leaks (and it is the **demo** value — §7),
  an attacker using the service-role credential bypasses RLS regardless (BYPASSRLS).
  FORCE does not change that; the primary mitigation remains key rotation (HR3/§7).
  FORCE closes the owner-role bypass gap for all other credentials.
- **Checks (read-only).**
  ```sql
  -- posture table (counts only):
  select count(*) app_tables,
         count(*) filter (where relrowsecurity)      rls_enabled,
         count(*) filter (where relforcerowsecurity) rls_forced
  from pg_class join pg_namespace on relnamespace=pg_namespace.oid
  where nspname='app' and relkind='r';
  -- pre-DB1 verified: 31 | 31 | 0
  -- post-DB1 expected: 31 | 31 | 31
  select tablename, count(*) from pg_policies where schemaname='app' group by 1;
  ```
  RAG knowledge-only invariant (NW4 trigger) — confirm derived RAG is blocked:
  ```sql
  select tgname from pg_trigger where tgrelid='app.rag_chunks'::regclass;  -- _block_derived_rag_insert
  ```
- **Remediation plan.** B-MVP-013 report-only phase complete (HR2). FORCE adopted in
  BATCH-DB1 (2026-06-13). Remaining high-leverage mitigation: rotate the demo
  service-role/DSN (§7, HR3), which removes the cheap credential.
- **Residual risk.** FORCE closes the owner-bypass gap. The service-role BYPASSRLS is
  inherent to Postgres; mitigated by key rotation (HR3) and localhost bind.
- **Risk rating.** MEDIUM (Gateway is the boundary; demo key residual risk until HR3
  rotation) — reduced from HIGH (if DSN leaks) now that FORCE is in place.
- **Owner batch.** DB1 (FORCE — DONE); HR3 (key rotation, removes cheap exploit).

## 9. RAG / Hugging Face / sentence-transformers (B-MVP-004)

- **Purpose.** RAG embeds knowledge-only corpus into pgvector; the embedding model
  load is a network/integrity surface.
- **Current posture.** RAG is **knowledge/reference only** (architecture invariant;
  derived-RAG rejected, NW4). Model name is allowlisted in code
  (`rag_mcp/utils.py`, `config.py`) but `SentenceTransformer(model_name)` is called
  **without an offline guard** in several seed/query paths
  (`pgvector_seed.py`, `refresh.py`, `query_embedding.py`,
  `scripts/download_index.py`). **verified 2026-06-12:** the on-disk HF cache holds
  **`models--BAAI--bge-base-en-v1.5`** (snapshot `a5beb1e3…`) under
  **`/home/sansforensics/.cache/huggingface/hub`** (operator home, NOT the
  `sift-service` home `/var/lib/sift`). **This contradicts HR1 §13**, which assumed
  the allowlist was `all-MiniLM-L6-v2` / `all-mpnet-base-v2`; the **live** model is
  `bge-base-en-v1.5`. (HR1's "no offline guard / no revision pin" gap still holds.)
- **Threats.** Without `HF_HUB_OFFLINE`/`TRANSFORMERS_OFFLINE`, a hardened/air-gapped
  install can silently fetch from huggingface.co, or load a moved revision; the cache
  living in the operator home (not the service home) is a posture inconsistency
  worth flagging.
- **Checks.**
  ```bash
  sudo find / -type d -path '*huggingface/hub/models--*' 2>/dev/null  # which model + revision
  # confirm allowlist vs live model:
  grep -nE 'MiniLM|mpnet|bge|allowlist|RAG_MODEL_NAME' \
    packages/forensic-rag-mcp/src/rag_mcp/utils.py packages/forensic-rag-mcp/src/rag_mcp/config.py
  ```
- **DB query (redacted).**
  ```sql
  select count(*) from app.rag_chunks;        -- knowledge chunk count
  select count(*) from app.rag_documents;     -- knowledge doc count
  ```
- **Remediation plan.** **B-MVP-004 DECIDED:** keep live downloads but **pin
  versions + SHA-256 verify** all of D1–D6, add an **offline mode** requiring
  operator-staged artifacts and skipping network fetches; GeoIP off by default →
  HR3. HR3 also sets `HF_HUB_OFFLINE`/`TRANSFORMERS_OFFLINE` in the service env
  and/or pins the model revision and pre-stages the cache.
  **Open item for HR3 / OR:** confirm whether `bge-base-en-v1.5` (live) or the
  HR1-cited MiniLM/mpnet set is the intended allowlist — the doc and runtime disagree.
- **Residual risk.** Until HR3, a non-cached or air-gapped run reaches the internet.
- **Risk rating.** HIGH (air-gapped) / MEDIUM (lab).
- **Owner batch.** HR3 (B-MVP-004); RAG-model-allowlist mismatch needs an OR/HR3
  reconciliation (**fork candidate**).

## 14. Hayabusa

- **Purpose.** EVTX→Sigma detection tool executed under the service identity over
  attacker-controlled evidence.
- **Current posture.** `install.sh install_hayabusa` resolves the **latest** GitHub
  release, downloads the zip, validates it is a ZIP, installs `755`, symlinks
  `/usr/local/bin/hayabusa`. **No version pin, no SHA256 verification.**
  **verified 2026-06-12:** binary present at
  `/var/lib/sift/.sift/bin/hayabusa` (16 MB, `sift-service:sift-service 0755`),
  symlink `/usr/local/bin/hayabusa → …/bin/hayabusa`. (Direct exec as the SSH
  operator user was denied by the dir ACL — `bin/` is `0700+ACL` for `sift-service`;
  the binary itself is `0755`. Run version checks as the service path / via the tool
  pipeline, not as the operator.)
- **Threats.** "latest" + unverified binary = non-reproducible install and an
  undetectable tag re-point or compromised download.
- **Checks.**
  ```bash
  ls -l /usr/local/bin/hayabusa /var/lib/sift/.sift/bin/hayabusa
  sudo -u sift-service /var/lib/sift/.sift/bin/hayabusa --version 2>&1 | head -1  # record version
  grep -n 'releases/latest' install.sh                                            # confirm unpinned
  ```
- **Remediation plan.** **B-MVP-004 DECIDED** → HR3 pins a Hayabusa version and
  verifies the GitHub release-asset SHA256 digest before chmod+exec, or accepts an
  operator-provided artifact under offline mode.
- **Residual risk.** Existing binary's provenance is unverified retroactively.
- **Risk rating.** MEDIUM.
- **Owner batch.** HR3 (B-MVP-004).

---

# Section C — Containment & host controls

## 12. systemd service hardening

- **Purpose.** Cheapest, highest-leverage host containment for the two network/
  forensic services.
- **Current posture.** Both units run as non-root `sift-service`, `Type=simple`,
  `Restart=on-failure`, journald, `EnvironmentFile=-` (`0600`),
  `WorkingDirectory=/opt/sift-mcps`. **No sandboxing directives are set** (no
  `NoNewPrivileges`, `ProtectSystem`, `ProtectHome`, `PrivateTmp`,
  `RestrictAddressFamilies`, `SystemCallFilter`, `CapabilityBoundingSet`, etc.).
  **verified 2026-06-12:** `systemd-analyze security` →
  **`sift-gateway.service` 9.2 UNSAFE** and **`sift-job-worker.service` 9.2 UNSAFE**
  (top contributor flagged: `UMask=` world-readable default). Both services `active`.
  These baseline scores are the HR3 before/after target.
- **Threats.** A code-exec bug in the gateway runs with the full ambient privilege of
  `sift-service` — no syscall filter, no read-only system, no namespace restriction.
- **Checks.**
  ```bash
  systemd-analyze security sift-gateway.service | tail -2     # → 9.2 UNSAFE (baseline)
  systemd-analyze security sift-job-worker.service | tail -2  # → 9.2 UNSAFE (baseline)
  systemctl show sift-gateway.service -p NoNewPrivileges -p ProtectSystem -p PrivateTmp
  ```
- **Remediation plan.** HR3 adds a **tested, minimal** hardening block, validated
  against the sudo/mount/FUSE execution model: the gateway spawns forensic tooling
  via `sudo`/`systemd-run` and writes under `/cases` + `/var/lib/sift`, so a blanket
  `ProtectSystem=strict` / `NoNewPrivileges=yes` / `PrivateDevices` / `RestrictNamespaces`
  can break ingest mounts and the `run_command` `sudo -n -u <runtime_user>` model.
  Apply incrementally (`UMask=0077`, `ProtectHome`, `PrivateTmp`, scoped
  `ReadWritePaths`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`,
  `LockPersonality`), re-score, and prove `/health=ok` + ingest + a `run_command`
  smoke still pass.
- **Residual risk.** Some directives may be incompatible with FUSE/sudo and must be
  excluded; full lockdown is not achievable without breaking ingest.
- **Risk rating.** HIGH (missing the cheapest containment).
- **Owner batch.** HR3 (this section's 9.2 baseline is the proof gate).

## 13. AppArmor

- **Purpose.** MAC profile to deny evidence writes / shell-exec / unexpected network
  from the gateway process.
- **Current posture.** Profile template
  `configs/apparmor/sift-gateway.template` has evidence-write denies, shell-exec
  denies, network restrictions. **verified 2026-06-12 (`aa-status`):** 175 profiles
  loaded, 77 in enforce mode; the sift profile is loaded for
  **`/opt/sift-mcps/.venv/bin/python`** and is in **complain mode** (listed under
  "complain mode", absent from enforce). **Important correction to HR1 §10:** the
  live profile targets the **correct** `/opt/sift-mcps` path — the stale
  `sift-mcps-test` / `/home/*` paths HR1 warned about are **not present on the live
  VM** (install-time substitution resolved them). The remaining real gap is **complain
  mode = no containment**.
- **Threats.** A control that *appears* present (`aa-status` shows it) but does **not
  block** anything — complain mode only logs.
- **Checks.**
  ```bash
  sudo aa-status | sed -n '/enforce mode/,/complain mode/p' | grep -i sift   # (empty = not enforced)
  sudo aa-status | sed -n '/complain mode/,$p' | grep -i sift                # currently lists it
  sudo journalctl -k | grep -i apparmor | grep -i sift | tail               # complain-mode violations
  ```
- **Remediation plan.** CL1 no longer needs the `sift-mcps-test→/opt` path fix on the
  **live** install (it is already correct) — but should fix the **template** so a
  fresh install stays correct. HR3 decides + implements the enforce transition after
  profiling with `aa-logprof`, then proves gateway start + ingest + `run_command`
  with no denials in `journalctl -k`.
- **Residual risk.** Enforcing without thorough profiling can break ingest/exec;
  must be validated, not blanket-flipped.
- **Risk rating.** HIGH (complain-only) — downgraded from HR1's "HIGH + path
  mismatch" because the path mismatch is **not** present live.
- **Owner batch.** HR3 (enforce transition) + CL1 (template path hygiene).

## 11. auditd

- **Purpose.** Tamper-evident audit of evidence-chain writes, secret access, and
  privileged exec.
- **Current posture.** Repo ships `configs/audit/99-sift-evidence.rules` (watches
  `CASES_ROOT` + `/var/lib/sift` for write/attr changes, keys `sift_evidence_write` /
  `sift_core_write`), installed by `install.sh` (`auditctl -R`).
  **verified 2026-06-12 — CONTRADICTS HR1 §11:** **auditd is NOT installed/active on
  the VM.** `auditctl` is **command not found**; there is **no `/etc/audit/rules.d/`**
  directory; `systemctl is-enabled auditd` → `not-found`, `is-active` → `inactive`.
  So the shipped rules are **not loaded** and evidence/secret writes are **not**
  being audited at the kernel level today. (DB `app.audit_events` still records
  application-level tool/identity/custody events — that layer is intact; the gap is
  the **host kernel audit** layer.)
- **Threats.** No kernel-level tamper trail on the evidence chain, the secret files,
  or privileged-command execution. The application audit log persists tool calls but
  cannot see a direct filesystem tamper by a root/host actor.
- **Checks.**
  ```bash
  systemctl is-enabled auditd; systemctl is-active auditd     # currently: not-found / inactive
  command -v auditctl || echo 'auditd NOT installed'          # currently: NOT installed
  ls /etc/audit/rules.d/ 2>&1                                 # currently: No such file or directory
  # after remediation:
  sudo auditctl -l | grep -E 'sift_evidence_write|sift_core_write'
  ```
- **Remediation plan.** HR3: install/enable `auditd` and load
  `99-sift-evidence.rules` (the installer step exists but the package/daemon is
  absent on this VM — investigate whether the install path silently no-ops when
  `auditd` is missing). Add watches for the secret files
  (`supabase.env`, `control-plane.env`, TLS keys), the gateway config, and the
  `execve`/sudo path; set `-e 2` (immutable config) and document
  persistence/rotation. Re-verify rules survive a reboot.
- **Residual risk.** Even enabled, auditd is bypassable by a kernel-level attacker;
  it is detection, not prevention.
- **Risk rating.** HIGH — the shipped control is **absent at runtime**, not merely
  thin (HR1 rated MEDIUM assuming rules were loaded; live evidence shows it is not).
- **Owner batch.** HR3 (install+enable+extend) — **also a fork candidate**: confirm
  with the operator whether auditd was intentionally omitted on this VM or the
  installer step failed silently.

## 10. TLS / certificates

- **Purpose.** Confidentiality + integrity of the analyst↔gateway and MCP channels.
- **Current posture.** Installer generates a self-signed local CA (RSA-4096,
  `CN=sift-mcps-CA`, 3650d) + gateway cert (RSA-4096, 730d); keys `0600`, certs
  `0644`. **verified 2026-06-12:** gateway cert
  (`/var/lib/sift/.sift/tls/gateway-cert.pem`) carries
  **`subjectAltName = IP:192.168.122.81, IP:127.0.0.1, DNS:siftworkstation,
  DNS:localhost`** and is valid **2026-06-11 → 2028-06-10**. **This resolves HR1
  §12's open question:** the cert **does** include the VM IP SAN, so IP-based strict
  MCP clients verify successfully. TLS dir `0700`, all four PEMs present with correct
  modes (keys `0600`, certs `0644`).
- **Threats.** Self-signed CA means analysts must import the CA or bypass
  verification; no documented renewal for the 730-day cert.
- **Checks.**
  ```bash
  sudo openssl x509 -in /var/lib/sift/.sift/tls/gateway-cert.pem -noout -ext subjectAltName
  sudo openssl x509 -in /var/lib/sift/.sift/tls/gateway-cert.pem -noout -dates
  sudo stat -c '%a %U' /var/lib/sift/.sift/tls/gateway-key.pem   # 600 sift-service
  ```
- **Remediation plan.** TLS1 (B-MVP-001): document CA-import / MCP endpoint trust /
  renewal-rotation; the IP-vs-DNS decision can now note that the IP SAN is already
  present (internal CA remains pragmatic for the IP-only libvirt VM; LE IP certs are
  ~6-day short-lived + certbot-unsupported).
- **Residual risk.** Trust friction + manual renewal before 2028; no automated
  rotation.
- **Risk rating.** MEDIUM (operational trust friction; TLS itself is real).
- **Owner batch.** TLS1 (B-MVP-001).

---

# Section D — Evidence, reports, worker, portal (most important)

## 16. Evidence custody & sealing

- **Purpose.** Court-grade chain of custody; evidence must be registered + sealed
  before analysis, and sealed bytes are read-only.
- **Current posture.** DB-authoritative (OR2): `app.evidence_objects`
  (`seal_status`, `current_sha256`), `app.evidence_chain_heads` (`head_hash`),
  append-only `app.evidence_custody_events` (per-case `prev_hash`/`event_hash`,
  mutation blocked by trigger `app.evidence_block_mutation`), custody appended only
  via SECURITY-DEFINER `app.evidence_append_custody_event`. File artifacts
  (`evidence-manifest.json`, `evidence-ledger.jsonl`, per-case `audit/*.jsonl`) are
  **export/proof only** — "DB is the authority; no file manifest/ledger is consulted"
  (`portal_services.py:535-578`). Sensitive evidence actions (seal/ignore/retire)
  are re-auth gated. **verified 2026-06-12:** `/health` `evidence_root`:
  `path:/cases`, `readable:true`, `writable:true`, **`write_protected:false`**,
  `case_count:0`. Sealing chmods evidence to `0444` (`evidence_chain.py`).
- **Threats.** A host/root actor editing `/cases` bytes directly — caught by hash on
  re-verification, but (today) **not** by kernel auditd (§11, absent). `/cases` is
  writable at rest until seal.
- **Checks.**
  ```bash
  curl -sk https://127.0.0.1:4508/health | python3 -c 'import sys,json;print(json.load(sys.stdin)["evidence_root"])'
  ```
- **DB query (redacted).**
  ```sql
  select count(*) from app.evidence_objects;
  select count(*) from app.evidence_custody_events;     -- append-only ledger length
  select tgname from pg_trigger where tgrelid='app.evidence_custody_events'::regclass; -- block-mutation trigger
  ```
- **Logs.** App audit: `app.audit_events` (custody class). File mirror per case:
  `<case>/audit/*.jsonl` (proof copy only).
- **Tests.** Custody append-only trigger test (sift-core); seal→`0444` mode test.
- **Remediation plan.** Primary gap is the **missing kernel auditd** watch on
  `/cases` + `/var/lib/sift` (→ §11/HR3). The custody model itself is well-built;
  no change owed here beyond enabling auditd.
- **Residual risk.** Pre-seal `/cases` is writable; integrity relies on hash
  re-verification + (once enabled) auditd.
- **Risk rating.** LOW (custody design is strong) — elevated to MEDIUM only because
  the kernel audit layer is currently absent.
- **Owner batch.** HR3 (auditd enablement covers the residual gap); custody = no
  change.

## 17. Reports / exports

- **Purpose.** Reports must include **approved** findings + approved supporting data
  only; export is re-auth gated.
- **Current posture.** DB-authoritative `app.report_metadata` (`status`,
  `seal_status`, `manifest_hash`, `chain_head_hash`, `exported`); `report_inputs()`
  returns **approved-only** findings (`investigation_store.py:614`); content-hash
  approval guard consolidated to a single authority (NW1,
  `investigation_store.py:186`); generate/export are re-auth gated. Generated PDF/MD
  files are export artifacts, not authority. Evidence proof exports
  (`app.evidence_proof_exports`, optional Solana anchor) are non-authoritative
  metadata.
- **Threats.** Inclusion of unapproved findings/data; export without re-auth; a
  tampered exported file passed off as authoritative.
- **Checks / DB query (redacted).**
  ```sql
  select count(*) from app.report_metadata;
  select count(*) filter (where status='approved') from app.investigation_findings; -- report-eligible
  ```
- **Tests.** Reporting reconcile test (DB content_hash) `reporting.py:696-723`;
  approved-only inclusion test.
- **Remediation plan.** None owed by HR-track — the approval/re-auth gate is the
  locked design. Regression-watch via the reconcile tests.
- **Residual risk.** Exported files live outside DB authority by design; the manifest
  hash is the integrity anchor.
- **Risk rating.** LOW.
- **Owner batch.** report-only (regression-watch; no fix).

## 18. Worker sandbox / `run_command`

- **Purpose.** The job worker executes forensic tooling (ingest, enrich, report,
  `run_command`) under the service identity; `run_command` is the broadest exec
  surface.
- **Current posture.** Durable jobs are fully DB-backed (`app.jobs` + `job_steps` +
  `job_logs` + `worker_heartbeats`; `claim_next_job` `FOR UPDATE SKIP LOCKED`); no
  external queue/file. `run_command` runs under `sudo -n -u <runtime_user>` (per
  HR1 §2 execution-model note). **verified 2026-06-12:** the service user
  `sift-service` is **NOT in the `docker` group** (only `sansforensics` is) and the
  Docker socket is `root:docker 0660` — so a `run_command`/worker compromise **cannot
  reach the Docker daemon** (a meaningful containment, not noted in HR1). However,
  spawned tools have **no OS-level sandbox** (no seccomp/namespace per command; see
  §12 systemd has none either) and (per the run_command memory note) the gateway
  passes literal argv (deny-floor solid, but evidence/ write-reachability and
  no OS sandbox remain open).
- **Threats.** A malicious evidence file processed by a spawned tool runs with the
  service user's ambient privilege; without systemd/AppArmor enforcement (§12/§13)
  there is no per-command containment.
- **Checks.**
  ```bash
  getent group docker                       # sift-service must be absent
  ls -l /var/run/docker.sock                # root:docker 0660
  systemctl restart sift-job-worker.service # [DANGER] service restart — do NOT run during a live job
  ```
- **DB query (redacted).**
  ```sql
  select status, count(*) from app.jobs group by status;       -- queue depth by status
  select count(*) from app.worker_heartbeats;                  -- worker liveness rows
  ```
- **Remediation plan.** Covered by §12 (systemd hardening) + §13 (AppArmor enforce)
  — per-command OS sandboxing is the real fix and is HR3-scoped, validated against
  the sudo/mount/FUSE model. The run_command deny-floor + evidence-write gap is its
  own hardening track (run_command memory item S-1).
- **Residual risk.** Until §12/§13 land, a spawned tool has full service-user
  privilege; only the no-docker-group containment limits lateral movement.
- **Risk rating.** MEDIUM.
- **Owner batch.** HR3 (systemd/AppArmor) + the run_command hardening track.

## 19. React / Vite portal

- **Purpose.** Human/operator REST UI (agents use MCP only — invariant). Served by
  the gateway under TLS at `/portal/`.
- **Current posture.** `packages/case-dashboard/frontend` builds with Vite 8 /
  React 19 / Tailwind 3, base `/portal/`, output to
  `src/case_dashboard/static/v2`. The **dev-server proxy** hardcodes
  `target: https://192.168.122.81:4508` with **`secure:false`** (TLS verification
  off) — dev-only, not shipped, but a hardcoded VM IP + CL1 cleanup candidate.
  Session config in `gateway.yaml` portal (`session_max_age`,
  `require_password_reset: true`). `examiner.json` PBKDF2 fallback is `0600`
  (legacy path; B-MVP-011 retirement).
- **Threats.** Hardcoded IP / `secure:false` are dev-only (no production-build
  exposure). Risk is accidental secret embedding in built assets.
- **Checks.**
  ```bash
  grep -rn 'secure:' packages/case-dashboard/frontend/vite.config.js   # dev-proxy secure:false
  # after build, scan bundle for accidental secrets:
  grep -rIE 'eyJ[A-Za-z0-9_-]{10,}|service_role|SUPABASE_SERVICE' \
    packages/case-dashboard/src/case_dashboard/static/v2 || echo 'clean'
  ```
- **Remediation plan.** PT1 for functional/UX gaps (root `/`→`/portal/` redirect);
  **CL1** for the hardcoded IP / `secure:false` dev coupling. Build-time asset
  security is not HR3-scoped.
- **Residual risk.** Dev coupling only; no production gap observed.
- **Risk rating.** LOW.
- **Owner batch.** PT1 / CL1.

---

## Cross-cutting strengths (INFO — assert as regression checks)

**verified 2026-06-12:**

- Secret env files `0600 sift-service`: `supabase.env`, `control-plane.env`,
  `gateway.yaml`, `opensearch.yaml`. TLS dir `/var/lib/sift/.sift/tls` `0700`; keys
  `0600`, certs `0644`. `SIFT_HOME` `/var/lib/sift/.sift` `0700` (state root
  `/var/lib/sift` itself `0755`).
- Examiner password stored PBKDF2-HMAC-SHA256 (`install.sh`, 600,000 iterations —
  OWASP-aligned); `require_password_reset: true`. (`examiner.json` is the legacy
  fallback path being retired in CL1 per B-MVP-011; live `verification/` ledger dir
  is **empty**, supporting the "dead fallback" finding.)
- HTTP security headers (HSTS / X-Frame / CSP) + restricted CORS set by the gateway.
- Docker socket not reachable by the service user (no docker group membership).

Regression check (run periodically):
```bash
for f in supabase.env control-plane.env gateway.yaml opensearch.yaml; do
  sudo stat -c '%n %a %U' /var/lib/sift/.sift/$f; done   # all must be 600 sift-service
sudo stat -c '%a' /var/lib/sift/.sift /var/lib/sift/.sift/tls   # 700 700
```

---

## Findings that contradict / refine HR1 (for the register)

1. **auditd is absent at runtime** (HR1 §11 assumed rules loaded; live: `auditctl`
   not found, no `/etc/audit/rules.d/`). Raises §11 from MEDIUM to **HIGH** and adds
   a fork candidate (intentional omission vs silent installer no-op?).
2. **RAG model is `BAAI/bge-base-en-v1.5`** live, not HR1 §13's MiniLM/mpnet
   allowlist. Doc/runtime mismatch — fork candidate for OR/HR3 to reconcile the
   allowlist.
3. **AppArmor profile path is correct on the live VM** (`/opt/sift-mcps/.venv/bin/python`),
   not the stale `sift-mcps-test`/`/home/*` paths HR1 §10 warned about. The live gap
   is **complain-only**, not path-mismatch; CL1's path fix applies to the *template*,
   not the live install.
4. **OpenSearch container runs non-root (User=1000)** — better than HR1 §3's
   default-user assumption; the remaining gap is cap_drop/no-new-privileges/rootfs.
5. **Gateway cert carries the VM IP SAN** — resolves HR1 §12's open question in
   TLS1's favour (internal CA already IP-valid).
6. **Service user not in docker group** — a containment positive not recorded in HR1.

## Operator decisions required (fork candidates)

These need an operator decision before HR3 implements; several already exist as
B-MVP rows and are resolved there, not in a batch:

- **auditd absence (new):** was `auditd` intentionally left off this VM, or did the
  installer step no-op silently? HR3 cannot enable it without this answer.
- **RAG model allowlist mismatch (new, ties B-MVP-004):** is `bge-base-en-v1.5` the
  intended model? Reconcile the code allowlist + offline-mode pin to the real model.
- **Supabase production keys (B-MVP-012 — confirmed demo):** rotation is DECIDED for
  HR3; operator confirms timing (cross-cuts TLS1 + portal reset).
- **Postgres RLS FORCE (B-MVP-013 — report-only):** whether to `FORCE` RLS on
  `app.*` is a schema change needing a separate go-ahead; report-only here.
- **B-MVP-001 (TLS1):** internal CA vs DNS+ACME — now informed by the confirmed IP
  SAN; internal CA remains pragmatic for the IP-only VM.

---

*Live evidence in this guide was gathered read-only on 2026-06-12 against
`sansforensics@192.168.122.81`. No secret values, JWTs, DSNs, key material, DB
password hashes, or the SSH password appear in this document; secret-equality is
reported as MATCH/NO-MATCH from on-VM sha256 comparisons only.*
