# Hardening Research Matrix (BATCH-HR1)

Status: research-only. No implementation, config, installer, or VM change is made
by this batch. Repo posture is derived by reading the checked-in source on branch
`batch/hr1-hardening-matrix`; live runtime facts that cannot be read from the repo
are marked **verify in HR2 on VM**.

Retrieval date for all external sources: **2026-06-12**.
Repo commit base: see the BATCH-HR1 landing commit on this branch.

## How to read this document

Each component has:

- **Posture** — what the repo/runtime actually does today, with file:line citations.
- **Reference** — the official vendor/project doc, exact URL, version, retrieved 2026-06-12.
- **Gap** — the delta between posture and the reference.
- **Severity** — `HIGH` / `MEDIUM` / `LOW` / `INFO`. HIGH = exploitable or
  data-exposure now; MEDIUM = weakened defence-in-depth; LOW = polish; INFO = posture
  is already aligned, recorded for completeness.
- **Owner** — the follow-up batch that should implement or decide the fix
  (HR2 audit guide, HR3 implementation, PT1/PT2 portal, TLS1 certs, AD1/AD2 add-ons,
  CL1/CL2 cleanup/rename), or an explicit *not applicable* rationale, or a
  **fork candidate** when an operator decision is required before any batch.
- **Validation** — how HR2/HR3 proves the fix on the VM.

Severity legend for the rollup at the end: counts and the top gaps are summarised in
[§ Severity rollup](#severity-rollup).

## Source-discipline note

- Library/framework/CLI/cloud docs were resolved via the Context7 CLI per repo rules
  where Context7 added value (FastAPI confirmed: `/fastapi/fastapi`, versions incl.
  0.122.0/0.128.0, source reputation High). For OS/security components the official
  vendor/project documentation is cited directly because that is the authoritative
  source (systemd man pages, docs.docker.com, docs.opensearch.org, postgresql.org,
  supabase.com/docs, Ubuntu/AppArmor docs, huggingface.co/docs, letsencrypt.org).
- No Context7 quota or availability failure was hit during this batch; Context7 was
  used sparingly (well under the 3-commands-per-question ceiling) because most
  components are OS/security surfaces where vendor docs are the correct source.

---

## 1. Ubuntu / SIFT host

- **Posture.** Target host is SANS SIFT (Ubuntu-based). Installer stages to
  `/opt/sift-mcps` and provisions system services; it does not run a host-level
  CIS baseline. Target Python is `/usr/bin/python3.12`; managed-Python downloads
  are disabled on the VM (`UV_NO_MANAGED_PYTHON=1`, `UV_PYTHON_DOWNLOADS=never`,
  enforced in `configs/systemd/sift-job-worker.service` and `install.sh` uv calls).
  State dirs created with explicit modes: `SIFT_HOME`/TLS dir `0700` owned
  `sift-service` (`install.sh:489-492`); secrets `0600` (`install.sh:908,1435`).
- **Reference.** Ubuntu Security / hardening overview —
  https://documentation.ubuntu.com/security/ (Ubuntu Security documentation,
  current). CIS-style host baselines are operator scope, not bundled.
- **Gap.** No documented host-baseline expectation (kernel sysctl, login policy,
  unattended-upgrades, firewall default-deny). The installer assumes a trusted lab
  VM. **verify in HR2 on VM** whether a host firewall (ufw/nftables) restricts
  inbound to 4508/portal only.
- **Severity.** MEDIUM (lab) / HIGH if this VM is ever exposed beyond libvirt.
- **Owner.** HR2 (document expected host baseline + firewall posture); HR3 only if a
  safe-for-core host control is approved. Host OS image hardening itself is
  *not applicable* to the installer (operator owns the base image).
- **Validation.** HR2 records `ufw status` / `nft list ruleset`, listening sockets
  (`ss -tlnp`), and unattended-upgrades state on the VM.

## 2. systemd services (sift-gateway, sift-job-worker)

- **Posture.** Both units run as the dedicated non-root `sift-service`
  (`configs/systemd/sift-gateway.service`, `sift-job-worker.service`), `Type=simple`,
  `Restart=on-failure`, journald logging, secrets via `EnvironmentFile=-` with `0600`
  files. **Neither unit sets any sandboxing directive** — no `NoNewPrivileges`,
  `ProtectSystem`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`,
  `ProtectKernelTunables/Modules/ControlGroups`, `RestrictAddressFamilies`,
  `RestrictNamespaces`, `MemoryDenyWriteExecute`, `SystemCallFilter`,
  `CapabilityBoundingSet`, `ReadOnlyPaths`/`ReadWritePaths`, or `LockPersonality`.
- **Reference.** systemd.exec(5) sandboxing directives —
  https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html
  (mirror: https://man7.org/linux/man-pages/man5/systemd.exec.5.html). Exposure
  scoring tool: `systemd-analyze security <unit>` —
  https://www.man7.org/linux/man-pages/man1/systemd-analyze.1.html. Confirmed text:
  `NoNewPrivileges=` is "the simplest and most effective way to ensure that a process
  and its children can never elevate privileges again" (defaults false);
  `ProtectSystem=strict` mounts the entire hierarchy read-only except /dev, /proc, /sys.
- **Gap.** Running a network-facing forensic gateway with **zero** systemd hardening
  directives is a large unused defence-in-depth surface. The gateway *does* need to
  spawn forensic tooling via `sudo`/`systemd-run` and write under `/cases` and
  `/var/lib/sift`, so a blanket `ProtectSystem=strict` would need carefully scoped
  `ReadWritePaths`. Caution: directives that block `sudo`/mount/FUSE (e.g.
  `NoNewPrivileges=yes`, `RestrictNamespaces`, `PrivateDevices`) can break ingest
  and `run_command`'s `sudo -n -u <runtime_user>` model — must be validated, not
  blanket-applied.
- **Severity.** HIGH (missing the cheapest, highest-leverage host containment).
- **Owner.** HR3 (add a tested, minimal hardening block); HR2 first establishes the
  baseline `systemd-analyze security` score per unit and which directives are safe
  given the sudo/mount/FUSE execution model.
- **Validation.** HR2: `systemd-analyze security sift-gateway.service` /
  `sift-job-worker.service` exposure score before. HR3: re-score after, then prove
  `/health=ok`, ingest mount, and a `run_command` smoke still pass on the VM.

## 3. Docker / Compose (core OpenSearch; OpenCTI add-on)

- **Posture.** Core `docker-compose.yml` runs `opensearchproject/opensearch:3.5.0`
  pinned, bound to `127.0.0.1:9200` only, `restart: unless-stopped`, healthcheck,
  ulimits set. **No `cap_drop`, no `security_opt: no-new-privileges`, no
  `read_only: true`, no non-root `user:`** on the container; `DISABLE_SECURITY_PLUGIN=true`
  (see §6). OpenCTI compose (`docker-compose.opencti.yml`,
  `docker-compose.opencti-connectors.yml`) is add-on-only, on its own `opencti-net`
  with its own OpenSearch datastore — correct isolation per the core/add-on contract.
- **Reference.** Docker Engine security —
  https://docs.docker.com/engine/security/ (official; confirms drop all caps except
  required, run as non-root, protect the daemon socket, resource limits, Content
  Trust). Per-flag guidance (`--cap-drop`, `--security-opt no-new-privileges`,
  `--read-only`) — https://docs.docker.com/engine/containers/run/ and
  https://docs.docker.com/reference/cli/docker/container/run/.
- **Gap.** Container runs with default capability set and writable root FS, no
  `no-new-privileges`. Image tag is pinned by version but not by digest
  (`@sha256:...`), so the tag could be re-pointed upstream.
- **Severity.** MEDIUM (localhost-bound limits blast radius; still a CIS-aligned gap).
- **Owner.** HR3 (add `security_opt: [no-new-privileges:true]`, `cap_drop: [ALL]`
  plus any required add-backs, consider digest pin); links to B-MVP-005 OpenSearch
  posture decision.
- **Validation.** HR2/HR3: `docker inspect sift-opensearch` shows dropped caps +
  no-new-privileges; cluster still green/yellow and reachable on 127.0.0.1:9200.

## 4. Supabase CLI / Auth / Postgres control plane

- **Posture.** `scripts/setup-supabase.sh` pins the Supabase CLI to **v2.105.0** and
  **verifies a SHA256** of the release tarball
  (`SUPABASE_CLI_SHA256=11ac44...`, `setup-supabase.sh:31-34`) — a good supply-chain
  model. Brings up only `db (postgres 15) + auth (gotrue) + api (kong)`; studio,
  storage, realtime, edge, analytics disabled. Agent token TTL requirement is
  source-controlled (`configs/supabase/auth-jwt.env.template`,
  `GOTRUE_JWT_EXP=172800`). Gateway reads `SUPABASE_URL/ANON/SERVICE_ROLE_KEY` from
  env only, never the config file (`configs/gateway.yaml.template` auth block;
  `install.sh write_supabase_env` writes `supabase.env` `0600`).
- **Reference.** Supabase self-hosting —
  https://supabase.com/docs/guides/self-hosting/docker and the docker dir
  https://github.com/supabase/supabase/tree/master/docker (official; "never start
  your self-hosted Supabase using these defaults", generate keys, strong dashboard
  password, use a secrets manager in production).
- **Gap.** Local-dev Supabase CLI defaults (e.g. the well-known demo JWT secret /
  anon / service-role keys that `supabase start` emits, DSN
  `postgres:postgres@127.0.0.1:54322`) are acceptable for a lab but are **not**
  production secrets. There is no documented rotation of the JWT signing secret or
  DB superuser password for a hardened deployment. **verify in HR2 on VM** whether
  the running project still uses CLI demo keys.
- **Severity.** HIGH if treated as production; MEDIUM in the current lab framing.
- **Owner.** HR2 (document the demo-vs-production key boundary and rotation path);
  fork candidate if the operator wants the lab to move to generated production keys
  now (cross-cuts TLS1 and the portal reset flow).
- **Validation.** HR2: confirm `SUPABASE_SERVICE_ROLE_KEY` is not a known CLI demo
  value; confirm DSN password is not the default; confirm `supabase.env` is `0600`
  `sift-service`.

## 5. Postgres / RLS / pgvector

- **Posture.** Postgres is the authoritative control plane (`app.*` tables,
  `app.mcp_backends`, `app.rag_chunks`). DSN/pepper held only in
  `control-plane.env` `0600` (`gateway.yaml.template` control_plane/token_registry
  reference env names, not values). RAG uses pgvector via `PgVectorRagStore`.
  **Whether RLS is enabled and FORCEd on tenant tables cannot be read from this
  repo subtree** and must be checked against the Supabase migrations / live DB.
- **Reference.** PostgreSQL Row Security Policies —
  https://www.postgresql.org/docs/current/ddl-rowsecurity.html (current = PostgreSQL
  18). Confirmed: RLS is **disabled by default**; `ENABLE ROW LEVEL SECURITY` yields
  default-deny; **superusers and table owners bypass RLS** unless
  `FORCE ROW LEVEL SECURITY` is set; the service-role connection typically bypasses
  RLS. pgvector — https://github.com/pgvector/pgvector (official).
- **Gap.** The Gateway is the policy boundary and connects with elevated DB rights,
  so RLS is defence-in-depth, not the primary control — but the matrix cannot
  confirm RLS is present/forced on `app.*` knowledge/case tables. If absent, a DB
  credential compromise reads all tenants directly. pgvector knowledge plane must
  stay knowledge-only (architecture invariant; relevant to B-MVP-006).
- **Severity.** MEDIUM (Gateway is the real boundary) / HIGH if the DSN ever leaks
  and no RLS exists.
- **Owner.** HR2 (document RLS posture from migrations + live `\d+`/`pg_policies`);
  fork candidate if introducing/forcing RLS on control-plane tables is desired
  (schema change — out of HR3's safe-installer scope).
- **Validation.** HR2 on VM: `SELECT relname, relrowsecurity, relforcerowsecurity
  FROM pg_class ...` and `SELECT * FROM pg_policies` against `app.*`.

## 6. OpenSearch

- **Posture.** Core OpenSearch 3.5.0 runs single-node with
  **`DISABLE_SECURITY_PLUGIN=true`** (`docker-compose.yml`), bound to
  `127.0.0.1:9200` over **plain HTTP**. Gateway/installer talk to it on
  `http://127.0.0.1:9200` (`gateway.yaml.template` opensearch.url; `install.sh`
  health/index calls). `path.repo` snapshot dir mounted from
  `/var/lib/sift/snapshots`. This is exactly the lab posture flagged by B-MVP-005.
- **Reference.** OpenSearch security best practices —
  https://docs.opensearch.org/latest/security/configuration/best-practices/ and
  disable/enable security —
  https://docs.opensearch.org/latest/security/configuration/disable-enable-security/
  (latest). Confirmed: the security plugin must be enabled in production, TLS +
  authentication configured, default `admin` credentials changed, security never
  disabled in production.
- **Gap.** No authentication, no TLS, no audit log on the data store. Mitigated by
  localhost-only binding and the fact that only `sift-service` processes reach it,
  but it is the canonical "do not run security-disabled in production" anti-pattern.
- **Severity.** HIGH if the cluster is ever reachable off-host or multi-node;
  MEDIUM given the current 127.0.0.1 bind and single-tenant lab.
- **Owner.** B-MVP-005 decision → HR2 (document target posture: security plugin
  vs. accepted localhost-only-no-auth lab rationale, snapshot policy, replica
  settings) → HR3 (implement the approved posture). This is a **fork candidate**:
  enabling the security plugin is a non-trivial behavioural change that needs an
  operator decision, not a silent installer edit.
- **Validation.** HR2: `curl 127.0.0.1:9200/_cluster/health`,
  `curl 127.0.0.1:9200/_plugins/_security/health` (404 confirms disabled),
  `ss -tlnp | grep 9200` confirms localhost-only.

## 7. FastAPI / FastMCP (Gateway)

- **Posture.** Strong. `packages/sift-gateway/src/sift_gateway/server.py` sets
  `Strict-Transport-Security: max-age=31536000; includeSubDomains` (line 52),
  `X-Frame-Options: DENY` (line 54), a `Content-Security-Policy` (line 61), and a
  **restricted CORS allow-list** (`allow_origins=[gateway_origin,
  "https://localhost:4508"]`, lines 1336-1337) rather than `*`. Gateway is the sole
  policy boundary; unified Supabase JWT auth (`gateway.yaml.template` auth.supabase,
  D30/PR03A); legacy token fallback gated behind explicit `auth.legacy.*` flags.
  Rate limits configured (`gateway.yaml.template` rate_limit). Deps pinned with
  lower bounds: `fastapi>=0.136`, `fastmcp>=3`, `uvicorn>=0.30`, `starlette>=0.49.1`
  (`packages/sift-gateway/pyproject.toml`).
- **Reference.** FastAPI (Context7 `/fastapi/fastapi`, versions incl. 0.122.0,
  0.128.0, retrieved 2026-06-12) and https://fastapi.tiangolo.com/deployment/.
  Starlette HTTPS/middleware — https://www.starlette.io/middleware/.
- **Gap.** Bind host is `0.0.0.0:4508` (`gateway.yaml.template` host, confirmed in
  `server.py:1332`), so the listener is reachable on every interface; only TLS +
  JWT protect it (no host firewall asserted — see §1). Dependency floors use `>=`
  not exact/locked pins at the package manifest level (the workspace `uv.lock`
  pins transitively, but manifests do not). Legacy auth fallback flags
  (`token_fallback_enabled: true`, `portal_session_enabled: true`) remain on.
- **Severity.** MEDIUM (0.0.0.0 bind + no firewall) / LOW (pin style; legacy flags
  are an intentional compatibility bridge).
- **Owner.** HR2 (document bind/firewall expectation and the legacy-auth sunset);
  HR3 only if narrowing the bind or firewalling is approved as safe-for-core. Legacy
  flag sunset is a CL1/RG1 concern, not a fork.
- **Validation.** HR2: `ss -tlnp | grep 4508`; confirm headers via
  `curl -ski https://127.0.0.1:4508/health | grep -i strict-transport`; confirm an
  operator Supabase login token is rejected at `/mcp` (already proven in
  Session-Notes) and a portal-issued agent token is accepted.

## 8. React / Vite portal

- **Posture.** `packages/case-dashboard/frontend` builds with Vite 8, React 19,
  Tailwind 3, base `/portal/`, output to `src/case_dashboard/static/v2`
  (`frontend/vite.config.js`). The dev-server proxy hardcodes
  `target: https://192.168.122.81:4508` with **`secure: false`** (TLS verification
  off) — dev-only, not shipped in the build, but a hardcoded VM IP. Portal is
  human/operator REST only; agents use MCP only (architecture invariant). Session
  cookie config in `gateway.yaml.template` portal (`session_max_age: 28800`,
  `require_password_reset: true`).
- **Reference.** Vite — Context7-resolvable; official build/security guidance
  https://vite.dev/guide/build.html and https://vite.dev/config/server-options.html
  (server options incl. `https`); React 19 — https://react.dev/. (Library docs;
  retrieved 2026-06-12.)
- **Gap.** Hardcoded VM IP and `secure:false` in the dev proxy are dev-only but are
  CL1 cleanup candidates (stale environment coupling). No production-build security
  gap observed (static assets served by the gateway under TLS). Confirm built assets
  do not embed secrets.
- **Severity.** LOW.
- **Owner.** PT1 (portal workflow/health UX; root `/` → `/portal/` redirect) for
  functional gaps; CL1 for the hardcoded IP / `secure:false` dev coupling. Build-time
  asset security is *not applicable* to HR3 installer hardening.
- **Validation.** PT1: `npm run build` succeeds; portal loads under gateway TLS;
  `grep -r` built bundle for accidental secrets.

## 9. Python / uv

- **Posture.** uv-managed workspace; VM forbids managed-Python downloads
  (`UV_NO_MANAGED_PYTHON=1`, `UV_PYTHON_DOWNLOADS=never` in the worker unit and all
  `install.sh` uv invocations, e.g. `--no-managed-python --no-python-downloads`).
  `requires-python = ">=3.10"` (root + package `pyproject.toml`); VM target 3.12.
  `uv` itself bootstrapped via `curl -LsSf https://astral.sh/uv/install.sh | sh`
  (`install.sh:239`) — **piped to shell, no checksum/signature pin**.
- **Reference.** uv installation & lockfile —
  https://docs.astral.sh/uv/getting-started/installation/ and
  https://docs.astral.sh/uv/concepts/projects/sync/ (official; supports
  `--require-hashes`/locked installs). Astral install script —
  https://astral.sh/uv/install.sh.
- **Gap.** The `curl | sh` uv bootstrap has no pinned version or checksum (contrast
  with the Supabase CLI in §4 which is pinned + SHA256-verified — that is the model
  to copy). Manifest deps use `>=` floors; reproducibility relies on `uv.lock`.
- **Severity.** MEDIUM (supply-chain: unpinned bootstrap of the tool that builds the
  whole runtime).
- **Owner.** HR3 (pin uv version + verify checksum, mirroring the Supabase CLI
  pattern; or pre-stage uv as an operator-provided artifact under the offline policy
  B-MVP-004). Ties to B-MVP-004.
- **Validation.** HR3: install pins a known uv version; `uv --version` matches;
  checksum verified before exec.

## 10. AppArmor

- **Posture.** A profile exists (`configs/apparmor/sift-gateway.template`) with
  evidence-write denies (`deny /cases/*/evidence/** w`), shell-exec denies, and
  network restrictions. **It is installed in complain mode only and never enforced**:
  `install.sh:2490` runs `apparmor_parser -C -r` (the `-C` flag = complain) and logs
  "AppArmor profile installed (complain mode)"; there is no `aa-enforce` step.
  **The profile's source-tree paths are stale**: it allows
  `/home/*/sift-mcps-test/**` and `/home/*/sift-mcps-test/.venv/bin/**`, but the
  runtime root is `/opt/sift-mcps` and the service user is `sift-service`
  (home `/var/lib/sift`), so the code/venv read+exec rules do not match the real
  install path.
- **Reference.** AppArmor — https://apparmor.net/ and Ubuntu Server AppArmor
  how-to https://documentation.ubuntu.com/server/how-to/security/apparmor/;
  aa-enforce(8) https://apparmor.net/man/3.0/aa-enforce/. Confirmed: default mode is
  enforce; complain mode logs violations but does **not** block them.
- **Gap.** (a) Complain mode provides no actual containment. (b) The `sift-mcps-test`
  paths mean even if enforced, the profile would not correctly cover the `/opt`
  install — risk of either no protection or breaking the service. This is a real,
  concrete CL1 + HR3 gap.
- **Severity.** HIGH (a security control that looks present but does not enforce, and
  is path-mismatched to the actual deployment).
- **Owner.** CL1 (fix the stale `sift-mcps-test` → `/opt/sift-mcps` paths and the
  `/home/*` vs `/var/lib/sift` home assumption); HR3 (decide and implement the
  enforce transition after profiling with `aa-logprof`). HR2 documents the profiling
  procedure.
- **Validation.** HR2/HR3: `aa-status` shows the profile and its mode; after path
  fix + `aa-enforce`, prove gateway start, ingest, and `run_command` still work
  with no denials in `journalctl -k | grep apparmor`.

## 11. auditd

- **Posture.** `configs/audit/99-sift-evidence.rules` watches `CASES_ROOT` and
  `/var/lib/sift` for write+attribute changes (perm=wa) with keys
  `sift_evidence_write` / `sift_core_write`; `CASES_ROOT` substituted at install
  (`install.sh:2467` installs rules `0640`, then `auditctl -R`). Captures chmod/chattr
  (immutable-flag clearing) on the evidence chain.
- **Reference.** auditd / audit.rules — https://man7.org/linux/man-pages/man8/auditd.8.html
  and https://man7.org/linux/man-pages/man7/audit.rules.7.html; Ubuntu Security
  auditing https://documentation.ubuntu.com/security/. (Official, retrieved
  2026-06-12.)
- **Gap.** Coverage is evidence/state-focused. No watches on the secret files
  (`supabase.env`, `control-plane.env`, TLS keys), on the gateway config, or on
  privileged-command execution (`-a exit,always -F arch=b64 -S execve` for the
  runtime/sudo path). No documented `-e 2` (immutable audit config) or log
  rotation/forwarding posture. **verify in HR2 on VM** that auditd is enabled and
  rules persist across reboot.
- **Severity.** MEDIUM (good evidence coverage; gaps in secret-access and
  privileged-exec auditing).
- **Owner.** HR2 (document recommended additional watch rules + persistence); HR3
  (add safe, low-noise rules for secret files and the sudo/run_command path).
- **Validation.** HR2: `auditctl -l`, `ausearch -k sift_evidence_write`,
  `systemctl is-enabled auditd`; confirm rules survive reboot.

## 12. TLS / certificates

- **Posture.** Installer generates a **self-signed local CA + gateway cert** with
  OpenSSL (`install.sh:824-865`): CA RSA-4096 valid 3650d (`CN=sift-mcps-CA`),
  gateway key RSA-4096, cert valid 730d. Keys `0600` `sift-service`, certs `0644`,
  handoff references `ca-cert.pem`. Gateway serves TLS on 0.0.0.0:4508 with these
  files (`gateway.yaml.template` tls). OpenSearch uses `verify_certs: true` against
  the CA internally; the OpenSearch *container* itself is plain HTTP on localhost
  (§6). **verify in HR2 on VM** whether the gateway cert carries an IP SAN for
  `192.168.122.81` (the analyst connects by IP).
- **Reference.** Let's Encrypt — https://letsencrypt.org/ and the 2025 IP-cert
  announcement https://letsencrypt.org/2025/07/01/issuing-our-first-ip-address-certificate/.
  Confirmed (retrieved 2026-06-12): LE now *can* issue IP-address certs but only as
  **~6-day short-lived** certs requiring the ACME Profiles `shortlived` profile and
  `http-01`/`tls-alpn-01` (no DNS-01), and **certbot does not yet support IP SSL**
  (lego required). For an IP-only libvirt lab VM, an internal/local CA remains the
  pragmatic choice. certbot — https://certbot.eff.org/.
- **Gap.** Self-signed CA means analysts must import the CA or disable verification
  (`secure:false`-style workarounds). No documented renewal/rotation procedure for
  the 730-day gateway cert. The IP-vs-DNS-name decision is unmade (B-MVP-001). If the
  cert lacks an IP SAN, IP-based MCP clients will fail strict verification.
- **Severity.** MEDIUM (operational trust friction; not a confidentiality break since
  TLS is real).
- **Owner.** TLS1 (decide internal-CA vs DNS+ACME profile, document CA import / MCP
  endpoint trust / renewal; verify SANs include the VM IP). B-MVP-001 is the
  blocking operator decision → this is a **fork candidate** already tracked as
  B-MVP-001.
- **Validation.** TLS1: `openssl x509 -in gateway-cert.pem -noout -text` shows SANs +
  validity; analyst trust step documented; renewal rehearsed.

## 13. Hugging Face / sentence-transformers

- **Posture.** RAG embeds with sentence-transformers (required runtime dep,
  `forensic-rag-mcp/pyproject.toml` `sentence-transformers>=2.2`). Model is
  **allowlisted** to prevent arbitrary model loading
  (`rag_mcp/utils.py:28-39`: `all-MiniLM-L6-v2`, `all-mpnet-base-v2`;
  `config.py:82-86` rejects non-allowlisted). **But `SentenceTransformer(model_name)`
  is called with no `local_files_only`/offline guard** in
  `pgvector_seed.py:325`, `refresh.py:119`, `query_embedding.py:57`,
  `scripts/download_index.py:228` — so if the model is not already cached it will
  reach out to the Hugging Face Hub at runtime/seed time. This is the core of
  B-MVP-004.
- **Reference.** HF Hub cache & offline —
  https://huggingface.co/docs/huggingface_hub/guides/manage-cache (cache mechanics,
  retrieved 2026-06-12) and HF environment variables (offline switches)
  https://huggingface.co/docs/huggingface_hub/package_reference/environment_variables
  (`HF_HUB_OFFLINE=1`) plus Transformers `TRANSFORMERS_OFFLINE=1`
  https://huggingface.co/docs/transformers/installation#offline-mode. Confirmed: HF
  caches under `~/.cache/huggingface/hub`; offline env vars force no-network loads.
- **Gap.** No enforced offline mode and no pinned model revision/sha — a hardened or
  air-gapped install could silently fetch from the internet, or load a moved model
  revision. The model identity is allowlisted but the *revision* is not pinned.
- **Severity.** HIGH for an offline/air-gapped forensic deployment; MEDIUM otherwise.
- **Owner.** B-MVP-004 decision (allow live download vs pre-bundle/cache vs
  operator-provided) → HR3 (set `HF_HUB_OFFLINE`/`TRANSFORMERS_OFFLINE` in the
  service env and/or pin model revision and pre-stage the cache under the chosen
  policy). PT2 also consumes this for the RAG document flow. **Fork candidate** via
  B-MVP-004.
- **Validation.** HR2/HR3: with network blocked, seed + `kb_*` query succeed from the
  local cache; confirm no outbound to `huggingface.co` during a seed (`ss`/strace or
  egress firewall).

## 14. Hayabusa

- **Posture.** `install.sh install_hayabusa` resolves the **latest** release via the
  GitHub API (`api.github.com/.../releases/latest`, `install.sh:755`), downloads the
  zip (`install.sh:769`), checks it is a valid ZIP, installs the binary `755`, and
  symlinks `/usr/local/bin/hayabusa`. **No version pin and no SHA256/signature
  verification** of the downloaded binary (contrast §4 Supabase CLI).
- **Reference.** Hayabusa releases — https://github.com/Yamato-Security/hayabusa/releases
  and repo https://github.com/Yamato-Security/hayabusa (official). Confirmed
  (retrieved 2026-06-12): Hayabusa does not publish a stable SHA256/GPG manifest in
  release notes; GitHub now exposes per-asset SHA256 *digests* on release assets, and
  the project recommends compiling from source if supply-chain assurance is required.
- **Gap.** "Latest" + unverified binary = non-reproducible install and a supply-chain
  trust gap. A tag re-point or a compromised download is undetectable.
- **Severity.** MEDIUM (forensic tool executed under the service identity; localhost,
  but processes attacker-controlled evtx).
- **Owner.** HR3 (pin a Hayabusa version and verify via the GitHub release-asset
  SHA256 digest API, or operator-provided artifact under B-MVP-004). HR2 documents the
  current unpinned behaviour and recommended pin.
- **Validation.** HR3: install resolves a pinned tag; downloaded asset SHA256 matches
  the GitHub digest before chmod+exec; `hayabusa help` runs.

## 15. MCP / add-on manifests

- **Posture.** Add-on backends are declared by a JSON manifest validated against
  `packages/sift-gateway/src/sift_gateway/sift-backend.schema.json`; registration is
  authoritative in Supabase `app.mcp_backends` reached through the Gateway portal/API
  (`gateway.yaml.template` D22A note: legacy YAML `backends: {}` is intentionally
  non-authoritative). Secrets are env-var *references* (`bearer_token_env`,
  `tls_cert_env`, `env_refs`); usable values live only in the gateway process env.
  OpenCTI is the first external add-on (`packages/opencti-mcp/sift-backend.json`),
  installed via `scripts/setup-addon.sh`, never in the core path. Query-only /
  authority restrictions are enforced by the gateway policy middleware.
- **Reference.** Model Context Protocol spec — https://modelcontextprotocol.io/ and
  https://spec.modelcontextprotocol.io/ (transport, capabilities, tools). The
  repo's own JSON Schema is the local contract of record. (Retrieved 2026-06-12.)
- **Gap.** This is primarily a *documentation/contract completeness* gap for
  third-party authors (manifest schema, capabilities/requires, env_refs,
  authority_contract, scopes, prohibited operations, failure modes), plus the need
  for conformance tests (duplicate/shadowed tool names, missing env refs, denied
  scopes, query-only fail-closed). No core security gap observed in the manifest model
  itself; the env-ref secret model is sound.
- **Severity.** LOW (security) / this is mainly an AD1/AD2 deliverable.
- **Owner.** AD1 (author-facing spec + conformance checklist), AD2 (conformance tests
  + OpenCTI external-only proof; Windows-triage decision is B-MVP-003). *Not
  applicable* to HR3 installer hardening.
- **Validation.** AD1/AD2: golden manifest validates against the schema; negative
  cases (missing Docker, missing env var, insufficient scopes, authority attempt)
  fail closed; add-on tools appear/disappear from aggregate MCP without gateway
  restart.

---

## Cross-cutting: secrets, file modes, password hashing (INFO — already aligned)

- Secret env files (`supabase.env`, `control-plane.env`) and TLS private keys are
  written `0600` owned `sift-service` (`install.sh:1435,862-863`); TLS dir / SIFT_HOME
  `0700` (`install.sh:489-492`). Examiner password stored as PBKDF2-HMAC-SHA256 with
  **600,000 iterations** (`install.sh:897`) — matches current OWASP guidance for
  PBKDF2-SHA256. `require_password_reset: true` forces first-login reset.
  HTTP security headers (HSTS/X-Frame/CSP) and restricted CORS are set in the gateway.
- **Reference.** OWASP Password Storage Cheat Sheet —
  https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
  (PBKDF2-HMAC-SHA256 ≥600,000 iterations; retrieved 2026-06-12).
- **Severity.** INFO — recorded as a strength; no batch action. HR2 should re-assert
  these as audit checks so a regression is caught.

---

## Severity rollup

Component severities reflect the **current lab framing** (localhost binds, single
tenant, libvirt-only network). Several MEDIUMs become HIGH if the VM is exposed or
treated as production — noted inline.

| # | Component | Severity | Owner | Fork-gated? |
| --- | --- | --- | --- | --- |
| 2 | systemd hardening directives (none set) | HIGH | HR3 (HR2 baseline) | no |
| 10 | AppArmor complain-only + stale `sift-mcps-test` paths | HIGH | CL1 + HR3 | no |
| 6 | OpenSearch security plugin disabled, plain HTTP, no auth | HIGH/MED | HR3 | yes (B-MVP-005) |
| 13 | sentence-transformers no offline guard / no revision pin | HIGH/MED | HR3 | yes (B-MVP-004) |
| 4 | Supabase CLI demo keys vs production secrets | HIGH/MED | HR2 + fork | yes |
| 5 | Postgres RLS presence/FORCE unconfirmed | MED/HIGH | HR2 + fork | maybe |
| 1 | Ubuntu host baseline / firewall unasserted | MED/HIGH | HR2 | no |
| 9 | uv bootstrap `curl\|sh` unpinned/unverified | MED | HR3 | ties B-MVP-004 |
| 14 | Hayabusa latest + unverified download | MED | HR3 | ties B-MVP-004 |
| 3 | Docker container caps/no-new-priv/read-only not set | MED | HR3 | ties B-MVP-005 |
| 11 | auditd missing secret/privileged-exec watches | MED | HR2 + HR3 | no |
| 12 | TLS self-signed, renewal undocumented, IP SAN unconfirmed | MED | TLS1 | yes (B-MVP-001) |
| 7 | Gateway 0.0.0.0 bind + legacy-auth flags | MED/LOW | HR2/HR3 | no |
| 8 | Portal dev-proxy hardcoded IP + secure:false | LOW | PT1/CL1 | no |
| 15 | Add-on manifest author docs + conformance tests | LOW | AD1/AD2 | B-MVP-003 |

**Top-10 highest-severity gaps (with owner):** (2) systemd no hardening — HR3;
(10) AppArmor complain-only + stale paths — CL1+HR3; (6) OpenSearch security
disabled — HR3 (B-MVP-005 fork); (13) HF no offline guard — HR3 (B-MVP-004 fork);
(4) Supabase demo keys — HR2/fork; (5) Postgres RLS unconfirmed — HR2/fork;
(1) host firewall unasserted — HR2; (9) uv unpinned bootstrap — HR3;
(14) Hayabusa unverified download — HR3; (3) Docker container hardening — HR3.

## Operator decisions required (fork candidates)

These need an operator decision before any HR3 implementation; several already exist
as B-MVP backlog rows in `Session-Notes.md` and should be resolved there, not
silently in a batch:

- **B-MVP-001 (TLS1):** internal CA vs DNS+ACME; with the 2025 LE IP-cert change,
  short-lived IP certs are *technically* possible but certbot-unsupported — confirm
  internal-CA remains the choice for the IP-only VM, and that the gateway cert carries
  the VM IP SAN.
- **B-MVP-004 (OR4/HR2/HR3):** download/offline policy — this single decision gates
  HF offline mode (§13), uv bootstrap pinning (§9), Hayabusa pinning (§14), and the
  RAG index download checksum behaviour.
- **B-MVP-005 (HR2/HR3):** OpenSearch production posture — enable the security plugin
  (auth/TLS/audit) vs accept localhost-only-no-auth lab rationale; drives Docker
  container hardening (§3) too.
- **New fork candidate — Supabase production keys (§4):** decide whether the lab
  should rotate off Supabase CLI demo JWT/anon/service-role keys and the default DB
  password now, or stay on demo keys for the lab. Cross-cuts TLS1 and Postgres RLS.
- **New fork candidate — Postgres RLS (§5):** decide whether `app.*` control-plane /
  knowledge tables should `ENABLE`/`FORCE` RLS as defence-in-depth behind the Gateway
  boundary (schema change, out of HR3 safe-installer scope).

## Validation summary for HR2/HR3

HR2 turns this matrix into executable checks (per-component commands, expected output,
risk rating) per the BATCH-HR2 spec. HR3 implements only the deltas that are safe for
the core install and individually tested, after the fork-gated decisions above are
made. No recommendation in this matrix is implemented by HR1.
