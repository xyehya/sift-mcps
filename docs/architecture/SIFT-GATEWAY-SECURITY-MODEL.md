# SIFT Gateway — Security Model (canonical reference)

> **Read this before any gateway / security / backend / execution work.** It is the
> intended security architecture (C4 + STRIDE viewpoints VP-1..VP-5).
>
> Source of the rendered diagrams: `docs/drafts/architecture/sift-architecture.html`
> (open it for the visuals). This file condenses that document to the security
> *semantics* in text — the giant inline SVGs were stripped so agents can read it.
>
> **This is the DESIGN model. Where it disagrees with the code, the CODE wins — and
> flag the drift.** Known drift as of 2026-06-26: VP-3 stage A still mentions a
> "PR02 hash / api_key fallback"; **SEC-6 removed that — Supabase JWT is now the SOLE
> auth authority and an outage fails closed (503), with no legacy fallback.** Nuance:
> the `mcp:*` superuser *scope* still exists and grants all tools when explicitly
> assigned (`supabase_auth.py::is_tool_allowed`); SEC-6 removed only its legacy
> *default-grant* to fallback tokens — minting still must not default to it.
> The live opensearch-mcp wiring is mapped, code-verified, in
> `docs/drafts/architecture/OPENSEARCH-INTEGRATION-SPEC.md` (this doc's opensearch annex).
> **Runtime note:** these 9 design gates map to 1 catalog middleware (`mcp_server.py`)
> + the policy chain, which also carries 2 code-only objects not drawn here —
> `ControlPlaneRequiredMiddleware` (outermost: no DSN ⇒ refuse all) and
> `OpenSearchIngestStatusAugmentMiddleware` (merges durable-job rows into ingest-status).

## The model in one paragraph
The **Gateway is the single policy boundary**: every REST call, every MCP tool call,
every privileged action passes through it. **Postgres is the authoritative control
plane** (FORCE RLS); **OpenSearch is derived and never authoritative**. AI agents reach
tools only through the aggregate `/mcp`; humans use the React portal at `/portal`. Heavy
work runs as durable Postgres jobs claimed by least-privilege workers, and deep execution
is confined to an **OS-sandboxed `run_command` plane**. There is no second door.

## VP-1 — System context: who the gateway serves
Only two consumer classes exist — a **human operator** over HTTPS to `/portal`, and an
**AI agent** over MCP to `/mcp` (Supabase JWT, `/mcp` only). Both terminate at one system.
The lone external dependency, **OpenCTI**, is reached *through* the gateway under a
query-only contract — the agent never talks to it directly.

If OpenCTI later shares the OpenSearch cluster, that sharing is a conditional
deployment target, not a second authority boundary: the core Security plugin
must be enabled with TLS, the OpenCTI platform receives a dedicated `opencti*`
role, and Redis/RabbitMQ/MinIO/workers remain on an OpenCTI-only network. The
Gateway must not expose `opencti_*` through case-search tooling. Until those
compatibility, constrained-role, audit, capacity, and outage proofs pass,
OpenCTI remains stopped. Fresh deployment is the only accepted path; legacy
data migration and rollback are out of scope.

The supported OpenCTI 7 role follows upstream's required cluster-template,
ingest-pipeline, and ISM actions plus an `opencti*` index boundary. OpenSearch
cannot name-scope those cluster metadata actions; this is an explicit trusted-
component exception guarded by audit attribution and case-metadata drift proof,
not a grant of `case-*` data access. See
`docs/security/OPENCTI-SHARED-OPENSEARCH-TRUST-AND-RISK.md`.

## VP-2 — Eight planes, one gate
Authority flows one way: **Postgres (control plane) is the source of truth**; OpenSearch
(data plane) is a derived projection rebuilt from artifacts, never trusted as the system of
record. Heavy work doesn't block the agent — the gateway **enqueues a durable job**,
least-privilege workers **claim** it under a lease, confined execution writes results back
up to Postgres and out to the derived index. Evidence is operator-mounted and immutable;
reports only ever contain approved material.

| Plane | What it is |
| --- | --- |
| ① Client | Operator Portal (React/Vite, `/portal`, human-only REST) + AI Agent clients (Supabase JWT, `/mcp` only) |
| ② **Gateway — single policy boundary** (`pkg: sift-gateway`) | HTTP middleware stack (SecureHeaders → HTTPSGuard → NormalizePath → CORS → Auth; auth skips `/mcp`, which owns its own) · the 9-stage MCP tool-call chain · REST routes (`rest.py`, portal/operator) · backend aggregator (`mcp_backends_registry`, `http_backend`, `stdio_backend`) |
| ③ Core in-process tools (`sift-core`) | `run_command` (OS-sandboxed exec) · `record_finding`/`record_timeline`/todo · case/evidence/reporting/verify |
| ④ **Control plane — AUTHORITATIVE** (Supabase/Postgres, FORCE RLS) | identity + JWT principals · active-case authority · evidence custody (append-only chains) · durable jobs/steps/logs · audit events (append-only) · report+approval ledger · `mcp_backends` registry · opensearch provenance · rag pgvector |
| ⑤ Add-on MCP backends (`app.mcp_backends`) | **opensearch-mcp** (CORE, ns `opensearch`) · **forensic-rag-mcp** (CORE, ns `kb`, pgvector, knowledge-only) · **opencti-mcp** (EXTERNAL, `cti_*`, query-only) |
| ⑥ **Data plane — DERIVED** (OpenSearch, security ON, per-consumer scoped roles) | `case-*` indices · `opencti_*`/timeline · N ingest workers `sift-opensearch-worker@` (least-priv, parallel, non-blocking) |
| ⑦ Execution plane (SIFT VM) | `sift-job-worker` (claim `FOR UPDATE SKIP LOCKED`, lease 300s, poll 1s; types run_command/ingest/enrich) · sandboxed `run_command` (Landlock v4 + seccomp=kill + cgroup + AppArmor=enforce) |
| ⑧ Evidence & reports | Evidence Vault (immutable raw bytes + sha256, `chattr +i`, manifest+ledger, operator-mounted only) · Reports/Exports (APPROVED findings & data only) |

## VP-3 — One ordered path, nine fail-closed gates
Every agent tool call traverses this fixed chain (verified in `mcp_server.py` +
`policy_middleware.py`). **A deny at any stage short-circuits to an audited MCP error — the
tool body never runs.** Identity is resolved *before* the chain begins.

**Identity** — `SiftTokenVerifier` verifies the Supabase JWT → principal (type · scopes ·
case). *(Design doc says "PR02 hash / api_key fallback" — REMOVED by SEC-6; Supabase is sole
authority, fail-closed on outage.)*

1. **GatewayToolCatalog** — filter the catalog to what this principal may even see.
2. **ToolAuthorization** (B-10) — fail-closed if no identity · deny on tool_scope · rate limit.
3. **AddonAuthority** (H1) — enforce `authority_contract` + `required_scopes` · deny prohibited add-on ops.
4. **CaseContext** — inject the DB active-case context (no env / pointer trust).
5. **AuditEnvelope** — pre-dispatch DB audit write · fail-closed for write tools · append-only.
6. **ProxyActiveCase** — propagate the active case to the proxied add-on backend.
7. **EvidenceGate** — read-only reconcile mounted inventory into Postgres custody observations; REQUIRE the case-wide Custody Gate `OPEN` and every evidence input resolve to an active sealed Evidence Version, else block before dispatch. *(the hard interlock; target contract in `EVIDENCE-CUSTODY-SPEC.md`)*
8. **ResponseGuard** — redact secrets → `[REDACTED:*]` · label untrusted output · no path/traceback leaks.
9. **OpenSearchJobDispatch** — ingest/enrich → durable worker job, non-blocking (returns `job_id`).

→ **Tool body executes** — core in-process tool OR proxied add-on — only now, only if all gates passed. Result returns redacted · audited · with `job_id` if dispatched.

Fail-closed defaults: no identity → reject · tool out of scope → reject · prohibited add-on
op → reject · evidence unsealed → block · audit write fails → block.

## VP-4 — STRIDE trust boundaries and the control that closes each
Seven boundaries; every flow crosses at least one. (S poofing · T ampering · R epudiation ·
I nfo disclosure · D oS · E levation.) The two a forensic system lives or dies on are **#2**
(evidence can never be silently mutated) and **#6** (tool output is treated as hostile and
scrubbed before re-entering the agent's context — the prompt-injection-from-evidence defense).

| # | Trust boundary | STRIDE | Enforcing control |
| --- | --- | --- | --- |
| 1 | Client → Gateway single policy boundary; per-backend `/mcp` routes disabled | S T R E | `AuthMiddleware` + `SiftTokenVerifier` (Supabase JWT); `ToolAuthorization` fail-closed on no identity / out-of-scope |
| 2 | Execution/Core → Evidence Vault immutability | T R I | `EvidenceGate` (sealed + chain OK before any tool runs); `chattr +i`; append-only custody chains |
| 3 | Worker → OS Sandbox privilege confinement | E D T | Landlock v4 + seccomp=kill + AppArmor=enforce + no-new-privs; cgroup `MemoryMax`/`TasksMax`, `IPAddressDeny=any`; runtime-user fail-closed |
| 4 | Gateway → Control Plane authority | T R E | Postgres authoritative + `FORCE RLS`; `active_case_authority` (no env/pointer state); append-only audit |
| 5 | Gateway/Add-ons → Data Plane derived-data | T I E | OpenSearch never authoritative; per-consumer scoped roles; provenance; case-scoped mediated search |
| 6 | Tool output → Agent untrusted-output | I T | `ResponseGuard`: secret patterns → `[REDACTED:*]`, untrusted-output labelling, no path/traceback leaks |
| 7 | Operator → privileged action human step-up | S R E | Supabase fail-closed re-verify (CL3a/b) on case activation, evidence seal/retire, finding approval, report export, credential issuance; `approval_ledger` |

**Residual risk (boundary 2 — accepted):** custody hash, seal, and append-only chain prove
*integrity and provenance* of registered evidence — **not** that image bytes are safe to
mount or parse. Non-dry-run ingest still redirects to a mount-capable worker that may process
hostile filesystem content (kernel FS / FUSE / userspace parsers). Minimized sudoers,
EvidenceGate-before-dispatch, and least-priv workers bound *who* mounts; they do not isolate
hostile bytes from the host kernel. MicroVM / userspace-parse isolation is a separate future
mitigation; optional `isolation_tier` surfacing is separate agent-facing surface work. Detail:
`docs/codex-assessment/validation/cluster-EXEC.md` (DSS-CAN-007 residual).

**Operator intake boundary:** placing evidence bytes is a pre-agent, human VM operation.
The gateway deliberately has no `CAP_CHOWN`/`CAP_FOWNER` and never repairs evidence ownership
at seal time. `scripts/stage-evidence.sh` either copies named source bytes into the canonical
case directory or, after a manual privileged copy, offers pathless `--prepare`: it resolves the
DB-active custody-blocked case itself and requires its native service-owned `0755` evidence directory.
It validates every direct entry, rejects non-regular/linked/untrusted entries, leaves existing
immutable sealed files untouched, and descriptor-pins only eligible non-immutable
`root`/service-owned regular files before changing them to the service account and `0644`.
It does not register, seal, or make files immutable; the re-auth gated portal Seal does that.
Adding a new file must block agent dispatch without requiring an unrelated sealed file to be
unprotected. MCP tools have zero evidence-folder mutation authority: Gateway admission may inspect
the mounted tree read-only and persist the resulting custody observation, but only Portal/operator
workflows may copy, repair, protect, replace, disposition, or seal evidence. Do not expose this
helper or any equivalent filesystem/custody mutation path as an MCP tool. The canonical vocabulary,
state model, workflows, and test contract are in `docs/architecture/EVIDENCE-CUSTODY-SPEC.md`.

**Known current drift (2026-07-13):** the installed MCP evidence gate reads the persisted Postgres
head without first reconciling the mounted inventory, and active-case containment can authorize an
unregistered evidence path. P4.23 demonstrated a successful read of post-seal unregistered bytes.
Until the spec's pre-dispatch reconciliation and sealed-version authorization both land, the design
contract above is not fully enforced by code.

## VP-5 — The `run_command` jail (ceiling + floor, both deny-default)
`run_command(command: str)` runs `shell=False`, multi-stage argv (supports `| && || ; > >> < 2>&1`)
as the `agent_runtime` uid on the SIFT VM. Two stacked layers gate it before any forensic
binary runs. The ceiling reasons about *intent*; the floor enforces *capability* at the kernel.

**CEILING — policy** (`sift-core/execute/security.py`):
positive allowlist `@mvp_forensic` (`unlisted_policy = reject`, fail-closed) · generic
argv-rewriting launchers denied without partial recursive parsing · program-text scanners
(sed/sqlite3/tshark/vol/exiftool) · block shells & interpreters (sh/bash/python/perl/ruby/node ·
awk system/getline) · direct `dotnet` denied (approved Zimmerman wrappers select fixed targets) · `/var/lib/sift` hard block +
active-case-only agent input operands (including redirects and input flags; raw `input_files` is not
public) · case-confined mutation targets · output sanitation (ANSI/OSC strip · untrusted label · secret
redaction). Explicitly documented non-file flag semantics and vetted forensic `/dev` device operands are
the only path-shape exceptions.

**FLOOR — kernel/OS** (`dfir_exec_launcher.py` + `worker.py`):
runtime-user fail-closed (`SIFT_EXECUTE_REQUIRE_RUNTIME_USER`, `agent_runtime` uid) ·
`systemd-run --scope` (memory ceiling dynamically derives from 60% of current `MemAvailable` unless an
operator explicitly configures one; `TasksMax=64 OOMPolicy=kill IPAddressDeny=any`) ·
no-new-privs · Landlock ABI v4 (FS+net deny-default) · **seccomp = KILL** (SIGSYS on disallowed
syscall) · AppArmor `dfir-exec` = ENFORCE. Landlock grants read-only: case/evidence paths,
`/etc/mime.types`, `/proc/N/fd` — nothing else is reachable.

## Notation key (for the rendered HTML diagrams)
Color encodes a node's plane and trust: Gateway = the single boundary everything crosses ·
Control plane (Postgres) = authoritative · Data plane (OpenSearch) = derived, never authoritative ·
Execution = confined sandbox · Evidence/reports = immutable bytes, approved-only outputs ·
Client (operator + agent) = untrusted by default. Shapes: rounded = process/component · sharp =
external actor · cylinder = data store · red-dashed = trust boundary · double line = workers claim
durable jobs (lease) · dashed arrow = async/derived/poll.
