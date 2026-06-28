---
title: Security Architecture — Controls and Threat Model
source_commit: eadb92b
generated: 2026-06-27
verified_against: code+tests+config
invariants_checked: 27
status: draft
---

## 1. Security Controls on the Architecture (Full Diagram)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ ① CLIENT PLANE                                                              │
│  ┌──────────────────────────┐   ┌──────────────────────────────┐            │
│  │ Operator Portal          │   │ AI Agents                    │            │
│  │ [HSTS][CSP][XFO]        │   │ [IP Rate Limit]               │            │
│  │ [HTTPSRedirect]         │   │ [Origin Check]                │            │
│  │ [Cookie: 12h absolute]  │   │ [Bearer JWT]                  │            │
│  └───────────┬──────────────┘   └────────┬─────────────────────┘            │
└──────────────┼───────────────────────────┼──────────────────────────────────┘
               │ HTTPS /portal/*           │ MCP /mcp (Bearer JWT)
               ▼                           ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ ② GATEWAY — SINGLE POLICY BOUNDARY (sift-gateway)                          │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ HTTP Middleware Stack                                                  │  │
│  │  [SecureHeaders: HSTS/CSP/XFO/CTO/RP][PortalHTTPSGuard]               │  │
│  │  [NormalizeMCPPath][AuthMiddleware][CORS]                              │  │
│  ├───────────────────────────────────────────────────────────────────────┤  │
│  │ MCP Surface (/mcp):                                                    │  │
│  │  MCPAuthASGIApp▸[BodyCap10MB][TokenVerify][ReadonlyGuard]              │  │
│  │  → FastMCP → 10-Stage Policy Chain:                                    │  │
│  │   [1]  ControlPlaneRequired — no DSN ⇒ deny all                        │  │
│  │   [2]  ToolAuthorization — B-10 scope gate + rate limit                │  │
│  │   [3]  AddonAuthority — prohibited ops gate + authority_contract       │  │
│  │   [4]  CaseContext — DB-authority active case injection                │  │
│  │   [5]  AuditEnvelope — pre-dispatch write, fail-closed for mutating    │  │
│  │   [6]  ProxyActiveCase — case-bound args to proxied backends           │  │
│  │   [7]  EvidenceGate — chain status gate, DB-authority                  │  │
│  │   [8]  ResponseGuard — secret/path redaction, output cap               │  │
│  │   [9]  IngestStatusAugment — merge durable-job rows                   │  │
│  │   [10] JobDispatch — enqueue ingest/enrich to worker queue             │  │
│  ├───────────────────────────────────────────────────────────────────────┤  │
│  │ REST Surface (/portal, /health, /api):                                  │  │
│  │  AuthMiddleware [Bearer Verify][Session Cookie]                         │  │
│  │  require_control_plane_operator [agent/service deny]                   │  │
│  │  require_recent_reauth [step-up password re-verify]                    │  │
│  │  approval_ledger [operator approval required for privileged actions]   │  │
│  └───────┬───────────────────────────────────────────────────────────────┘  │
└──────────┼──────────────────────────────────────────────────────────────────┘
           │
     ┌─────┼─────────────┬──────────────────────┬──────────────────┐
     ▼     ▼             ▼                      ▼                  ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────────┐ ┌────────────────────┐
│ ③ CORE       │ │ ④ CONTROL   │ │ ⑤ ADD-ON MCP     │ │ ⑥ DATA PLANE      │
│ IN-PROCESS   │ │ PLANE        │ │ BACKENDS          │ │ (DERIVED)          │
│ TOOLS        │ │ (AUTHORIT.)  │ │                   │ │                    │
│ (sift-core)  │ │              │ │ opensearch-mcp    │ │ OpenSearch         │
│              │ │ Supabase/    │ │ [query-only][ns]  │ │ [scoped roles]     │
│ run_command  │ │ Postgres     │ │ forensic-rag-mcp  │ │ [provenance        │
│ [Landlock+   │ │ [FORCE RLS]  │ │ [knowledge-only]  │ │  stamping]         │
│  seccomp]    │ │ [append-only │ │ opencti-mcp       │ │ [case-* indices]   │
│ record_      │ │  audit]      │ │ [query-only]      │ │                    │
│ finding      │ │ [active_case │ │ [external]        │ └────────────────────┘
│ evidence_    │ │  authority]  │ │                    │
│ chain        │ │ [pgvector]   │ └────────────────────┘
│ [append-only]│ │              │
└──────────────┘ └──────────────┘
     │                  │
     ▼                  ▼
┌──────────────────────────────────────────────┐
│ ⑦ EXECUTION PLANE (SIFT VM)                  │
│  ┌────────────────────────────────────────┐   │
│  │ sift-job-worker                         │   │
│  │ [claim: FOR UPDATE SKIP LOCKED]         │   │
│  │ [lease: 300s][poll: 1s]                │   │
│  ├────────────────────────────────────────┤   │
│  │ dfir-exec-launcher                      │   │
│  │  [Landlock ABI v4: FS+net deny-default] │   │
│  │  [seccomp=KILL: 30 syscall kill set]   │   │
│  │  [no_new_privs][rlimits: 4G/64 tasks]  │   │
│  │  [systemd-run --scope][cgroup]          │   │
│  │  [AppArmor=ENFORCE][runtime-user]       │   │
│  │  [env scrub: allowlist+secret deny]     │   │
│  └────────────────────────────────────────┘   │
└──────────────────────────────────────────────┘
     │
     ▼
┌──────────────────────────────────────────────┐
│ ⑧ EVIDENCE & REPORTS PLANE                   │
│  ┌───────────────────┐ ┌───────────────────┐  │
│  │ Evidence Vault     │ │ Reports / Exports  │  │
│  │ [chattr +i]       │ │ [APPROVED only]    │  │
│  │ [SHA-256 hashes]  │ │ [evidence chain    │  │
│  │ [manifest+ledger] │ │  appendix]         │  │
│  │ [operator-mount]  │ │                    │  │
│  └───────────────────┘ └───────────────────┘  │
└──────────────────────────────────────────────┘
```

## 2. Security Control Reference (27 Controls)

| # | Control Name | STRIDE | Layer | File:Symbol | Fail-Closed | What It Protects |
|---|---|---|---|---|---|---|
| 1 | `SecureHeadersMiddleware` | T/I | Application | `server.py:48` | Yes | Portal browser surface — HSTS, CSP, XFO, CTO, Referrer-Policy |
| 2 | `PortalHTTPSGuard` | T/I/S | Network | `server.py:27` | Yes | Portal credentials in transit — rejects plain HTTP for /portal when TLS configured |
| 3 | `MCPAuthASGIApp` (8 sub-guards) | S/E/D | Application | `mcp_endpoint.py:305` | Yes | MCP surface access — body cap 10 MB, token verify, readonly guard, origin check |
| 4 | `SiftTokenVerifier` | S/E | Application | `mcp_endpoint.py:155` | Yes | MCP tool access — Supabase JWT verification, principal resolution |
| 5 | `ToolAuthorizationMiddleware` | E | Application | `policy_middleware.py:280` | Yes | Tool access by scope — B-10 scope gate, deny on missing identity/scope |
| 6 | `AddonAuthorityMiddleware` | E/T | Application | `policy_middleware.py:394` | Yes | Add-on tool enforcement — authority_contract + required_scopes, deny prohibited ops |
| 7 | `ControlPlaneRequiredMiddleware` | E/I | Application | `policy_middleware.py:530` | Yes | DFIR tool calls — no service DSN => refuse all tools |
| 8 | `CaseContextMiddleware` | E/I | Application | `policy_middleware.py:756` | Yes | Case isolation — inject DB-active case, never from env/pointer |
| 9 | `ProxyActiveCaseMiddleware` | E/T | Application | `policy_middleware.py:839` | Yes | Case-bound args — propagate active case to proxied add-on backends |
| 10 | `AuditEnvelopeMiddleware` | R/T | Applic/Data | `policy_middleware.py:979` | Yes | Non-repudiation — pre-dispatch DB audit write, fail-closed for mutating tools |
| 11 | `EvidenceGateMiddleware` | T/S | Applic/Data | `policy_middleware.py:580` | Yes | Evidence chain integrity — gate on chain_status before tool execution |
| 12 | `ResponseGuardMiddleware` | I | Application | `policy_middleware.py:649` | Yes | Secret/path leakage — redact secrets → `[REDACTED:*]`, label untrusted output, no traceback leaks |
| 13 | `check_evidence_gate_db` | T | Applic/Data | `evidence_gate.py:62` | Yes | Evidence chain — DB-authority seal status resolution, fail-closed on DB error |
| 14 | `assert_actor_may_mutate_control_plane` | E/T | Application | `mcp_backends_registry.py:276` | Yes | Registry mutations — only control-plane operators may modify backend registry |
| 15 | `normalize_connection_config` | T/I | Application | `mcp_backends_registry.py:314` | Yes | Backend secrets — strip sensitive fields from connection configs |
| 16 | `assert_stdio_command_allowlisted` | E/T/R | Application/OS | `mcp_backends_registry.py:445` | Yes | Add-on binary execution — deny non-allowlisted stdio backends |
| 17 | `DENY_FLOOR` / `validate_shell_command` | R/E | Application/OS | `security_policy.py:14` / `security.py:856` | Yes | Malicious binary exec — 130+ denied patterns (shells, interpreters, device tools, privilege escalators) |
| 18 | Binary allowlist mode | E | Application/OS | `security.py:920` / `security_policy.py:200` | Yes | Unapproved tools — `MVP_FORENSIC_ALLOWLIST` with fail-closed reject |
| 19 | `sanitize_extra_args` | R/T | Application | `security.py:84` | Yes | Argument injection — tool-specific flag blocking, destructive pattern rejection |
| 20 | Output/Input/Mutating path validation | T/E/I | Application/OS | `security.py:377,444,814` | Yes | System file protection — case write-jail, protected path rejection |
| 21 | Evidence ref / Output ref resolution | I/T | Application | `security.py:1166,1226` | Yes | Arbitrary file read — refs resolve only within case directory |
| 22 | Path sanitization (tool boundary) | I | Application | `security.py:1312` | Yes | Path leakage — `sanitize_path_value` collapses absolute paths to relative or `[REDACTED:absolute_path]` |
| 23 | Landlock + seccomp + no_new_privs + rlimits | E/T/D | Kernel | `dfir_exec_launcher.py:531` | Yes | Subprocess containment — Landlock FS+net deny-default, seccomp=KILL, no_new_privs, rlimits 4G/64 tasks |
| 24 | Environment scrubbing | I/E | Application/OS | `runtime_acl.py:153` | Yes | Credential leakage — allowlist-only env with secret-pattern deny pass |
| 25 | Authority-file write protection | T/R | Application/Data | `runtime_acl.py:232,244` | Yes | Integrity record overwrite — block writes to audit/anchors/authority paths |
| 26 | Evidence chain append-only | T/R | Applic/Data/Blockchain | `evidence_chain.py` | Yes | Evidence tampering — SHA-256 hash chain, ledger.jsonl append-only, `chattr +i` on seal |
| 27 | Tool-boundary path redaction | I | Application | `security.py:1312` | Yes | Path leakage — deep recursive path sanitization through response structures |

### Control Detail Notes

**Control 3 — MCPAuthASGIApp sub-guards:**
- Body size cap (10 MB) — rejects oversized MCP messages
- Token verification — Supabase JWT validation before any processing
- Readonly guard — denies mutation tools to read-only principals
- Origin check — validates Origin/Referer headers for browser-based MCP clients
- HTTP method enforcement — only POST/SSE allowed
- Path validation — only `/mcp` and `/mcp/{name}` served
- Header sanitization — strips internal headers before forwarding
- Rate limiting — per-IP/principal token bucket

**Control 17 — DENY_FLOOR categories (130+ patterns):**
- Shells/interpreters: sh, bash, dash, zsh, python*, perl*, ruby*, node*, php, lua*
- Device/filesystem destruction: mkfs, dd, shred, wipefs, blkdiscard, mount, losetup
- Privilege escalation: sudo, chroot, nsenter, unshare, setcap, capsh
- Network: nc, ncat, socat
- Editors/pagers: vi, vim, nano, emacs, less, more
- Process control: kill, killall, pkill, nohup, timeout, xargs
- Container/podman/docker: any container runtime

**Control 23 — Kernel isolation stack (dfir_exec_launcher.py:531 `_prepare_and_exec`):**
1. `_close_inherited_fds()` — close all inherited FDs beyond stdin/out/err
2. `_set_limits(policy)` — rlimits: `RLIMIT_AS=4G`, `RLIMIT_NPROC=64`, `RLIMIT_NOFILE=128`
3. `_assert_runtime_identity(policy)` — verify running as `agent_runtime` uid
4. `_set_no_new_privs()` — `prctl(PR_SET_NO_NEW_PRIVS)` prevents privilege gain via setuid/setcap
5. `_install_landlock(policy)` — Landlock ABI v4: deny-default FS access, grant read-only to case/evidence paths, `/etc/mime.types`, `/proc/N/fd`
6. `_install_seccomp(policy)` — seccomp-BPF: KILL action on 30 disallowed syscalls (clone, mount, reboot, ptrace, etc.)
7. `os.execvpe(real_argv[0], real_argv, env)` — execute with scrubbed environment

## 3. STRIDE Threat Model

The architecture defines 7 trust boundaries (mapped from the C4+STRIDE viewpoints in `docs/architecture/SIFT-GATEWAY-SECURITY-MODEL.md`):

| # | Trust Boundary | S | T | R | I | D | E | Key Control(s) |
|---|---|---|---|---|---|---|---|---|
| 1 | Client → Gateway | ✓ | ✓ | ✓ | | | ✓ | `AuthMiddleware` + `SiftTokenVerifier` (Supabase JWT), `ToolAuthorization` fail-closed on no identity, `PortalHTTPSGuard` enforces TLS, `SecureHeadersMiddleware` hardens browser surface |
| 2 | Execution → Evidence Vault | | ✓ | ✓ | ✓ | | | `EvidenceGateMiddleware` + `check_evidence_gate_db` (sealed + chain OK before tool runs), `chattr +i` on sealed evidence, append-only custody chains with SHA-256 hash chain |
| 3 | Worker → OS Sandbox | | | | | ✓ | ✓ | Landlock ABI v4 (FS+net deny-default), seccomp=KILL (30 syscall deny), no_new_privs, AppArmor=ENFORCE, cgroup `MemoryMax=4G`/`TasksMax=64`, `IPAddressDeny=any`, runtime-user fail-closed (`agent_runtime` uid), `systemd-run --scope` |
| 4 | Gateway → Control Plane | | ✓ | ✓ | | | ✓ | Postgres authoritative + `FORCE RLS` on all app tables, `active_case_authority` (DB-resolved, never env/pointer), append-only audit via `AuditEnvelopeMiddleware`, audit writer has no `BYPASSRLS` |
| 5 | Gateway/Add-ons → Data Plane | | ✓ | | ✓ | | ✓ | OpenSearch never authoritative (Postgres is the source of truth), per-consumer scoped roles, provenance stamping on all indexed documents, case-scoped mediated search (`case-*` index prefix isolation) |
| 6 | Tool output → Agent | | | | ✓ | ✓ | | `ResponseGuardMiddleware`: secret patterns → `[REDACTED:*]`, untrusted-output labelling, no path/traceback leaks, `sanitize_paths_deep` recursive redaction, output size cap |
| 7 | Operator → privileged action | ✓ | | ✓ | | | ✓ | Supabase fail-closed re-verify on case activation, evidence seal/retire, finding approval, report export, credential issuance; `require_recent_reauth` step-up; `approval_ledger` in Postgres |

### STRIDE Category Legend

- **S**poofing — impersonating a user, agent, or component
- **T**ampering — modifying data or code in transit or at rest
- **R**epudiation — denying an action without verifiable proof
- **I**nformation disclosure — leaking sensitive data to unauthorized parties
- **D**enial of service — exhausting resources or crashing services
- **E**levation of privilege — gaining unauthorized access or capabilities

## 4. Defense-in-Depth: run_command Sandbox

The `run_command` tool implements a four-layer defense-in-depth architecture. Every layer is deny-default — a command must survive all four to execute.

```
Layer 1: COMMAND VALIDATION (security.py:validate_shell_command)
  ┌─────────────────────────────────────────────────────────────┐
  │ Rejects:                                                     │
  │  • Control characters (null, BEL, escape sequences)          │
  │  • IFS manipulation via variable assignment in argv          │
  │  • proc/environ reads (/proc/*/environ, /proc/*/fd/*)        │
  │  • Process substitution (<(), >(), $(...))                   │
  │  • Destructive patterns (dd if=/dev/zero, mkfs, mount)       │
  │  • Sudo/timeout/nohup prefix wrapping                        │
  │  • Pipeline-to-logic-chain with dangerous combinations       │
  │  • Binary resolution — finds binary, rejects case-shadow     │
  └─────────────────────────────────────────────────────────────┘
                              │ pass
                              ▼
Layer 2: BINARY POLICY (security.py + security_policy.py)
  ┌─────────────────────────────────────────────────────────────┐
  │ 1. DENY_FLOOR (130+ patterns): ::frozenset                   │
  │    • Shells: sh, bash, python*, perl*, ruby*, node, ...      │
  │    • Device: dd, mount, mkfs, shred, wipefs, ...             │
  │    • Escalation: sudo, chroot, nsenter, setcap, ...          │
  │    • Network: nc, ncat, socat, ...                           │
  │    Always enforced — cannot be overridden.                   │
  │                                                              │
  │ 2. Allowlist mode (configurable):                             │
  │    • MVP_FORENSIC_ALLOWLIST: sleuthkit, bulk_extractor,      │
  │      yara, evtx_dump, tshark, vol, exiftool, ...             │
  │    • Any binary not in allowlist ⇒ reject                    │
  │                                                              │
  │ 3. Tool-specific flag blocking:                               │
  │    • sanitize_extra_args() — rejects destructive flags       │
  │      per tool (e.g. grep --binary-files, sed -i)             │
  │                                                              │
  │ 4. Program-text scanning:                                     │
  │    • sed/sqlite3/tshark/vol/exiftool have inline text        │
  │      scanners that verify the full program text              │
  └─────────────────────────────────────────────────────────────┘
                              │ pass
                              ▼
Layer 3: SUBPROCESS ORCHESTRATION (executor.py + worker.py)
  ┌─────────────────────────────────────────────────────────────┐
  │ • systemd-run --scope --property=MemoryMax=4G               │
  │ • systemd-run --scope --property=TasksMax=64                │
  │ • systemd-run --scope --property=OOMPolicy=kill             │
  │ • systemd-run --scope --property=IPAddressDeny=any          │
  │ • Runtime-user transition: agent_runtime uid                │
  │ • JSON stdin (paths never visible in ps output)             │
  │ • Inherits service uid, drops all group memberships         │
  │ • Poll 1s, lease 300s, claim: FOR UPDATE SKIP LOCKED        │
  └─────────────────────────────────────────────────────────────┘
                              │ pass
                              ▼
Layer 4: KERNEL ISOLATION (dfir_exec_launcher.py:_prepare_and_exec)
  ┌─────────────────────────────────────────────────────────────┐
  │ 1. Inherited FD cleanup (_close_inherited_fds)               │
  │    — Close all FDs beyond stdin(0)/stdout(1)/stderr(2)       │
  │                                                              │
  │ 2. rlimits (_set_limits)                                     │
  │    — RLIMIT_AS:       4 GB (address space)                   │
  │    — RLIMIT_NPROC:    64 (fork/clone limit)                  │
  │    — RLIMIT_NOFILE:   128 (open FD limit)                    │
  │    — RLIMIT_CORE:     0 (no core dumps)                      │
  │                                                              │
  │ 3. Runtime identity check (_assert_runtime_identity)         │
  │    — Must be agent_runtime uid; raises if not                │
  │                                                              │
  │ 4. no_new_privs (_set_no_new_privs)                          │
  │    — prctl(PR_SET_NO_NEW_PRIVS, 1)                          │
  │    — Blocks all privilege escalation via setuid/setcap/      │
  │      capability inheritance                                  │
  │                                                              │
  │ 5. Landlock LSM (_install_landlock)                          │
  │    — ABI v4: handled_fs = all FS actions                     │
  │    — handled_net = TCP bind/connect (kernel 6.x)            │
  │    — Deny-default: nothing accessible until granted           │
  │    — Grants read-only:                                       │
  │       • Case/evidence directories (resolved)                 │
  │       • /etc/mime.types, /etc/passwd (system aux)           │
  │       • /proc/N/fd (tool's own stdin/out/err)               │
  │    — Everything else: EACCES                                 │
  │                                                              │
  │ 6. seccomp-BPF (_install_seccomp)                            │
  │    — Default action: KILL (SIGSYS)                           │
  │    — Allowlisted syscalls only: read, write, open, close,   │
  │      mmap, munmap, brk, exit_group, etc. (~60 basic)        │
  │    — Denied syscalls (SIGSYS on any attempt):                │
  │       clone (thread), mount, umount, swapon, swapoff,       │
  │       pivot_root, chroot, ptrace, process_vm_readv,         │
  │       kexec_load, bpf, perf_event_open, etc.                │
  │                                                              │
  │ 7. Scrubbed environment (build_sandbox_env)                  │
  │    — Only explicit safe allowlist names survive              │
  │    — Secret-pattern deny (token, password, key, secret,      │
  │      credential, auth, jwt, dsn, api_key, ...)              │
  │    — TERM=dumb, LC_ALL=C.UTF-8 forced                       │
  │                                                              │
  │ 8. execvpe (no shell wrapper)                                │
  │    — Direct syscall exec, never through /bin/sh -c           │
  └─────────────────────────────────────────────────────────────┘
                              │ pass
                              ▼
                     FORENSIC TOOL EXECUTES
                     (or returns EACCES/SIGSYS if kernel denies)
```

## 5. Security Invariants

All 17 declared architecture invariants from `docs/architecture/SIFT-GATEWAY-SECURITY-MODEL.md`:
Verified against code at commit `eadb92b`. Each invariant includes its enforcement mechanism and source citation.

| # | Invariant | Enforcement | Code Citation |
|---|---|---|---|
| 1 | **Postgres authoritative, OpenSearch derived** | Control plane queries always read Postgres; OpenSearch is a rebuildable derived index. OpenSearch never authorizes tool access, case context, or evidence status. | `policy_middleware.py:756` (CaseContext reads Postgres), `evidence_gate.py:62` (DB-authority gate), `OPENSEARCH-INTEGRATION-SPEC.md` |
| 2 | **Single policy boundary** | Every REST call and every MCP tool call passes through the gateway HTTP middleware stack + 10-stage policy chain. No backend is reachable directly. Per-backend `/mcp` routes are disabled. | `server.py`, `mcp_server.py`, `mcp_endpoint.py:305` (MCPAuthASGIApp) |
| 3 | **Evidence append-only** | `evidence_chain.py`: SHA-256 hash chain with ledger.jsonl append-only writes; manifest versioning; `chattr +i` on seal; `EvidenceGateMiddleware` blocks tools if chain is unsealed/violated. | `evidence_chain.py`, `evidence_gate.py:62`, `policy_middleware.py:580` |
| 4 | **Supabase sole credential (SEC-6)** | Supabase JWT is the sole auth authority. No PR02 hash/api_key fallback. Outage fails closed (503). The `mcp:*` superuser scope exists but must be explicitly assigned, never default-granted. | `mcp_endpoint.py:155` (SiftTokenVerifier), `supabase_auth.py` (is_tool_allowed), `SECURITY-MODEL.md` SEC-6 |
| 5 | **Mutating tools fail-closed on audit failure** | `AuditEnvelopeMiddleware` pre-dispatch DB audit write for mutating tools; if the write fails, the tool call is rejected before execution. | `policy_middleware.py:979` |
| 6 | **Agent TTL >= 48h (AUT2-B0)** | Agent sessions (supabase JWT) have a minimum 48-hour TTL. Implementation: JWT expiry set to 48h from issuance. | `supabase_auth.py`, `token_gen.py` |
| 7 | **No raw token storage** | Tokens are verified but never stored in logs, DB, or response bodies. `ResponseGuardMiddleware` redacts token patterns. `security.py` env scrubbing strips token env vars. | `response_guard.py`, `security.py:1312`, `runtime_acl.py:153` |
| 8 | **Redact-then-cap** | Output is redacted first (`ResponseGuardMiddleware`, `sanitize_paths_deep`), then capped to max size. Order guarantees secrets are not in truncated content. | `policy_middleware.py:649`, `security.py:1312` |
| 9 | **Control-plane DSN required for DFIR tools** | `ControlPlaneRequiredMiddleware`: if no service DSN is configured, all DFIR tool calls are rejected before any policy check. | `policy_middleware.py:530` |
| 10 | **Evidence gate DB-authoritative** | `check_evidence_gate_db` resolves seal status from Postgres (`app.evidence_gate_status`) by case_id. File-backed gate removed (BU3/XYE-21). DB error => blocked=True (UNSEALED). | `evidence_gate.py:62` |
| 11 | **Case index prefix isolation** | OpenSearch indices for case data are prefixed `case-*`. Search is scoped to the active case's index. Cross-case search requires explicit portal approval. | `opensearch-mcp` tool routing, `policy_middleware.py:839` (ProxyActiveCase) |
| 12 | **Ingest/enrich result_public path-free** | Worker `result_public` envelope contains structured content only — no local file paths, no absolute references. Paths are resolved server-side and redacted before reaching the agent. | `security.py:1312` (sanitize_path_value), worker `result_public` schema |
| 13 | **Provenance stamping on all indexed docs** | Every document indexed into OpenSearch carries a provenance block: `case_id`, `tool_name`, `agent_id`, `indexed_at`, `source` (gateway/worker/portal). | OpenSearch ingest pipelines, `mcp_backends_registry.py` |
| 14 | **Knowledge-only enforcement for RAG** | `forensic-rag-mcp` operates in knowledge-only mode: pgvector semantic search over pre-ingested knowledge base, never raw evidence text. Results are citations, not document content. | `forensic-rag-mcp`, `policy_middleware.py:394` (AddonAuthority) |
| 15 | **Portal cookie 12h absolute ceiling** | Portal session cookie has a 12-hour absolute expiry. Re-authentication required after expiry. No sliding extension beyond 12h. | `server.py`, `auth.py` session config |
| 16 | **FORCE RLS on all app tables** | All application tables in Supabase/Postgres use `FORCE ROW LEVEL SECURITY`. Every query is scoped by the authenticated principal's identity and case membership. Audit writer has no `BYPASSRLS`. | Supabase migrations (docs/latest/08 - Control Plane.md), `evidence_gate.py` |
| 17 | **Audit writer no BYPASSRLS** | The Postgres user used for audit log writes does not have the `BYPASSRLS` attribute. RLS policies govern every row written. | Postgres role configuration, `audit_helpers.py` |
