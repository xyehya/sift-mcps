---
title: Core Tools — In-Process Forensic Investigation Core
source_commit: eadb92b
generated: 2026-06-27
verified_against: code+tests+config
invariants_checked: 14
status: draft
---

## Overview

`sift-core` (packages/sift-core/src/sift_core/) provides 8 core MCP tool specs (`case_info`, `evidence_info`, `record_finding`, `record_timeline_event`, `list_existing_findings`, `manage_todo`, `get_tool_help`, `run_command`) plus 3 gateway-local tools (`capability_guide`, `run_command_job`, `running_commands_status`) registered in the Gateway and invoked in-process. It provides case/investigation helpers and the `run_command` sandbox (ceil+floor dual-layer containment). Active evidence custody is solely Postgres-authoritative and is mediated by the Gateway's durable custody operations; retained `sift-core` file-chain helpers are legacy export/compatibility utilities, never a second authority or failover mode. Key files: `agent_tools.py`, `case_manager.py`, `execute/security.py`, `execute/dfir_exec_launcher.py`; `evidence_chain.py` is legacy/export compatibility only.

## How it works

Diagram: Core tools are invoked in-process by the Gateway via `call_core_tool()`. The dispatch routes to private handlers: `_case_info()`, `_evidence_info()`, `_record_finding()`, `_run_command()`, etc. The `run_command` handler goes through a 4-layer sandbox: command plan validation → subprocess orchestration → argv-only worker → kernel isolation (Landlock + seccomp + cgroup).

## Reference sections

### agent_tools.py — Core Tool Registry

8 tool names from `core_tool_names()`: `{"case_info", "evidence_info", "record_finding", "record_timeline_event", "list_existing_findings", "manage_todo", "get_tool_help", "run_command"}`.

**class CoreToolSpec** `@dataclass(frozen=True)`: `name`, `description`, `input_schema`, `read_only` (default False), `output_schema`.

Tool specs (from `core_tool_specs()`):
- `case_info` — read_only=True, no required input
- `evidence_info` — read_only=True, no required input
- `record_finding` — read_only=False, requires `finding` object
- `record_timeline_event` — read_only=False, requires `event` object
- `list_existing_findings` — read_only=True, optional filters
- `manage_todo` — read_only=False, requires `action` enum
- `get_tool_help` — read_only=True, requires `tool_name`
- `run_command` — read_only=False, requires `command`, `purpose`

**call_core_tool(name, arguments, *, examiner, manager, audit)** -> str: Validates name in `_SPECS_BY_NAME`. Routes via if/elif chain. Returns JSON text. Exceptions become `{"success": False, "tool": name, "data": None, "error": ...}`.

### evidence_chain.py — Legacy File/Export Compatibility Helpers

These functions describe the retained file-format implementation and its tests.
They are not the active DB custody, admission, mutation, re-authentication, or
Full Verify Evidence authority. In DB-active operation, Postgres objects,
versions, chain heads, custody events, and durable operations are authoritative;
file manifests/JSONL are export/proof artifacts only.

**class ChainStatus(str, Enum)**: OK, UNSEALED, MODIFIED, MISSING, UNREGISTERED, LEDGER_ERROR.

Key functions:
- `chain_status(case_dir)` — Fast stat-check + structural hash-chain verify, no rehashing
- `verify_chain_integrity(case_dir)` — Full structural verify (manifest hash + ledger chain)
- `seal_manifest(case_dir, file_specs, examiner, derived_key)` — Seal new manifest version
- `harden_sealed_evidence(case_dir, rel_paths)` — Set `+i` immutable flag. Fails CLOSED.
- `hash_file(path)` — Streaming SHA-256
- `compute_manifest_hash(manifest)` — SHA-256 of canonical manifest JSON

Historical file-format enforcement points in `evidence_chain.py`:
1. Manifest versioning: every mutation increments version by exactly 1
2. Ledger chain: each event carries `previous_manifest_hash` + `new_manifest_hash`; `_check_hash_chain()` links consecutive events
3. HMAC signing: every event HMAC-SHA256 signed with `derived_key`
4. Ledger file permissions: `chmod 0o444` after each append
5. Immutable flag: `+i` set on sealed files
6. Atomic writes: `tempfile.mkstemp` + `os.replace` + `os.fsync`
7. Symlink rejection: `_resolve_sealed_target()` rejects symlinks at literal path

### evidence_ops.py — Evidence Data Operations

- `register_evidence_data(case_dir, path, examiner, description)` — Register file in evidence.json. Validates path containment.
- `list_evidence_data(case_dir)` — Return registered evidence
- `verify_evidence_data(case_dir)` — SHA-256 verification of every registered file

### case_manager.py — CaseManager

**class CaseManager**: `cases_dir` (Path), `active_case_dir` (Path|None), `examiner` (str).

Key methods:
- `get_case_status(case_id)` — Postgres investigation summary in served operation; file mode is an offline compatibility helper only
- `list_cases()` — File-mode only; raises in DB mode
- `record_finding(finding, ...)` — Validate and stage finding as DRAFT. Validation pipeline: validate → allowlist fields → process supporting_commands → process artifacts → provenance scoring → confidence ceiling → persist
- `record_timeline_event(event, ...)` — Stage timeline event as DRAFT
- `add_todo(description, ...)` / `list_todos()` / `update_todo()` / `complete_todo()` — TODO lifecycle

`_require_active_case()`: Served operation requires the DB `AuthorityContext` and fails closed if it is absent. Environment/pointer lookup remains only for explicit offline compatibility mode and is never a served fallback. Closed cases are refused in either mode.
`_persist_investigation(kind, item_id, record)`: DB-active mode writes to Postgres ONLY; raises if store unavailable. Never silently degrades to file-only.
`_derive_confidence_ceiling()`: HIGH requires FULL grade + >=2 MCP ids + 0 NONE ids. Clamps agent-supplied confidence DOWN, never up.

### case_ops.py — Case Lifecycle

- `case_status_data(case_dir)` — DB-authoritative in DB mode
- `case_list_data(cases_dir)` — File-mode only; raises `InvestigationStoreError` in DB mode
- `case_init_data(name, examiner, description, cases_dir, case_id)` — Create new case directory structure + evidence chain

### execute/ — Command Execution Sandbox

4 isolation layers:

```
agent_tools._run_command() → tools.generic.run_command() → executor.execute() → worker._execute_payload() → dfir_exec_launcher.main()
```

**execute/security.py** — Policy (Ceiling):
- `DENY_FLOOR`: 130+ glob patterns (shells, interpreters, device tools, system tools, editors, debuggers)
- `MVP_FORENSIC_ALLOWLIST`: ~90 forensic tools (Sleuth Kit, Zimmerman Tools, volatility, hayabusa, curl/wget)
- `DEFAULT_SECURITY_POLICY`: `"allowlist"` mode; unlisted = `"reject"`
- `build_security_policy(operator_policy)`: Operator can only add restrictions
- `validate_shell_command()`: Full pipeline — control chars → IFS → proc/environ → process substitution → destructive patterns → split → per-subcommand validation
- `sanitize_extra_args()`: Blocks dangerous flags, shell metacharacters, program-text constructs (awk `system()`, sed `e`, sqlite3 `.shell`)
- `sanitize_paths_deep()`: Recursive path sanitization for response structures
- `resolve_evidence_ref(ref, case_dir)`: Resolves evidence ref to absolute path against sealed manifest. Defined in `evidence_chain.py` (not in this file). Fail-closed.

**execute/runtime_acl.py** — Environment Scrubbing:
- `build_sandbox_env()`: Keeps only 20 safe names (PATH, HOME, locale) + 12 safe SIFT names. Drops 45+ secret patterns.
- `is_authority_path()`: Checks against 11 authority file basenames

**execute/executor.py** — Subprocess Orchestration:
- `execute()`: Resolves runtime user. Spawns isolated worker subprocess via JSON stdin (paths never in `ps`). Systemd cgroup scope: `IPAddressDeny=any`, memory/CPU limits.

**execute/worker.py** — argv-only worker: Reads JSON from stdin. Spawns with `shell=False`. Reports `isolation` dict per stage.

**execute/dfir_exec_launcher.py** — Kernel Isolation (The "Cage"): Order of hardening (fails CLOSED each step):
1. `_close_inherited_fds()`
2. `_set_limits()`: RLIMIT_CPU, RLIMIT_AS, RLIMIT_FSIZE, RLIMIT_NOFILE(256), RLIMIT_NPROC(64), RLIMIT_CORE(0)
3. `_assert_runtime_identity()`: refuses uid 0 or service uid
4. `_set_no_new_privs()`: PR_SET_NO_NEW_PRIVS
5. `_install_landlock()`: Landlock ABI v4: read+execute on /usr, /bin, /opt/*; read-only on evidence/, mounts_ro; read+write on agent/, extractions/, tmp/; restricted /dev/* access. Blocks network if ABI >= 4.
6. `_install_seccomp()`: BPF filter — kills on 48 dangerous syscalls (ptrace, mount, chroot, bpf, clone3, io_uring, etc.). Socket always LOG-only.
7. `os.execvpe()`: env scrubbed again via `build_sandbox_env()`.

### execute/tools/generic.py — run_command()

`run_command(command, purpose, timeout, save_output, save_dir, cwd, preview_lines)`: Converts list to string via `shlex.join`. Validates via `validate_shell_command()`. Groups stages by pipeline operator. Privilege escalation retry via `sudo -n` for `_PRIVILEGED_TARGETS`. Reports `partial_failure`.

### execute/tools/discovery.py — Tool Discovery

- `list_available_tools()`, `get_tool_help()`, `suggest_tools()`, `check_tools()`, `build_tool_inventory()`

### execute/catalog.py — YAML-backed tool registry

- `load_catalog()`, `get_tool_def()`, `load_security_policy()`

### execute/job_worker.py — Durable Postgres job worker

- `JobWorker`, `ClaimedJob`, `JobContext`, `JobResult`. Claims via `app.claim_next_job()`, heartbeats, completes/fails via stored procedures.

### execute/run_command_job.py — Durable-job handler for run_command

Path-free receipt persisted to Postgres.

### case_io.py — Case I/O

- `cases_root()`: `SIFT_CASES_ROOT` > `SIFT_CASES_DIR` > `~/cases`
- `get_case_dir()`: DB context > SIFT_CASE_DIR > raise
- `resolve_case_path()`: Forces containment within case dir
- `export_bundle(case_dir, since)`: Export findings+timeline
- `import_bundle(case_dir, bundle)`: Merge incoming bundle; respects APPROVED protection
- `verify_approval_integrity(case_dir)`: Hash-based approval verification

### finding_validation.py — Finding Validation

`validate(finding)`: Required fields: title, observation, interpretation, confidence, type, host. Valid types: finding/attribution/conclusion/exclusion. Confidence must be exactly HIGH/MEDIUM/LOW/SPECULATIVE. Attribution requires 3+ audit_ids (FD-003).

### identity.py — Identity Resolution

`get_examiner_identity()`: `--examiner` flag > SIFT_EXAMINER env > SIFT_ANALYST env > ~/.sift/config.yaml > OS user. Slug: lowercase alphanumeric + hyphens, max 20 chars.

### reporting.py — Report Generation

`generate_report_data(profile_name, case_dir, ...)` — 6 profiles: full, executive, timeline, ioc, findings, status. Reports include **only APPROVED** items. `build_mitre_mapping()`, `build_custody_appendix()`, `reconcile_verification_db()` for DB content_hash verification.

### approval_auth.py — Legacy Local-Mode Password Helpers

This module is not the active Portal sensitive-action verifier. Current Portal
actions use fresh Supabase password re-verification for the signed-in identity,
then bind a scoped, consumable DB audit receipt to the transition.

`set_password(config_path, analyst)`: PBKDF2-SHA256, 600K iterations, random 32-byte salt.
`verify_password()`: Constant-time comparison.
`require_confirmation()`: Prompt via `/dev/tty` raw mode (blocks LLM-via-Bash). 3 attempts, 15-min lockout.
`derive_auth_key()` / `derive_ledger_key()`: Domain-separated sub-keys.

### active_case_context.py — AuthorityContext

**class AuthorityContext** `@dataclass(frozen=True)`: `case_id`, `case_key`, `artifact_path`, `membership_role`, `principal`, `principal_type`, `tool_scopes`, `evidence_gate_status`, `db_active`, `audit_event_ids`.

`current_active_case()` → AuthorityContext | None. `db_authority_active()`: True when context says `db_active=True` OR `SIFT_DB_ACTIVE` env var. When True, core resolvers must NOT use SIFT_CASE_DIR or ~/.sift/active_case.

## Invariants

- **DB authority fails closed**: Core resolvers use only `AuthorityContext` for
  active workflows. Case data writes go to Postgres and raise if the store is
  unavailable; legacy file helpers never become a fallback authority.
- **DB custody is append-only**: Postgres custody events and versions are
  hash-linked and mutation-guarded; each successful seal increments manifest
  version exactly once. Protected filesystem posture is verified separately.
- **run_command sandbox defaults to deny**: Both ceiling (policy allowlist) and floor (kernel Landlock/seccomp) default deny. `validate_shell_command()` prevents injection. (`execute/security.py`, `execute/dfir_exec_launcher.py`)
- **Reports include only APPROVED items**: Draft/rejected findings and timeline events are dropped. (`reporting.py`)
- **Finding confidence ceiling is provenance-derived**: Agent-supplied confidence is clamped DOWN, never up. (`case_manager.py:_derive_confidence_ceiling()`)
- **Case list in DB mode raises**: `case_list_data()` raises `InvestigationStoreError` in DB mode — the authoritative case list is the Gateway `ActiveCaseService`. (`case_ops.py`)

## Gotchas & Edge Cases

> [!warning] `_derive_confidence_ceiling()` requires FULL grade + >=2 MCP ids + 0 NONE ids for HIGH. An agent-provided HIGH with insufficient provenance is silently downgraded. (`case_manager.py`)

> [!important] `_persist_investigation` in DB mode raises if store is unavailable — it does NOT silently degrade to file writing. (`case_manager.py`)

> [!warning] Run_command with `shell=False` means pipes (`|`), redirects (`>`), and backgrounding (`&`) are parsed by the validator, not the shell. The `split_command_by_operators()` function handles these explicitly. (`execute/security.py`)

> [!note] The Landlock sandbox blocks all network access when ABI >= 4. Tools needing network (curl, wget) work at the restricted level. Socket syscall is seccomp LOG-only (not killed). (`execute/dfir_exec_launcher.py`)

## Related

- Gateway doc (how core tools are registered and dispatched via `GatewayLocalTool`)
- Shared Contracts doc (AuditWriter used by all core tool handlers for logging)
- Control Plane doc (Postgres schema for investigation_store, audit_events)

## Key files

- `agent_tools.py` — 8 core tool specs, call_core_tool dispatcher
- `evidence_chain.py` — Append-only hash-linked evidence chain
- `evidence_ops.py` — Evidence data operations (register, list, verify)
- `case_manager.py` — CaseManager class, finding/timeline/todo lifecycle
- `case_ops.py` — Case lifecycle (init, activate, status)
- `case_io.py` — Case path resolution, file I/O with atomic writes
- `execute/security.py` — run_command sandbox ceiling (policy)
- `execute/dfir_exec_launcher.py` — run_command sandbox floor (kernel)
- `execute/executor.py` — Subprocess orchestration with systemd cgroup
- `execute/worker.py` — argv-only worker (paths never in ps)
- `execute/job_worker.py` — Durable Postgres job worker loop
- `execute/tools/generic.py` — run_command() implementation
- `execute/catalog.py` — YAML-backed forensic tool catalog
- `execute/runtime_acl.py` — Environment scrubbing and authority-path protection
- `finding_validation.py` — Finding validation rules
- `identity.py` — Examiner identity resolution
- `reporting.py` — Report generation (6 profiles, approved-only)
- `approval_auth.py` — legacy/local-mode password and HMAC compatibility helpers; not active Portal re-auth
- `active_case_context.py` — AuthorityContext, db_authority_active
- `investigation_store.py` — InvestigationAuthorityStore ABC + Postgres impl

## Reconciliation log

None — independently confirmed against code.
