# Attack Path Analysis

Restored on 2026-06-26 from the Codex Security deep-scan transcript because the original `/tmp/codex-security-scans/...` artifacts were no longer present.

Original scan id: `b99549128386_20260620T080806Z`

| Candidate | Reportable | Final Severity | Confidence | Attack Path Summary |
|---|---|---|---|---|
| DSS-CAN-002 | yes | critical | high | Any bearer identity accepted by raw REST auth can attempt backend registry, service lifecycle, and join-code mutation routes. The routes validate shape and manifests but do not enforce route-local operator/admin, origin, or re-auth gates before mutating the Gateway control plane. |
| DSS-CAN-001 | yes | high | high | A non-agent/non-service REST token can POST to `/api/v1/tools/{tool_name}`. The handler calls `Gateway.call_tool` directly, bypassing MCP-only tool authorization, add-on authority, evidence gate, response guard, DB-first audit envelope, and OpenSearch job dispatch. |
| DSS-CAN-003 | yes | high | medium | A portal examiner who can satisfy re-auth can register a stdio backend with chosen `command`, `args`, and manifest/config. After materialization and start/restart, the Gateway launches that process under the Gateway account. |
| DSS-CAN-004 | yes | high | high | A caller with backend-registration authority, join-code influence, or registry write/config influence can persist an HTTP MCP backend URL. Runtime backend startup connects to that URL with only syntax checks and may attach bearer credentials, enabling persistent Gateway-originated SSRF or DNS-rebinding impact. |
| DSS-CAN-006 | yes | high | high | An authorized `run_command` caller supplies an allowlisted privileged forensic command that passes validation and fails direct execution with a permission error. The fallback internally prepends `/usr/bin/sudo -n --` and clears per-stage `runtime_user`, crossing the intended restricted-user boundary where sudoers permits it. |
| DSS-CAN-007 | yes | high | high | An authorized OpenSearch ingest caller provides malicious evidence under the active case and starts non-dry-run ingest. The job leaves the Gateway sandbox for a mount-capable worker that invokes direct sudo mount/FUSE helpers on attacker-controlled image bytes. |
| DSS-CAN-010 | yes | high | high | A caller authorized for OpenSearch query tools supplies `index=case-*`, `case-other-*`, or an exact other-case index. Gateway injects/checks `case_id` and `case_dir` only; the backend returns the explicit `index` before active-case resolution and sends it to OpenSearch. |
| DSS-CAN-014 | yes | high | high | A non-readonly portal examiner uses legacy token lifecycle routes to create, rotate, or reactivate agent tokens. TokenRegistry grants broad `mcp:*` scope and returns raw token material once. |
| DSS-CAN-015 | yes | high | high | In a Supabase-active deployment with retained legacy credentials, a legacy token can fall through REST or MCP auth because fallback defaults to enabled. MCP compatibility can stamp legacy identities with `mcp:*` scopes. |
| DSS-CAN-020 | yes | high | high | A registered or compromised stdio backend process starts with `env = dict(os.environ)`. The child can read unrelated Gateway environment secrets such as DSNs, Supabase keys, and tokens. |
| DSS-CAN-005 | yes | medium | medium | RAG refresh fetches fixed allowlisted URLs. A DNS/proxy attacker, compromised allowed host, or future allowlist expansion can make the allowed hostname resolve to a private or link-local address because validation checks only the hostname string before `urlopen`. |
| DSS-CAN-008 | yes | medium | medium | An authorized OpenSearch ingest caller supplies a tar archive under the active case. The code runs system `tar xf` before application containment checks, so extractor defaults and member side effects are the pre-write control. Local GNU tar blocked simple escape examples, narrowing the claim. |
| DSS-CAN-009 | yes | medium | medium | An authorized memory ingest caller supplies a zip/7z memory archive. The memory CLI uses a separate `7z x` extraction path without member preflight, post-containment checks, size limits, or regular-file selection before Volatility parsing. |
| DSS-CAN-011 | yes | medium | high | A caller with OpenSearch status tool or resource access invokes status with no arguments. Gateway passes through an empty safe-case set and the backend returns all `case-*` index names and counts, assisting cross-case targeting. |
| DSS-CAN-012 | yes | medium | high | A caller reaches the OpenSearch backend directly or through a Gateway-bypass path. With `SIFT_ENRICHMENT_SCOPE` unset, `opensearch_enrich_intel(dry_run=false)` skips the deny block and starts enrichment. Normal Gateway MCP remains protected by AddonAuthorityMiddleware. |
| DSS-CAN-013 | yes | medium | high | If a database/PostgREST role gains `USAGE` on schema `app`, PostgreSQL default `PUBLIC` execute can allow that role to call `app.evidence_unseal`, a SECURITY DEFINER function that changes evidence state. Current config keeps `app` out of exposed schemas, narrowing exploitability. |
| DSS-CAN-016 | yes | medium | high | A compromised OpenCTI container, connector env, worker env, compose env, or mutable `latest` image can reuse `OPENCTI_ADMIN_TOKEN` across OpenCTI admin/API, RabbitMQ, MinIO, workers, and connectors; internal OpenSearch security is disabled. |
| DSS-CAN-017 | yes | medium | medium | An authorized OpenSearch ingest caller supplies zip/7z evidence. The generic archive path trusts external 7z behavior without application-level preflight or post-checks before downstream collection/image selection. Local 7z blocked simple escapes, narrowing the impact. |
| DSS-CAN-018 | yes | medium | high | Operator configuration or environment influence sets `OPENCTI_URL` to a remote `http://` endpoint. Config validation warns but permits it, and `OpenCTIApiClient` receives the API token for plaintext transport. |
| DSS-CAN-019 | yes | medium | medium | A caller with a valid one-time setup join code posts `machine_type=wintools`, URL, and token. The join handler can persist an HTTP backend config for later runtime connection. Join-code and manifest validation narrow direct internal SSRF claims. |
| DSS-CAN-021 | yes | medium | high | A trusted allowlisted RAG upstream returns a redirect to an internal/private URL. `urlopen` follows the redirect before the code inspects `response.geturl()` and validates the final URL, allowing limited SSRF side effects or probing. |
| DSS-CAN-022 | yes | medium | high | A deployment sets `SIFT_EXECUTE_SYSTEMD_SCOPE=auto` expecting cgroup/network controls. If `systemd-run` is unavailable, the executor logs a warning and runs the direct worker without properties such as `IPAddressDeny=any`. |

## Severity Mix

| Severity | Count |
|---|---:|
| critical | 1 |
| high | 9 |
| medium | 12 |

## Confidence Mix

| Confidence | Count |
|---|---:|
| high | 16 |
| medium | 6 |
