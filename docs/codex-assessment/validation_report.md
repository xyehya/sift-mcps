# Validation Report

Restored on 2026-06-26 from the Codex Security deep-scan transcript because the original `/tmp/codex-security-scans/...` artifacts were no longer present.

Original scan id: `b99549128386_20260620T080806Z`

Source validation artifacts originally referenced:

- `artifacts/validation_workers/gateway_auth_validation.md`
- `artifacts/validation_workers/egress_transport_validation.md`
- `artifacts/validation_workers/execution_archive_validation.md`
- `artifacts/validation_workers/opensearch_case_validation.md`
- `artifacts/validation_workers/db_opencti_validation.md`

| Candidate | Verdict | Severity | Confidence | Notes |
|---|---|---|---|---|
| DSS-CAN-001 | valid | high | high | REST tool execution bypasses the MCP policy middleware stack. |
| DSS-CAN-002 | valid | critical | high | Direct Gateway REST control-plane routes lack operator, origin, and re-auth gates. |
| DSS-CAN-003 | valid | high | medium | Examiner backend management can register and start arbitrary stdio backend commands; confidence narrowed by possible intended examiner authority. |
| DSS-CAN-004 | valid | high | high | HTTP MCP backend runtime egress validation can reach private or rebound destinations. |
| DSS-CAN-005 | partial | medium | medium | RAG URL fetch missing resolved-address checks is real, but current source set is fixed and exploitability is constrained. |
| DSS-CAN-006 | valid | high | high | Privileged `run_command` sudo fallback can bypass runtime-user launcher isolation. |
| DSS-CAN-007 | valid | high | high | OpenSearch ingest privileged mount path runs outside the generic command validator and sandbox channel. |
| DSS-CAN-008 | partial | medium | medium | OpenSearch tar extraction validates containment only after extraction; local GNU tar blocked simple escape examples. |
| DSS-CAN-009 | partial | medium | medium | OpenSearch memory ingest has a separate unchecked 7z extraction path; local 7z blocked simple escape examples. |
| DSS-CAN-010 | valid | high | high | OpenSearch explicit `index` parameter overrides Gateway active-case injection for cross-case reads. |
| DSS-CAN-011 | valid | medium | high | OpenSearch status exposes all case index names and counts without active-case binding. |
| DSS-CAN-012 | valid | medium | high | OpenSearch enrichment direct-MCP scope fallback fails open when `SIFT_ENRICHMENT_SCOPE` is unset; limited to direct-backend or Gateway-bypass paths. |
| DSS-CAN-013 | valid | medium | high | `app.evidence_unseal` SECURITY DEFINER RPC omits explicit `PUBLIC` execute revoke after hardening migration. |
| DSS-CAN-014 | valid | high | high | Legacy portal token lifecycle lets examiner users mint or rotate broad `mcp:*` agent tokens. |
| DSS-CAN-015 | valid | high | high | Supabase-active authentication accepts legacy token fallback by default across REST and MCP paths. |
| DSS-CAN-016 | valid | medium | high | OpenCTI optional stack reuses credentials, disables OpenSearch security, and relies on mutable images. |
| DSS-CAN-017 | partial | medium | medium | OpenSearch generic 7z/zip evidence archive extraction lacks application-level containment checks; direct escape not reproduced locally. |
| DSS-CAN-018 | valid | medium | high | OpenCTI configuration permits non-local HTTP endpoints and can send credentials without TLS. |
| DSS-CAN-019 | partial | medium | medium | Public Wintools join flow can persist attacker-selected HTTP backend URLs after join-code exchange; join-code and manifest validation narrow exploitability. |
| DSS-CAN-020 | valid | high | high | Registered stdio MCP backends inherit the full Gateway environment including service secrets. |
| DSS-CAN-021 | valid | medium | high | RAG maintenance URL fetch validates redirects only after urllib has followed them. |
| DSS-CAN-022 | valid | medium | high | `run_command` systemd auto mode silently downgrades cgroup and network isolation when `systemd-run` is unavailable. |

## Compact JSONL

```jsonl
{"candidate_id":"DSS-CAN-001","verdict":"valid","severity":"high","confidence":"high"}
{"candidate_id":"DSS-CAN-002","verdict":"valid","severity":"critical","confidence":"high"}
{"candidate_id":"DSS-CAN-003","verdict":"valid","severity":"high","confidence":"medium"}
{"candidate_id":"DSS-CAN-004","verdict":"valid","severity":"high","confidence":"high"}
{"candidate_id":"DSS-CAN-005","verdict":"partial","severity":"medium","confidence":"medium"}
{"candidate_id":"DSS-CAN-006","verdict":"valid","severity":"high","confidence":"high"}
{"candidate_id":"DSS-CAN-007","verdict":"valid","severity":"high","confidence":"high"}
{"candidate_id":"DSS-CAN-008","verdict":"partial","severity":"medium","confidence":"medium"}
{"candidate_id":"DSS-CAN-009","verdict":"partial","severity":"medium","confidence":"medium"}
{"candidate_id":"DSS-CAN-010","verdict":"valid","severity":"high","confidence":"high"}
{"candidate_id":"DSS-CAN-011","verdict":"valid","severity":"medium","confidence":"high"}
{"candidate_id":"DSS-CAN-012","verdict":"valid","severity":"medium","confidence":"high"}
{"candidate_id":"DSS-CAN-013","verdict":"valid","severity":"medium","confidence":"high"}
{"candidate_id":"DSS-CAN-014","verdict":"valid","severity":"high","confidence":"high"}
{"candidate_id":"DSS-CAN-015","verdict":"valid","severity":"high","confidence":"high"}
{"candidate_id":"DSS-CAN-016","verdict":"valid","severity":"medium","confidence":"high"}
{"candidate_id":"DSS-CAN-017","verdict":"partial","severity":"medium","confidence":"medium"}
{"candidate_id":"DSS-CAN-018","verdict":"valid","severity":"medium","confidence":"high"}
{"candidate_id":"DSS-CAN-019","verdict":"partial","severity":"medium","confidence":"medium"}
{"candidate_id":"DSS-CAN-020","verdict":"valid","severity":"high","confidence":"high"}
{"candidate_id":"DSS-CAN-021","verdict":"valid","severity":"medium","confidence":"high"}
{"candidate_id":"DSS-CAN-022","verdict":"valid","severity":"medium","confidence":"high"}
```
