---
title: Request and Data Flow
source_commit: eadb92b
generated: 2026-06-27
verified_against: code+tests+config
invariants_checked: 4
status: draft
---

# Request and Data Flow

## 1. MCP Tool Call — Full Request Flow

```mermaid
sequenceDiagram
    participant Agent as AI Agent
    participant Auth as MCPAuthASGIApp
    participant Rate as IP Rate Limit
    participant Body as Body Size
    participant Origin as Origin Check
    participant Verifier as SiftTokenVerifier
    participant Supabase as Supabase
    participant Repo as SupabasePrincipalRepository
    participant Identity as Identity
    participant FastMCP as FastMCP
    participant Control as ControlPlaneRequiredMiddleware
    participant ToolAuth as ToolAuthorizationMiddleware
    participant AddonAuth as AddonAuthorityMiddleware
    participant CaseCtx as CaseContextMiddleware
    participant ActiveCase as ActiveCaseService
    participant Postgres as Postgres
    participant Audit as AuditEnvelopeMiddleware
    participant ProxyCase as ProxyActiveCaseMiddleware
    participant EvidenceGate as EvidenceGateMiddleware
    participant ResponseGuard as ResponseGuardMiddleware
    participant Core as Core Tool
    participant Proxy as FastMCPProxy
    participant Addon as Add-on subprocess
    participant Backends as OpenSearch/pgvector/OpenCTI/SQLite

    Agent->>Auth: POST /mcp (Bearer JWT)
    Auth->>Rate: check_rate_limit()
    Auth->>Body: Content-Length < 10MB
    Auth->>Origin: CSRF guard
    Auth->>Verifier: verify_token(JWT)
    Verifier->>Supabase: GET /auth/v1/user
    Supabase-->>Verifier: user.id
    Verifier->>Repo: lookup_by_auth_user_id()
    Repo->>Identity: PrincipalRecord
    Identity-->>Verifier: AccessToken(claims, scopes)

    FastMCP->>Control: on_call_tool
    Control->>Control: [Fail if no DSN]
    FastMCP->>ToolAuth: is_tool_allowed()
    ToolAuth->>ToolAuth: [Fail if not authorized]
    FastMCP->>AddonAuth: check required_scopes
    FastMCP->>CaseCtx: resolve active case
    CaseCtx->>ActiveCase: require_active_case()
    ActiveCase->>Postgres: app.active_case_state

    FastMCP->>Audit: reserve audit event
    Audit->>Postgres: INSERT INTO app.audit_events
    FastMCP->>ProxyCase: validate/inject case args
    FastMCP->>EvidenceGate: check_evidence_gate_db()
    EvidenceGate->>Postgres: app.evidence_gate_status

    FastMCP->>ResponseGuard: guard_tool_result()
    FastMCP->>FastMCP: [Tool Dispatch: core or proxied add-on]

    Core->>Core: call_core_tool()
    Proxy->>Addon: stdio
    Addon->>Backends: query

    ResponseGuard->>ResponseGuard: [Redact secrets, paths, cap output]
    Agent-->>Auth: ToolResult(audited, redacted, capped)
```

## 2. Portal Auth Flow

```mermaid
sequenceDiagram
    participant Browser as Browser
    participant Portal as PortalSessionMiddleware
    participant Supabase as Supabase

    Browser->>Portal: GET /portal (sift_portal_session cookie)
    Portal->>Portal: [Extract + HMAC verify cookie]
    Portal->>Supabase: resolve(access_token)
    Portal->>Supabase: refresh_grant() [Expired + refresh token]
    Supabase-->>Portal: [New tokens]
    Portal->>Portal: rotate cookie (preserve eiat)
    Portal->>Portal: request.state: principal + examiner + role
    Browser-->>Portal: response
```

## 3. Evidence Sealing Flow (Operator)

```mermaid
sequenceDiagram
    participant Operator as Operator
    participant Portal as Portal
    participant Auth as Auth
    participant Supabase as Supabase
    participant Postgres as Postgres
    participant FS as Local FS

    Operator->>Portal: POST /evidence/chain/seal (re-auth)
    Portal->>Auth: _supabase_reverify(password)
    Auth->>Supabase: password_grant()
    Supabase-->>Auth: OK
    Portal->>Postgres: evidence_seal(file_specs)
    Postgres->>Postgres: INSERT INTO evidence_objects
    Postgres->>Postgres: INSERT INTO evidence_versions
    Postgres->>Postgres: INSERT INTO evidence_custody_events (append-only)
    Postgres->>Postgres: UPDATE evidence_chain_heads
    Portal->>FS: chattr +i (immutable flag)
    Portal->>FS: apply and read back protected evidence posture
    Portal->>Postgres: commit version/manifest/head atomically
    Operator-->>Portal: {sealed, manifest_version}
```

## 4. Ingest Data Flow

```mermaid
flowchart TD
    A[Evidence Container E01/raw/dir] --> B[discover.py<br>enumerate artifacts, detect hosts]
    B --> C[tools.py<br>run ZimmermanTools RECmd, MFTECmd, etc.]
    C --> D[parse_*.py<br>parse CSV/EVTX/JSON output]
    D --> E[bulk.py<br>bulk index with provenance stamping sift.* fields]
    D --> F[hayabusa<br>post-ingest sigma detection]
    E --> G[OpenSearch<br>case-{key}-{type}-{host} indices]
    E --> H[Postgres<br>opensearch_ingest_provenance per-artifact audit]
    F --> G
```

## 5. Enrichment Data Flow

```mermaid
flowchart TD
    A[opensearch_enrich_intel] --> B[OpenSearch<br>extract unique IOCs from case-* indices]
    B --> C[gateway.call_tool cti_lookup_ioc, ioc]
    C --> D[OpenCTI API<br>get_indicator_context]
    D --> C
    C --> E[Return related actors, malware, techniques]
    E --> F[OpenSearch<br>update matched docs with threat_intel.* fields]
    F --> G[Postgres<br>record enrichment provenance]
```

## 6. Cross-Component Data Flow Diagram

```mermaid
flowchart LR
    subgraph Clients
        Portal[Operator Portal]
        AI[AI Agents]
    end

    subgraph Gateway
        Auth[Auth]
        Policy[Policy Chain]
        Aggregator[Backend Aggregator]
    end

    subgraph Core
        CoreTools[Core Tools sift-core]
        CaseDir[Case Dir / FS]
    end

    subgraph ProxyBackends
        OS[opensearch-mcp]
        RAG[forensic-rag-mcp]
        CTI[opencti-mcp]
        WT[windows-triage-mcp]
    end

    subgraph BackendData
        OpenSearch[(OpenSearch<br>search/ingest)]
        PgVector[(pgvector<br>knowledge search)]
        OpenCTI[(OpenCTI API<br>threat intel)]
        SQLite[(SQLite<br>baselines)]
    end

    subgraph JobQueue
        PG[(Postgres<br>Durable Job Queue)]
        Worker1[sift-job-worker<br>run_command sandbox]
        Worker2[sift-opensearch-worker@<br>OpenSearch ingest/enrich]
    end

    Portal -->|HTTPS| Gateway
    AI -->|MCP| Gateway
    Auth --> Policy
    Policy --> Aggregator

    Aggregator -->|Core| CoreTools
    CoreTools --> CaseDir

    Aggregator -->|Proxy stdio| OS
    Aggregator -->|Proxy stdio| RAG
    Aggregator -->|Proxy stdio| CTI
    Aggregator -->|Proxy stdio| WT

    OS --> OpenSearch
    RAG --> PgVector
    CTI --> OpenCTI
    WT --> SQLite

    Aggregator -->|Durable Jobs| PG
    PG --> Worker1
    PG --> Worker2
    Worker1 -->|sandboxed| CoreTools
    Worker2 --> OpenSearch
```

## 7. Key Data Flow Rules

- **Postgres is authoritative**; OpenSearch is derived and never authoritative
- **Evidence chain is append-only**; no UPDATE/DELETE on `custody_events`
- **Agent never has DB credentials** — all DB access mediated by Gateway
- **Tool results are always redacted** before reaching agent context
- **Ingest/enrich job `result_public` is always path-free**
- **Secret redaction happens BEFORE output cap** (prevents straddle)
- **Case index prefix check** prevents cross-case data access
- **Mutating tools are DENIED** if pre-dispatch audit write fails
- **Agent session TTL must be >= 48h** (AUT2-B0)
