# Validation — Cluster EGRESS-MISC

> Validator agent: sec-egress (Opus 4.8, xhigh). Read-only. Validates the restored
> Codex assessment against **current HEAD**, not the stale scan base `b995491` (≈183
> commits old; directive line numbers were re-located). No source code was modified —
> this file is the only output.
>
> Skill run: `codeguard-security:codeguard` (secure-coding lens applied per candidate —
> SSRF allowlist-vs-resolved-IP / DNS-rebinding / redirect-following; SQL SECURITY
> DEFINER + PUBLIC EXECUTE default; secret reuse; plaintext credential transport).
>
> Cluster verdict: **PASS-WITH-FIXES** — 1 ALREADY-FIXED (013 revoke landed; one
> residual: no fail-on-revert test), 4 STILL-VALID but all **defense-in-depth / low
> live severity** (005/021 are operator-CLI-only with a fixed allowlist, not
> agent-reachable; 016/018 are the **non-live** OpenCTI optional stack).

## Summary table

| Candidate | Codex verdict | **Current status** | Current severity | Confidence | Already-fixed-by | Fix effort |
|---|---|---|---|---|---|---|
| DSS-CAN-005 | partial / med | STILL-VALID (defense-in-depth) | **Low** (live) / Med (code) | high | — | S |
| DSS-CAN-021 | valid / med | STILL-VALID (defense-in-depth) | **Low** (live) / Med (code) | high | — | S (shared w/ 005) |
| DSS-CAN-013 | valid / med | **ALREADY-FIXED** (revoke) + residual: no hardening TEST | Low | high | `202606242200_revoke_public_execute_secdef.sql` (05e9782) | S (test only) |
| DSS-CAN-016 | valid / med | STILL-VALID (non-live optional stack) | **Low** (not deployed) / Med (code) | high | — | M |
| DSS-CAN-018 | valid / med | STILL-VALID (non-live optional stack) | **Low** (not deployed) / Med (code) | high | — | S |

**Counts:** ALREADY-FIXED 1 (013, revoke landed — but its proposed hardening *test* is still absent) · STILL-VALID 4 · FALSE-POSITIVE 0. All four STILL-VALID are low live severity. No P0/P1-live items in this cluster.

---

## DSS-CAN-005 — RAG source fetch validates hostname string, never resolved IP (SSRF / DNS-rebinding)

**Codex claim (verbatim intent):** RAG source fetching blocks IP literals + requires fixed allowlisted hostnames, but never RESOLVES those hostnames to reject private/loopback/link-local/reserved/rebound addresses before `urlopen`. A DNS/proxy attacker, a compromised allowed host, or future allowlist expansion can make an allowed hostname resolve to an internal address.

**Current code located at:** `packages/forensic-rag-mcp/src/rag_mcp/sources.py:329-353` (`_validate_url_host`), enforced from `fetch_url:434-526` and `_fetch_url_once:389-431` (codex cited `329-353` on `b995491`).

**Drift since scan:** `git log --oneline b995491..HEAD -- packages/forensic-rag-mcp/src/rag_mcp/sources.py` → **empty. No drift.** The file is byte-identical to the scan base; the claim stands on current source.

**CURRENT STATUS:** STILL-VALID (genuine CWE-918 defense-in-depth gap) — but **low live severity** (see reachability).

**Evidence (current source):**
```python
# sources.py:329-353
def _validate_url_host(url: str) -> None:
    parsed = urlparse(url)
    if _is_ip_literal(parsed.hostname or ""):           # blocks 127.0.0.1, octal, etc.
        raise ValueError(f"IP literal URLs not allowed: {parsed.hostname}")
    if parsed.hostname not in ALLOWED_URL_HOSTS:        # string allowlist ONLY
        raise ValueError(f"URL host not allowed: {parsed.hostname}")
    if HTTPS_ONLY and parsed.scheme != "https":
        raise ValueError(...)
# never calls socket.getaddrinfo(); never classifies the resolved IP as
# private/loopback/link-local/reserved before urlopen connects.
```
Reachability / data-flow:
- **The fetch path is NOT an agent-facing MCP tool.** `server.py` (`RAGServer`) exposes only `@mcp.tool(readOnlyHint=True)` knowledge-query tools (`kb_*`). `fetch_url` is reached only from `refresh.py` (`main()` argparse CLI → `refresh()` → `get_latest_*` / `parse_*` / `clone_repo`), i.e. `python -m rag_mcp.refresh`, an **operator-run offline corpus update**.
- **URLs are not caller-controlled.** Every `fetch_url` call site (lines 532/545/557/814/1094/1136/1978/2081) passes a URL built from the hardcoded `SOURCES` registry / `ALLOWED_URL_HOSTS` (`api.github.com`, `raw.githubusercontent.com`, `github.com`, `www.cisa.gov`, `d3fend.mitre.org`, `atlas.mitre.org`). There is no path where an agent or remote user supplies an arbitrary URL.

**Exploit preconditions:** An attacker who controls **DNS resolution / an egress proxy on the SIFT host during a refresh run**, OR who **compromises one of the six allowlisted upstreams** (GitHub/CISA/MITRE) to make it resolve to / redirect to an internal address. No agent, case, or token is involved — the trigger is the operator running the refresh job.

**Blast radius if valid:** Gateway-host-originated request to an internal address (blind SSRF: probe internal services / metadata endpoints). Bounded by the 60 MB read cap, 30 s timeout, and HTTPS-only default; no credentials beyond an optional `GITHUB_TOKEN` (only attached when host is in the allowlist). The body is only returned to the caller if the final host is allowlisted.

**Project-invariant check:** Lives entirely in the `kb` add-on's offline maintenance path; touches none of the live agent surface, the evidence gate, the DB-authority manifest, or the MCP surfacing layers. The RAG is knowledge-only (NW4 decoupling) — this finding does not change that. No invariant interaction; fix is local to the add-on.

**FIX APPROACH (secure-by-design, preserves invariants, NOT monkey-patching):**
- **Root cause:** validation trusts the *hostname string*; it never resolves the host and classifies the destination IP, and (see 021) lets `urllib` follow redirects to an unvalidated hop.
- **Proposed change (shared with 021 — design ONE hardened fetch):** in `sources.py`, add a single `_resolve_and_classify(host) -> list[ip]` helper that `getaddrinfo`s the host and rejects any address where `ipaddress.ip_address(a).is_private/is_loopback/is_link_local/is_reserved/is_multicast/is_unspecified`. Call it inside `_validate_url_host`. Then **pin the connection to the validated IP** (resolve once, connect to that IP with `Host:` header preserved) so the address checked == the address connected — closing the TOCTOU/rebinding window. Apply the same `_validate_url_host` (host allowlist + resolved-IP classification) on **every** redirect hop (see 021 fix).
- **Why it preserves identity/invariants:** purely additive hardening inside the existing add-on validator; the fixed allowlist and HTTPS-only default stay; no gateway/policy-boundary change; no new surface.
- **Test strategy (fail-on-revert unit test):** `tests/test_sources_ssrf.py` monkeypatching `socket.getaddrinfo` so an allowlisted host resolves to `169.254.169.254` / `127.0.0.1` / `10.x` and asserting `fetch_url` returns `None` (validation raises). A second test asserts a public IP passes. This fails the moment the resolved-IP check is removed. No live deploy-and-prove needed (offline CLI, no behavioral live surface).
- **Alternatives rejected:** (a) "drop the allowlist entirely / block all private ranges only" — keeps rebinding open via an allowlisted name; (b) routing the refresh through the gateway egress policy — over-engineering for an offline operator CLI that the gateway never invokes.

**Cross-cluster dependency:** Conceptually parallel to **DSS-CAN-004 / 019 (cluster BACKENDS)** which need a *gateway-runtime* shared egress policy. This (005/021) is a **separate, simpler offline path** — do NOT fold it into the gateway egress policy; a self-contained resolve-and-pin helper in `sources.py` is correct. Same hardened-fetch fix covers 005 + 021.

**Open question for operator:** none — accept as low-priority hardening.

---

## DSS-CAN-021 — RAG fetch follows redirects before validating the final hop

**Codex claim (verbatim intent):** RAG validates the ORIGINAL url, then `urlopen` follows redirects to the target BEFORE `response.geturl()` is inspected → redirect-based SSRF.

**Current code located at:** `packages/forensic-rag-mcp/src/rag_mcp/sources.py:389-431` (`_fetch_url_once`), specifically `396-401` (codex cited `329-353`, same function family, on `b995491`).

**Drift since scan:** none (same `git log` empty as 005).

**CURRENT STATUS:** STILL-VALID (same root cause / same low live severity as 005).

**Evidence (current source):**
```python
# sources.py:396-401
with urlopen(req, timeout=30) as response:          # urllib auto-follows 3xx here
    final_url = response.geturl()                   # ...inspected only AFTER the follow
    if final_url != url:
        logger.debug(f"Redirect detected: {url} -> {final_url}")
        _validate_url_host(final_url)               # host-string check, post-connect
```
`urllib.request`'s default `HTTPRedirectHandler` transparently follows 30x to the redirect target; by the time `urlopen` returns, the GET to the redirected host has already been issued and the body is buffered for reading. The post-hoc `_validate_url_host(final_url)` rejects the *body* (raises → `fetch_url` returns `None`) when the final host is not allowlisted, but the **request to the internal host already happened** (blind SSRF), and a redirect to an *allowlisted* name that resolves internally (rebinding) passes entirely.

**Reachability / preconditions / blast radius:** identical to 005 — operator-run refresh CLI, fixed allowlist, no caller-controlled URL. Adds: requires a **compromised/malicious allowlisted upstream** to emit the redirect, or a redirect chain whose intermediate hop is the internal target. Blind-SSRF only for non-allowlisted finals; full SSRF only for allowlisted-name-resolving-internal.

**Project-invariant check:** same as 005 — add-on offline path, no live-surface interaction.

**FIX APPROACH:** **Shared with 005 — one hardened fetch.** Disable automatic redirects (`urllib.request.build_opener` with a no-follow `HTTPRedirectHandler` subclass whose `redirect_request` returns `None`, or handle 30x manually), then for each `Location` hop call `_validate_url_host` (host allowlist **+ resolved-IP classification from 005**) *before* issuing the next request, bounded by a small max-redirect count. This makes "validate then connect" hold on every hop.
- **Test (fail-on-revert):** in `test_sources_ssrf.py`, a mock HTTP handler returning `301 Location: http://127.0.0.1/` from an allowlisted host; assert `fetch_url` never connects to the redirect target (the mock records zero internal hits) and returns `None`. Fails if auto-redirect is reintroduced.
- **Alternatives rejected:** keeping `response.geturl()` post-check only — it is structurally too late (request already sent); a WAF/proxy egress filter — out of scope for an offline CLI.

**Cross-cluster dependency:** bundled with DSS-CAN-005 (same function, one PR). Parallel-but-separate from BACKENDS 004/019 (gateway egress).

**Open question for operator:** none.

---

## DSS-CAN-013 — `app.evidence_unseal` SECURITY DEFINER without explicit PUBLIC-execute revoke

**Codex claim (verbatim intent):** `202606160100_evidence_unseal.sql` creates `app.evidence_unseal` as SECURITY DEFINER + grants execute to `service_role` but does NOT explicitly revoke the PostgreSQL default EXECUTE from PUBLIC; a role that gains `USAGE` on schema `app` could call it. Proposed: idempotent revoke-from-PUBLIC + grant-only-service_role, plus a hardening test for ALL app SECURITY DEFINER functions.

**Current code located at:** `supabase/migrations/202606160100_evidence_unseal.sql:59-151` (function + grant). The closing fix is `supabase/migrations/202606242200_revoke_public_execute_secdef.sql:1-53` (codex cited `59-69` on `b995491`).

**Drift since scan:** `git log b995491..HEAD -- supabase/migrations/202606160100_evidence_unseal.sql` → empty (the unseal migration is unchanged). **But a NEW migration exists:** `202606242200_revoke_public_execute_secdef.sql` (commit `05e9782` "feat(audit): C2 durable revoke of PUBLIC execute on all app SECDEF functions"; later `ae745cd` G5-guards the `service_role` grant).

**CURRENT STATUS:** **ALREADY-FIXED** (the residual PUBLIC execute on `evidence_unseal` is revoked) **with one residual gap: the proposed hardening TEST is still absent.**

**Evidence (current source):**
```sql
-- 202606160100_evidence_unseal.sql:144-151  (creates the gap — grants service_role,
-- never revokes PUBLIC; this migration predates the fn but POST-DATES 141400's loop)
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'service_role') then
    grant execute on function app.evidence_unseal(uuid, text, uuid, uuid, uuid)
      to service_role;
  end if;
end $$;

-- 202606242200_revoke_public_execute_secdef.sql:30-50  (CLOSES it — data-driven loop
-- over EVERY app SECDEF fn, so it now includes evidence_unseal)
for r in
  select p.proname, pg_get_function_identity_arguments(p.oid) as fn_args
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'app' and p.prosecdef = true
loop
  execute 'revoke execute on function ' || fn_sig || ' from public';
  if exists (select 1 from pg_roles where rolname = 'service_role') then
    execute 'grant execute on function ' || fn_sig || ' to service_role';
  end if;
end loop;
```
**Migration-ordering proof (this is exactly the recalled invariant):** the *first* sweep `202606141400_harden_append_only_chains.sql:64-82` (F4) revoked PUBLIC on every SECDEF fn **existing on 2026-06-14**. `evidence_unseal` was added later (`202606160100`, 2026-06-16) and so **slipped through** the 141400 sweep and carried residual PUBLIC EXECUTE from 06-16 until the 06-24 sweep. `202606242200` re-runs the data-driven loop and now covers it. After all migrations apply in timestamp order, `evidence_unseal` has **no PUBLIC execute** → candidate closed.

**Reachability / preconditions:** Codex itself notes exploitability was already narrow — `app` is kept out of PostgREST-exposed schemas, so reaching the residual grant required a role first obtaining `USAGE on schema app`. The agent backend has **no DB creds by design**, so the agent path can never call it. With the revoke landed, even a role granted schema USAGE no longer inherits EXECUTE.

**Blast radius if valid (pre-fix):** a role with schema USAGE could invoke the SECDEF unseal RPC and flip evidence `sealed→detected/unsealed` (which, by design, drops the case aggregate to `unsealed` and BLOCKS the agent gate) — an integrity/availability hit on custody state, not data exfil. Now mitigated.

**Project-invariant check:** This *is* the recalled DB SECDEF hardening invariant ([[reference_schema_usage_secdef_exposure]]): granting a role USAGE on `app` silently re-exposes post-141400 SECDEF fns with residual PUBLIC EXECUTE; the fix is revoke-from-PUBLIC (preserve `service_role`) in the same migration. The 242200 migration is the durable, data-driven realization. Both sweeps correctly **preserve `service_role`** and G5-guard it for non-Supabase Postgres.

**FIX APPROACH (residual only — the revoke is done; the *test* is the gap):**
- **Root cause of the residual:** there is **no automated guard** asserting the invariant. Confirmed: `rg "proacl|has_function_privilege|prosecdef" -g 'test_*.py'` returns **zero** test hits (only the two migrations match `prosecdef`). So the protection is "remember to re-run the sweep" — the *exact* failure mode that let `evidence_unseal` slip past 141400. The next SECDEF fn added in a future migration after 242200 will silently re-acquire PUBLIC EXECUTE with nothing to catch it.
- **Proposed change (where it must land):** add a DB-backed hardening test (e.g. `packages/sift-gateway/tests/test_secdef_no_public_execute.py`, importskip-gated on a DSN like the other DB tests) that queries, for **every** `pg_proc` where `pronamespace = 'app'::regnamespace AND prosecdef`, that `has_function_privilege('public', p.oid, 'EXECUTE')` is **false**. Assert the set of violators is empty; on failure, print the offending signatures. This is the "hardening test for ALL app SECURITY DEFINER functions" Codex's proposed fix called for.
- **Why it preserves invariants:** read-only assertion over `pg_catalog`; no schema change; codifies the existing invariant so the recurrence (a new SECDEF fn shipping with default PUBLIC EXECUTE) **fails CI** instead of shipping inert. It is the fail-on-revert guard the project's surfacing/conformance philosophy demands.
- **Test strategy:** the test *is* the guard; fail-on-revert is proven by temporarily creating a SECDEF fn without the revoke in a scratch DB and observing the test go red. Optional belt-and-suspenders: have the test additionally `service_role` is still granted (so a future over-broad "revoke from all" can't break the legitimate path).
- **Alternatives rejected:** (a) "default-revoke in a shared migration template / event trigger" — heavier, and an event trigger that auto-revokes could surprise future authors; a CI test is the least-surprising guard. (b) Re-running 242200 as the last migration forever — order-fragile, the original failure mode.

**Cross-cluster dependency:** none for the revoke. The hardening test conceptually belongs with the DB-hardening test family (`202606141200`/`141400` lineage) and is independent of the AUTH/BACKENDS clusters.

**Open question for operator:** Approve adding the SECDEF-no-PUBLIC-execute CI test (the only residual). Low effort; closes the recurrence class permanently.

---

## DSS-CAN-016 — OpenCTI optional compose stack: secret reuse, disabled datastore security, mutable images

**Codex claim (verbatim intent):** the optional OpenCTI compose stack reuses `OPENCTI_ADMIN_TOKEN` across OpenCTI admin/API, RabbitMQ, MinIO, worker, connectors; uses mutable `latest` images; disables the OpenSearch security plugin inside the OpenCTI network.

**Current code located at:** `docker-compose.opencti.yml:19-38, 67, 84, 105-106, 123, 129, 157, 75/93/151` (codex cited `19-38` on `b995491`).

**Drift since scan:** `git log b995491..HEAD -- docker-compose.opencti.yml` → empty. No drift; claim stands verbatim.

**CURRENT STATUS:** STILL-VALID (real compose-hardening defects) — **but Low live severity: this stack is NOT deployed.** Per project invariant, **opencti-mcp is not integrated with the live gateway** (only `wintriage`/`opensearch`/`kb` run). This file is brought up only by an operator who opts into the optional add-on.

**Evidence (current source):**
```yaml
# secret reuse — one value drives 6 distinct credentials:
rabbitmq:  RABBITMQ_DEFAULT_PASS=${OPENCTI_ADMIN_TOKEN}      # :67
minio:     MINIO_ROOT_PASSWORD=${OPENCTI_ADMIN_TOKEN}       # :84
opencti:   APP__ADMIN__PASSWORD=${OPENCTI_ADMIN_TOKEN}      # :105
           APP__ADMIN__TOKEN=${OPENCTI_ADMIN_TOKEN}         # :106  (admin pw == API token)
           RABBITMQ__PASSWORD / MINIO__SECRET_KEY=${OPENCTI_ADMIN_TOKEN}  # :123,:129
worker:    OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}             # :157
# mutable tags:
minio/minio:latest (:75), opencti/platform:latest (:93), opencti/worker:latest (:151)
#   (opensearch:3.5.0, redis:7.4, rabbitmq:4.0-management ARE pinned — partial)
# datastore security disabled:
opencti-opensearch:  - DISABLE_SECURITY_PLUGIN=true          # :21
```

**Reachability / preconditions:** Requires the operator to deploy `docker compose -f docker-compose.opencti.yml up`. Then a compromise of **any** container in `sift-opencti-net` (or a poisoned `latest` pull) yields the single shared secret → lateral control of OpenCTI admin + RabbitMQ + MinIO. Mitigating context already present: the only published port is `127.0.0.1:8080` (opencti platform, loopback-bound); the OpenSearch datastore publishes **no** host port and lives on a dedicated `opencti-net` bridge, so `DISABLE_SECURITY_PLUGIN` exposes it only to siblings on that network, not the host/LAN.

**Blast radius if valid:** within the optional OpenCTI network only; isolated by design from the native SIFT forensic OpenSearch cluster (the file comment and `ELASTICSEARCH__INDEX_PREFIX=opencti` enforce datastore separation). No path into the live gateway, evidence, or DB.

**Project-invariant check:** Does not touch the live gateway/policy boundary, evidence gate, DB-authority, or surfacing layers. It is squarely the "optional/non-live add-on" surface the invariants quarantine. Severity is weighted down accordingly (real code defect, near-zero live blast radius today).

**FIX APPROACH (secure-by-design):**
- **Root cause:** convenience single-secret bootstrap + floating tags + datastore-auth-off for a single-node dev datastore.
- **Proposed change:** (1) split per-component secrets — distinct env vars `OPENCTI_ADMIN_TOKEN`, `OPENCTI_ADMIN_PASSWORD`, `RABBITMQ_PASSWORD`, `MINIO_SECRET_KEY`, each operator-supplied (document in `scripts/setup-addon.sh`); (2) pin `minio`/`opencti`/`worker` to a specific digest (`@sha256:…`) like the already-pinned services; (3) if the datastore network is ever broadened beyond the single-node bridge, enable the OpenSearch security plugin with a generated password — for the current loopback/bridge-only posture, document the residual rather than force auth on a throwaway single node.
- **Why it preserves invariants:** changes are confined to the optional compose file + its setup script; no change to the live gateway or the Backend Contract. Keeps the existing datastore isolation.
- **Test strategy:** a lightweight CI lint (e.g. a `pytest`/`yamllint` rule or a grep-based check in the add-on test set) asserting `docker-compose.opencti.yml` contains no `:latest` tag and that `${OPENCTI_ADMIN_TOKEN}` is not assigned to more than one credential field — fail-on-revert. No live deploy needed (not a runtime behavior of the live gateway).
- **Alternatives rejected:** Docker/Compose secrets files — heavier for an optional dev add-on; acceptable as a follow-up but per-var split is the minimum that breaks the single-point-of-failure.

**Cross-cluster dependency:** Pairs with **DSS-CAN-018** (same non-live OpenCTI stack — the MCP-client side). Treat both as one "OpenCTI optional-stack hardening" follow-up, gated behind "if/when OpenCTI is promoted to a live backend."

**Open question for operator:** Confirm OpenCTI remains non-live for the foreseeable term. If it is ever promoted to a live backend, 016+018 become **Medium** and should be fixed before integration.

---

## DSS-CAN-018 — OpenCTI MCP accepts remote `http://` with only a warning, then sends token in plaintext

**Codex claim (verbatim intent):** OpenCTI MCP accepts non-local `http://` URLs with only warnings, then builds the API client with the API token over plaintext transport.

**Current code located at:** `packages/opencti-mcp/src/opencti_mcp/config.py:326-380` (`_validate_url`), warn-only branch at `374-378`; token attached in `Config.load:181-196` / used downstream by the API client (codex cited `144-183` on `b995491`).

**Drift since scan:** `git log b995491..HEAD -- packages/opencti-mcp/src/opencti_mcp/config.py` → empty. No drift; claim stands.

**CURRENT STATUS:** STILL-VALID (real plaintext-credential gap) — **Low live severity (non-live optional stack;** the default `OPENCTI_URL` is `http://localhost:8080`, which is safe; the risk only materializes if an operator points it at a *remote* `http://`).

**Evidence (current source):**
```python
# config.py:349-380  — non-local http is permitted with a log warning, not rejected:
if parsed.scheme == "http":
    host = parsed.hostname or ""
    is_local = host in ("localhost", "127.0.0.1", "::1") or host.startswith((...private ranges...))
    if not is_local:
        logger.warning(
            "Using HTTP for non-local OpenCTI - credentials sent in plaintext", ...
        )
return url                                   # <-- returns OK; no raise
# Config.load:145  url = os.getenv("OPENCTI_URL", "http://localhost:8080")
# Config.load:181-196  passes SecretStr(token) into Config; the OpenCTIApiClient
#   later sends that token as a bearer over whatever scheme was accepted.
```
Note `ssl_verify` defaults `True` (`config.py:169-173`), so for `https` the cert is validated — good. But for a remote `http://` target the warning does not stop the token being sent in cleartext.

**Reachability / preconditions:** Operator (or env influence) sets `OPENCTI_URL=http://<remote-host>:8080`. The default is loopback, so out-of-the-box config is safe. Requires the optional opencti-mcp backend to be configured at all (not live today). A network MITM on that remote path can then capture the API token.

**Blast radius if valid:** disclosure of the OpenCTI API token to a network observer → full OpenCTI API access (read/write threat-intel). Confined to the optional OpenCTI deployment; no live-gateway/DB/evidence exposure.

**Project-invariant check:** Add-on config layer, not the live gateway policy boundary; opencti-mcp not integrated. No interaction with evidence gate, DB-authority, or surfacing layers. Severity weighted down for non-live.

**FIX APPROACH (secure-by-design):**
- **Root cause:** `_validate_url` warns-but-permits remote plaintext; "warn and continue" is not a control.
- **Proposed change:** in `_validate_url`, **reject** `http://` for any non-loopback host (`raise ConfigurationError`), gated by an explicit opt-out env (`OPENCTI_ALLOW_INSECURE_HTTP=1`) for dev-against-remote scenarios; for remote `https`, keep `ssl_verify=True` and refuse to silently disable it. Loopback http stays allowed (the dev default).
- **Why it preserves invariants:** local-first/secure-by-default; matches the secrets/transport CodeGuard rule (no plaintext credential transport without explicit, logged operator override); confined to the add-on config. Mirrors the RAG `RAG_ALLOW_HTTP` opt-out pattern already used in this repo (`sources.py:604`) for consistency.
- **Test strategy (fail-on-revert):** `tests/test_config_url.py` — `_validate_url("http://198.51.100.10:8080")` raises `ConfigurationError`; with `OPENCTI_ALLOW_INSECURE_HTTP=1` it passes; `http://localhost:8080` always passes; `https://remote` passes with verify on. Fails if the warn-only behavior is reintroduced.
- **Alternatives rejected:** auto-upgrade http→https — silently surprising and may break a deliberate dev setup; warn-only (status quo) — not a control.

**Cross-cluster dependency:** Pairs with **DSS-CAN-016** (same OpenCTI optional stack — server side vs MCP-client side). One "OpenCTI optional-stack hardening" follow-up.

**Open question for operator:** same as 016 — confirm OpenCTI stays non-live; if promoted, fix 016+018 first. Decide whether to require the `OPENCTI_ALLOW_INSECURE_HTTP` opt-out or hard-forbid non-loopback http entirely.

---

## Cluster-level notes for the orchestrator

- **No P0/P1-live findings in EGRESS-MISC.** Every STILL-VALID item is either operator-CLI-only with a fixed allowlist (005/021) or part of the **non-live** OpenCTI optional stack (016/018). 013's exploitable residual is already closed by a landed migration.
- **Single highest-priority fix:** add the **SECDEF-no-PUBLIC-execute CI hardening test** (013 residual). It is the only finding that guards a *live* security invariant (evidence custody) and it permanently closes the recurrence class that let `evidence_unseal` slip past the 141400 sweep. Low effort, high durability value.
- **Bundling:** 005+021 = one hardened-fetch PR in `sources.py` (resolve-and-pin + no-auto-redirect). 016+018 = one OpenCTI optional-stack hardening PR, gated behind any decision to promote OpenCTI to a live backend.
- **Cross-cluster:** 005/021 are conceptually adjacent to BACKENDS DSS-CAN-004/019 (SSRF/egress) but must NOT be merged into the gateway egress policy — they live on an offline add-on CLI the gateway never calls. Flagged for sec-backends awareness only.
