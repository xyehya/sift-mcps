# IG-6 — OpenCTI shared-OpenSearch compatibility and capacity gate

**Status:** investigation complete; do not migrate yet
**Scope:** P1.7 / IG-6 design, repository inspection, and read-only test-VM inventory
**Evidence date:** 2026-07-10 (VM inventory at 17:29 UTC)
**Decision owner for implementation:** IG-7

## Decision

The shared-cluster target is viable in principle, but the current implementation is
**not eligible for migration**. The core cluster deliberately starts OpenSearch 3.5.0
with `DISABLE_SECURITY_PLUGIN=true`. Therefore it cannot authenticate an OpenCTI
service identity or enforce an `opencti*`-only role. Removing
`opencti-opensearch` before first making the core cluster security-enabled would
turn the case/OpenCTI boundary into network reachability only and violates P1.

IG-7 must first implement and prove a security-enabled core OpenSearch transition
(TLS, service identities, and migration of the existing core clients), then run the
shared-mode proof matrix below. It must not silently set
`ELASTICSEARCH__ENGINE_CHECK=false`: OpenCTI documents that this bypasses its
compatibility check and may have negative effects
([configuration](https://docs.opencti.io/latest/deployment/configuration/)).

OpenCTI stays an external, query-only reference backend. Its existing manifest
already makes it non-authoritative, `default_case_scoped: false`, and limits every
tool to `cti:read`; that contract is unchanged. `opencti*` must not be made
searchable through any case-search surface (P3/DLS is the separate decision).

## What exists today

### Repository topology

| Area | Observed state | Consequence |
|---|---|---|
| Core OpenSearch | `docker-compose.yml` pins OpenSearch 3.5.0 by digest, uses a 4 GiB Java heap, binds `9200` to loopback, and names the bridge network `sift-net`. The Security plugin is explicitly disabled. | The digest and loopback binding are good starting controls, but no OpenSearch role can enforce a prefix boundary. |
| OpenCTI stack | `docker-compose.opencti.yml` has its own `sift-opencti-net`, `sift-opencti-opensearch` volume, and 2 GiB OpenSearch heap. Platform, worker, MinIO, and connector images use mutable `latest` tags. | This is isolated today, not shared, and cannot provide a reproducible version-compatibility claim. |
| OpenCTI package | `opencti-mcp` declares `pycti>=6.0`; the committed lock resolves `pycti 7.260626.0`. `OpenCTIClient._enforce_version_compat` checks that pycti and server *majors* match once reachable. | The selected platform must be an explicitly pinned 7.x release, or the lock/package constraint must be changed in the same intentional update. |
| OpenSearch client | `opensearch_mcp.client.get_client` already reads an authenticated host/user/password config, but the installer helper writes a loopback HTTP configuration with certificate verification disabled. | IG-7 must inventory every core caller and migrate them to separate service identities, HTTPS, and verified CA material before enabling Security. |
| Gateway boundary | OpenCTI setup emits only `OPENCTI_URL=SIFT_OPENCTI_URL` and `OPENCTI_TOKEN=SIFT_OPENCTI_TOKEN` references. The add-on process receives no database credentials. | Preserve this flow; OpenSearch credentials belong only to the OpenCTI platform container, never in the MCP registration payload or add-on subprocess. |

The local code's pycti major check is useful only after a reachable server reports a
version. It is not a substitute for pinning the server image, its digest, pycti, and
the core OpenSearch image as one tested compatibility tuple.

### Read-only VM inventory

The test VM currently runs the core only; it is not an OpenCTI migration source.
No OpenCTI containers, `sift-opencti-net`, or OpenCTI data volume exists. The only
OpenSearch volume is the core `sift-mcps_opensearch-data` volume. Thus **there is no
OpenCTI data to migrate or retain on this VM**. That is a test-environment fact, not
permission to skip the data-retention check on another environment.

| Item | Observed value |
|---|---|
| VM capacity | 8 CPUs; 33.65 GB RAM total, 26.74 GB available at capture; 513.33 GB filesystem total, 400.74 GB free; load 0.15 / 0.08 / 0.02. |
| Core container | `sift-opensearch`, pinned 3.5.0 digest, healthy; 4.615 GiB resident (14.72% of the 31.34 GiB Docker-visible limit). No container CPU/memory hard limit is set. |
| Cluster | OpenSearch 3.5.0, green, one node, 51 active primary shards, no pending tasks; persistent `cluster.max_shards_per_node=3000`; `vm.max_map_count=1048576`. |
| Index state | 40 `case-*` indices, 5,660,211 documents, 611,778,335 store bytes, six aliases; eight non-case indices (97 documents); one system index. There are zero `opencti*` indices and aliases. |
| Mapping / plugins | Case mappings expose 1,014 top-level fields across the 40 indices. The installed plugin list includes `opensearch-security`, `opensearch-index-management`, and `opensearch-security-analytics`; the compose configuration, not missing software, disables Security. |
| Core health | `sift-gateway`, `sift-job-worker`, and both `sift-opensearch-worker@` units were active/running at capture. This is a baseline only; it is **not** an OpenCTI-outage proof. |

The observed capacity is enough for a controlled fresh shared-mode experiment, not a
production sizing approval. OpenCTI's current deployment guidance lists minimums of
8 GB for the platform and 8 GB for its OpenSearch dependency, plus Redis,
RabbitMQ, S3/MinIO, workers, and connectors
([overview](https://docs.opencti.io/latest/deployment/overview/)). The present 4 GiB
core heap and unlimited container memory must not be treated as an implicit OpenCTI
budget. Initial shared-mode deployment needs cgroup limits, monitored headroom, and a
soak test with the chosen connector set.

## Compatibility verdict and release tuple

OpenCTI's current documentation accepts OpenSearch `>=2.9`, so the core's 3.5.0
meets the published version floor. Its documentation also exposes
`ELASTICSEARCH__ENGINE_SELECTOR=opensearch`, preserves the `opencti` index prefix,
and keeps the engine compatibility check enabled by default
([configuration](https://docs.opencti.io/latest/deployment/configuration/)). This is
not yet a tested exact tuple because the repository's OpenCTI platform image is
`latest` and is absent from the VM.

IG-7's first commit must declare, lock, and test one tuple:

| Component | Required rule |
|---|---|
| Core OpenSearch | Preserve the tested 3.5.0 digest, or intentionally bump the version and digest in the same compatibility test. |
| OpenCTI platform and worker | Replace `latest` with one selected 7.x release and immutable image digests. Platform, worker, and any shipped connector versions must be explicitly compatible with that release. |
| pycti | Pin to the selected OpenCTI major, initially `>=7,<8` with the exact lock resolution recorded. Do not leave the current floor-only dependency as the deployment decision. |
| Search configuration | `ELASTICSEARCH__ENGINE_SELECTOR=opensearch`, `ELASTICSEARCH__ENGINE_CHECK=true`, `ELASTICSEARCH__INDEX_PREFIX=opencti`, one primary and zero replicas only after the capacity test below. |
| Plugins | Verify startup and representative ingestion with the core's Security, Index Management, and any OpenCTI-required ingest plugin configuration. If file indexing is enabled, OpenCTI documents that OpenSearch needs `ingest-attachment` ([file indexing](https://docs.opencti.io/latest/administration/file-indexing/)); leave it disabled unless that plugin is deliberately provisioned and tested. |

Before changing compose, start the selected pinned platform against a disposable
security-enabled test cluster and record all three values from the platform's
authenticated `about` response: OpenCTI version, `@opencti/platform` dependency
version, and the OpenSearch version. The release gate passes only if pycti and
OpenCTI majors agree, OpenCTI leaves `ENGINE_CHECK` on, and its actual startup and
one connector ingest succeed against OpenSearch 3.5.0.

## Security-enabled shared target

### Identity and authorization

Enable the core Security plugin with TLS before joining the networks. Use a distinct
OpenCTI platform identity; never reuse a core ingest, gateway, or administrator
credential. The password/certificate material is generated or obtained at deploy
time and stored in a root/service-readable secret file; it is never committed,
placed in an `env_refs` payload, printed, or passed to `opencti-mcp`.

The role must use OpenCTI's documented integration permissions with an index pattern
restricted to `opencti*`: `indices_all` on that pattern plus the documented narrow
cluster permissions for templates, pipelines, ISM, monitoring, scroll, and bulk
([OpenCTI rollover and integration permissions](https://docs.opencti.io/latest/deployment/advanced/rollover/)).
Do **not** replace this with a broad `*` index rule, `all_access`, `readall`, a
system-index action, or any Security REST API permission. OpenSearch roles apply
permissions to underlying actions, including bulk and multi-search operations, not
merely to HTTP routes
([permissions](https://docs.opensearch.org/latest/security/access-control/permissions/)).

The intended role shape is below. IG-7 should place it in the security bootstrap
mechanism selected for the core transition, not embed a password in compose.

```yaml
sift_opencti_platform:
  cluster_permissions:
    - cluster_composite_ops_ro
    - cluster_manage_index_templates
    - cluster:admin/ingest/pipeline/put
    - cluster:admin/opendistro/ism/policy/write
    - cluster:monitor/health
    - cluster:monitor/main
    - cluster:monitor/state
    - cluster:monitor/task/get
    - indices:admin/index_template/put
    - indices:data/read/scroll
    - indices:data/read/scroll/clear
    - indices:data/write/bulk
  index_permissions:
    - index_patterns: ["opencti*"]
      allowed_actions: ["indices_all"]
```

Only a bootstrap administrator may create the role and the `sift-opencti-platform`
identity. That bootstrap identity uses mutually authenticated TLS and is not mounted
into the OpenCTI stack. OpenSearch's own guidance recommends roles and role mappings
for regular users, reserving super-admin certificates for the security
configuration itself
([users and roles](https://docs.opensearch.org/latest/security/access-control/users-roles/)).

After bootstrap, mount the generated OpenSearch credential read-only into the
`opencti` application container and set `ELASTICSEARCH__URL` to the internal HTTPS
endpoint plus `ELASTICSEARCH__USERNAME` / `ELASTICSEARCH__PASSWORD`. Do not give
that credential to the worker or connector containers; they use the OpenCTI API
only. Give each existing SIFT OpenSearch client its own minimum role and CA-backed
configuration as part of the security-plugin transition.

### Network topology

Use stable names so that compose project names cannot alter the trust boundary:

```text
gateway process -- http://127.0.0.1:8080 --> OpenCTI platform
                                                |
                         sift-opencti-app-net --+-- Redis / RabbitMQ / MinIO / workers / connectors
                                                |
                         sift-core-net --------> sift-core-opensearch:9200 (HTTPS, OpenCTI role only)
```

Implementation contract:

1. Core compose owns a named bridge network `sift-core-net` and assigns the
   OpenSearch service an explicit `sift-core-opensearch` alias. It may retain the
   loopback-only host port for local core services, but it is HTTPS and requires
   authentication after the transition.
2. The OpenCTI compose declares `sift-core-net` as an external network. Attach only
   the `opencti` platform service to it. Redis, RabbitMQ, MinIO, workers, and
   connectors stay on `sift-opencti-app-net` and cannot address the core cluster.
3. Keep OpenCTI's API port loopback-bound (`127.0.0.1:8080`) for the host gateway;
   do not publish it to a LAN interface. No agent gets a raw OpenCTI or OpenSearch
   URL—agents use gateway-mediated `cti_*` tools only.
4. Remove the dedicated OpenCTI OpenSearch service and volume only in the shared
   compose variant, after the security and live gates pass. Preserve the legacy
   compose/volume until acceptance; never run both platform variants concurrently.

An `internal: true` OpenCTI application network is not appropriate for the shipped
external-feed connectors because they need controlled outbound Internet access. Keep
connector egress a separately constrained operational policy; network access to the
core cluster remains limited to the platform container above.

## IG-7 proof checklist

All commands below are templates for the later migration. They intentionally use
secret-variable names rather than values and must run only after the credentials are
loaded from the protected deployment secret source.

### 1. Static and compatibility gates

- `docker compose config` shows no `opencti-opensearch` service, port, or data
  volume in shared mode; `opencti` alone is attached to `sift-core-net`.
- Images are immutable digests, not `latest`; the platform, worker, connector, pycti,
  and OpenSearch versions are captured in the proof record.
- `ELASTICSEARCH__ENGINE_CHECK` remains true and the selected platform starts with
  `ELASTICSEARCH__ENGINE_SELECTOR=opensearch`.
- Run the focused OpenCTI contract/surface tests, the updated compose/installer
  tests, and security-plugin client-auth tests before VM deploy.

### 2. OpenSearch least-privilege proof

Run this on a disposable shared-mode test setup, with a generated test index name
under `opencti*`; do not use a case index or delete existing VM data.

```bash
# Positive: authenticated OpenCTI identity can use its own prefix.
curl --fail-with-body --user "$SIFT_OPENCTI_OS_USER:$SIFT_OPENCTI_OS_PASSWORD" \
  "https://sift-core-opensearch:9200/opencti-permission-probe/_search"

# Negative: every command must return HTTP 403 and no case document/body.
for target in \
  '/case-*/_search' \
  '/_cat/indices/case-*?format=json' \
  '/_plugins/_security/api/roles' \
  '/case-permission-probe/_doc/1'; do
  status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --user "$SIFT_OPENCTI_OS_USER:$SIFT_OPENCTI_OS_PASSWORD" \
    "https://sift-core-opensearch:9200${target}")"
  test "$status" = 403
done
```

Use the deployment's trusted CA option with every HTTPS call; the abbreviated
template omits its path so it cannot encourage a copied insecure `-k` invocation.
Add a positive template/pipeline/rollover test that exercises the exact OpenCTI
startup operations. OpenCTI documents `opencti*` integration permissions and
rollover aliases, so checking only `_search` is insufficient.

### 3. Capacity and functional acceptance

1. Capture baseline `/_cluster/health`, `/_cat/indices`, `/_stats`, aliases,
   mappings, plugin list, OpenSearch heap, Docker memory/CPU, and disk free space.
   Store summaries by prefix; do not put case identifiers or raw evidence paths in
   the proof record.
2. Start one pinned platform, two workers, and the selected shipped connector set.
   Complete at least one connector ingest, then record `opencti*` count, store size,
   aliases, mappings, primary shards, cluster health, rejection counts, and peak
   memory/CPU during a 30-minute soak.
3. Require green cluster health, zero OpenSearch OOM/restart events, no sustained
   memory pressure or disk-watermark events, and headroom agreed from the measured
   peak before selecting the final heap/cgroup limits. The platform may use
   one-shard/zero-replica settings only after this measurement.
4. Query the authenticated OpenCTI `about` endpoint, verify the version tuple, then
   deploy/restart the gateway and run `cti_get_health` plus one representative
   `cti_lookup_ioc` through the agent-facing gateway surface. Confirm results remain
   reference-only and have no case-authoritative effect.

### 4. Outage isolation

With OpenCTI healthy, first record a successful case-scoped OpenSearch/gateway
operation. Stop only the OpenCTI platform and worker containers. Then require all of
the following before restoration:

- `sift-gateway`, `sift-job-worker`, and both OpenSearch workers stay active.
- gateway health, tools/list, and the recorded core case operation still succeed;
  core OpenSearch stays green;
- OpenCTI's agent-facing health/tool call fails safely within its configured bounded
  timeout and does not make case tools fail; and
- after restarting OpenCTI, `cti_get_health` and the representative lookup recover.

This VM has not run this experiment. Its active core services are a baseline, not a
substitute for the required failure-isolation proof.

## Data migration and rollback decision

The current testing VM has no legacy OpenCTI container or volume, so its first shared
mode test is an empty-source deployment and should explicitly record **"data migration
not applicable: no source OpenCTI data observed"**. Do not manufacture or remove
data merely to exercise IG-6.

For any environment with retained OpenCTI data, migration is mandatory and must be
reversible:

1. Inventory legacy `opencti*` indices, aliases, mappings, document counts, store
   bytes, and exact source/target OpenSearch versions.
2. Take a verified snapshot or export using a compatible repository, preserving the
   source volume and legacy compose untouched. OpenCTI's index guide lists the
   rollover aliases and identifies high-growth families such as history,
   observables, and relationships
   ([rollover guidance](https://docs.opencti.io/latest/deployment/advanced/rollover/)).
3. Restore/reindex to the security-enabled target with the restricted identity,
   compare every captured count/mapping/alias, and run OpenCTI consistency plus
   connector and gateway tests.
4. Retain the legacy compose file, volume, and rollback instructions until live
   acceptance. Rollback means stop shared OpenCTI, bring up the legacy dedicated
   search variant, restore its gateway environment reference, and re-run the
   agent-facing health/lookup and core-health checks. It never deletes the core
   OpenSearch volume or `/cases`.

## Security review

CodeGuard v1.3.1 guidance was applied to this design: hardcoded-credential,
container/IaC, input-validation, authorization, and MCP-boundary rules. **Verdict:
PASS for the investigation design; IG-7 is blocked on the explicit security-plugin
transition and its negative authorization proof.** The report contains no secret
values, prohibits raw agent access and database credentials in add-ons, uses
deny-by-default prefix authorization, retains a rollback path, and requires TLS with
certificate verification. Any implementation that disables TLS verification,
retains `DISABLE_SECURITY_PLUGIN=true`, grants `*`/system-index access, or publishes
OpenCTI/OpenSearch outside loopback fails this design.
