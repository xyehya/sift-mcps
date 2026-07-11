# OpenCTI shared OpenSearch trust boundary

## Decision

SIFT supports OpenCTI 7.260710.0 with pycti 7.260710.0 on the secured core
OpenSearch 3.5.0 cluster. Images are digest-pinned. This is a fresh-deployment
contract; migration of old OpenCTI indices is not supported or required.

OpenCTI is an operator-installed, trusted external component. It is non-core
because of its resource footprint and independent availability lifecycle, not
because its publisher is treated as malicious. Agents never connect directly
to OpenCTI or OpenSearch.

## Enforced boundaries

- The OpenCTI platform alone joins the core Docker network. Redis, RabbitMQ,
  MinIO, and workers remain on an internal OpenCTI-only network.
- OpenCTI and OpenSearch publish loopback ports only. TLS CA and hostname
  verification remain enabled for the platform-to-OpenSearch connection.
- The OpenSearch platform identity has `indices_all` only for `opencti*`.
  Direct create, read, write, update, bulk, and delete operations against
  `case-*` must return 401/403 in acceptance testing.
- The platform identity has no Security REST administration, snapshot, system
  index, or all-index role.
- Bootstrap admin, platform OpenSearch, RabbitMQ, MinIO, encryption, health,
  worker, and query credentials are distinct. The Docker stack file is
  root-owned mode 0600. The gateway receives only a query-token file owned by
  `sift-service`, mode 0600.
- The OpenCTI worker uses its own service account. OpenCTI 7 requires workers
  to have the `BYPASS` administrator capability; this account is privileged but
  is separate from the bootstrap administrator and confined to the internal
  application network.
- `opencti-mcp` uses a separate service account whose exact capability set is
  `KNOWLEDGE`. Registration stores environment references only. No raw token,
  OpenSearch credential, worker token, or administrator token enters the
  registry payload or add-on subprocess.
- Case-search tooling remains prefix/case scoped and must never expose
  `opencti*` indices.

## Official role and unavoidable cluster metadata authority

OpenCTI creates and refreshes composable/component templates, the attachment
ingest pipeline, and its ISM policy during startup. The official OpenCTI role
therefore includes:

- `cluster_composite_ops_ro`
- `cluster_manage_index_templates`
- `cluster:admin/ingest/pipeline/put`
- `cluster:admin/opendistro/ism/policy/write`
- the documented monitor, scroll, bulk, and index-template actions

OpenSearch 3.5 does not resource-scope these cluster actions by template,
pipeline, policy name, or body index pattern. Consequently, the `opencti*`
index rule prevents direct case-data access but cannot cryptographically prevent
the trusted platform process from installing a template whose body targets a
future `case-*` index. Upgrading OpenSearch does not currently remove this
limitation, and OpenCTI 7.260710.0 provides no supported disable-template-
management switch.

This is an explicit trust decision, not a claim of perfect least privilege.
OpenCTI must be treated like another operator-installed cluster-management
component for those narrow metadata actions. A compromised platform container
could affect future index creation through a malicious template or pipeline,
although it still cannot directly read or rewrite existing case documents with
its index permissions.

## Custody and detection

Forensic evidence and custody are authoritative in Postgres and the immutable
evidence vault; OpenSearch is derived and cannot rewrite custody history. An
OpenSearch metadata change can disrupt or influence derived search results, but
must not be interpreted as an evidence mutation.

Acceptance records hashes of case templates, component templates, pipelines,
aliases, mappings, and settings before OpenCTI startup and after startup/restart.
Any unexpected object whose name or body targets `case-*`, or any case-state
hash drift, is a release blocker. Direct case-index denial, role readback,
credential separation, registration redaction, and core-health-with-OpenCTI-
stopped are also mandatory acceptance rows. OpenSearch Security audit logging
must retain granted and denied actions for the dedicated `sift_opencti`
principal so cluster metadata changes are attributable and cannot be silent.

## Residual risks and operating rules

1. The platform's global template/pipeline/ISM write permissions are broader
   than the `opencti*` data boundary. Mitigation is operator trust, dedicated
   identity, audit attribution, drift comparison, and fail-closed acceptance.
2. The worker is a privileged OpenCTI API identity because upstream requires
   `BYPASS`. Network isolation and a distinct token reduce reuse and exposure;
   they do not make the worker unprivileged.
3. Secrets are visible to Docker administrators through container inspection.
   Docker/root access is already host-administrator authority.
4. Shared-cluster resource contention can reduce core availability. OpenCTI is
   independently stoppable, and core health must remain green while it is down.
5. Every OpenCTI, pycti, or OpenSearch version change reopens the compatibility,
   permission, template-drift, image-digest, and outage proof matrix. Floating
   tags and automatic upgrades are prohibited.

If audit visibility or drift comparison is unavailable, shared-target
acceptance fails closed. The supported fallback is to leave OpenCTI stopped;
weakening TLS, using the core admin identity, exposing raw services, or granting
case-index access is never an acceptable workaround.
