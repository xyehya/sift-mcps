# OpenCTI public-feed baseline for DFIR grounding

## Decision

The secure shared-target setup starts four keyless, release-aligned public
connectors by default:

| Connector | Agent value | Default posture |
| --- | --- | --- |
| MITRE ATT&CK | Canonical tactics, techniques, software, groups, mitigations, and relationships | Weekly; preserve source markings |
| CISA KEV | Authoritative signal that a CVE is exploited in the wild | Daily; no synthetic Infrastructure objects |
| ThreatFox | Recent IP, domain, URL, and hash IOCs with malware-family context | Daily; online IOCs only; score 50 |
| URLhaus | Malware-delivery URLs for browser, proxy, DNS, and download-artifact correlation | Daily; online URLs only; score 70 |

These sources add complementary semantic, vulnerability, network, and file-hash
grounding without paid subscriptions or operator-provided API keys. A match is
threat-intelligence context, not proof that evidence is malicious. Findings must
remain supported by sealed evidence, provenance, and the gateway policy chain.

MITRE's upstream bundle contains a cyclic provenance dependency: its Identity is
marked by its statement Marking while the Marking names that Identity as creator.
Setup validates the pinned STIX IDs and semantics, temporarily creates the
Identity without the marking, creates the Marking, then reapplies the original
marked Identity before the connector starts. This prevents forward-reference
retry storms without removing provenance.

The MITRE connector deliberately uses its built-in typed scope. Setting
`CONNECTOR_SCOPE=mitre`, as shown in upstream examples, turns that label into an
import filter and drops ATT&CK endpoint objects while still attempting their
relationships. Enterprise ATT&CK is pinned to immutable commit
`d4a34a19eb60dcd0a9d15a456da842a42e1003fc` (ATT&CK v17.1), the newest release
whose types are fully supported by this connector/platform tuple. Newer bundles
add analytic and detection-strategy types that leave dangling relationships in
connector 7.260710.0; move the pin only after the replacement tuple passes the
same zero-unresolved-reference acceptance gate.

## Deliberately not enabled by default

- **MalwareBazaar:** valuable file-hash and family metadata, but requires a free
  API key. Sample download connectors are excluded entirely because they create
  a new hostile-file storage and scanning boundary.
- **NVD CVE:** useful CVSS/CPE background but requires an API key, produces much
  more data, and can explode in volume when software/CPE import is enabled. CISA
  KEV provides the higher-signal default for incident response.
- **AlienVault OTX, MISP, and bulk community feeds:** useful when an operator
  already trusts a tenant/feed, but quality, marking, licensing, duplication,
  and false-positive rates vary.
- **VirusTotal:** strong enrichment but key/plan constrained. The keyless default
  substitute is ThreatFox plus URLhaus. It is narrower than VirusTotal and must
  not be represented as equivalent coverage.

## Security and authority model

- Every connector has its own OpenCTI service account, UUID, and token.
- The dedicated worker has the same bounded import capabilities plus OpenCTI's
  required `BYPASS`; `BYPASS` alone does not satisfy the platform's explicit
  reference/mandatory-field import checks.
- Worker and connector groups automatically receive newly imported markings, as
  required by OpenCTI's fresh-import model, and reconcile pre-existing markings
  created before those groups. The query group does not receive this authority.
- The connector role has only API token access, connector API access, connector
  metadata read, knowledge read/update, reference-import, and creation of the
  markings, labels, vocabularies, and kill-chain phases carried by imported
  STIX. It has no `BYPASS`, delete, merge, upload, export, enrichment, TAXII,
  connector-management, user, role, or general
  platform-administration capability.
- Connectors receive no OpenSearch, gateway, database, worker, query, or
  bootstrap-admin credential.
- Connectors join the internal OpenCTI application network and a connector-only
  egress bridge. They never join `sift-net`, publish ports, mount the Docker
  socket, or access case indices directly.
- Images match connector release `7.260710.0` and are pinned by multi-platform
  manifest digest. Containers drop all capabilities, set no-new-privileges,
  run as explicit unprivileged UID/GID 65532, use read-only roots and bounded
  tmpfs/resources, and rotate local logs.
- Connector tokens remain in root-owned mode-0600 runtime state. They never
  enter the MCP registry payload or gateway environment.
- Offline provisioning does not start Internet-feed connectors. Cached platform
  services and query access remain usable.

Docker bridge NAT permits general outbound Internet access from the feed
containers; it does not enforce destination/FQDN allowlists. The separate bridge
prevents connector attachment to the core network, while host firewall/proxy
policy is required for strict destination filtering. This is the remaining
deployment-level egress risk.

## Reliability criteria

Acceptance requires exact-image verification, one registered connector per
stable UUID, successful initial import, provenance/external-reference retention,
an idempotent rerun, and recovery after connector restart. Stopping all feed
connectors must leave OpenCTI, the gateway, core OpenSearch, and existing queries
healthy. A stale or failed connector is a loss of freshness, not a core outage.
The shared stack defaults to eight OpenCTI workers for the large initial MITRE and
URLhaus queues; `SIFT_OPENCTI_WORKERS` may set a measured value from 1 through 8.
Readiness requires at least 675 ATT&CK techniques from the immutable Enterprise
bundle, rather than accepting a misleading non-zero partial import.
First-run readiness is bounded to 30 minutes by default because MITRE Enterprise
alone contains more than 25,000 STIX objects; the bounded timeout is configurable.
