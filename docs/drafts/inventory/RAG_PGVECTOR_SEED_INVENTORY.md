# RAG pgvector Seed Inventory

_Generated from the checked-in RAG package on 2026-07-11. This inventory
describes source artifacts available in the repository; it does not assert the
contents of a particular deployed database._

## Scope and trust boundary

`forensic-rag-mcp` is a shared **knowledge/reference-only** plane. The default
seed writes `kind='knowledge'` and `case_id=NULL`; it must not receive case
evidence or create findings. The RAG package is gateway-owned: the gateway
holds the control-plane connection, and no RAG child process receives a
database credential.

The default installer path is:

```text
packages/forensic-rag-mcp/knowledge/**/*.jsonl
  -> rag-mcp-seed-pgvector --embedding-mode model
  -> app.rag_collections / app.rag_documents / app.rag_chunks
```

Each JSONL record becomes one pgvector chunk. `manifest.sha256` is the
integrity manifest for every bundled document.

## Default, checked-in seed corpus

The direct (`SIFT_RAG_IMPORT_SOURCE=direct`, or unset) seed contains **2
collections, 44 documents, and 4,318 chunks**. All 44 SHA-256 entries verified
against `knowledge/manifest.sha256` on 2026-07-11.

| Collection / provider | Documents | Chunks | Repository location |
| --- | ---: | ---: | --- |
| AppliedIR analyst references | 6 | 570 | `knowledge/AppliedIR/` |
| SANS cheat sheets and posters | 38 | 3,748 | `knowledge/SANS/` |
| **Total** | **44** | **4,318** | `knowledge/` |

Both directories contain a `.bundled` marker. Attribution for these providers
is in [`ATTRIBUTION.md`](../../../packages/forensic-rag-mcp/ATTRIBUTION.md).

### AppliedIR documents

| Document | Chunks |
| --- | ---: |
| `AppliedIR/Credential-Defense-Analyst-Reference.jsonl` | 52 |
| `AppliedIR/Default-Windows-Processes-Quick-Reference.jsonl` | 17 |
| `AppliedIR/Lateral-Movement-Analyst-Reference.jsonl` | 182 |
| `AppliedIR/PowerShell-Quick-Reference.jsonl` | 36 |
| `AppliedIR/WMIC-Quick-Reference.jsonl` | 45 |
| `AppliedIR/Windows-Event-Log-Analyst-Reference.jsonl` | 238 |

### SANS documents

| Document | Chunks |
| --- | ---: |
| `SANS/SANS-CD-OSINT-1125.jsonl` | 163 |
| `SANS/SANS-ICS-Assessment-Quick-Start-Guide.jsonl` | 82 |
| `SANS/SANS-ICSPS-ICS410-0525.jsonl` | 29 |
| `SANS/SANS-ICSPS-ICSCIR-0525.jsonl` | 69 |
| `SANS/SANS-Memory-Forensics-Cheatsheet-102325.jsonl` | 38 |
| `SANS/SANS-Pivoting-Cheat-Sheet-v1.2.jsonl` | 30 |
| `SANS/SANS-SIFT-Cheatsheet-102325.jsonl` | 47 |
| `SANS/SANS-Trifold-Cheatsheet-DFIR-CTI-v1.1.jsonl` | 45 |
| `SANS/SANS_Analysing_Malicious_Docs_Cheat_Sheet.jsonl` | 51 |
| `SANS/SANS_BloodHound_Cheat_Sheet.jsonl` | 55 |
| `SANS/SANS_Burp_Suite_Cheat_Sheet.jsonl` | 58 |
| `SANS/SANS_CloudNativeSecurityToolsCheatSheet_V1.0.0.jsonl` | 37 |
| `SANS/SANS_DFIR_Cheat_Sheet_Booklet_v2.jsonl` | 372 |
| `SANS/SANS_DFPS-FOR572_v1.13_09-23.jsonl` | 94 |
| `SANS/SANS_DFPSFOR5180924.jsonl` | 532 |
| `SANS/SANS_DFPS_Command-Line.jsonl` | 60 |
| `SANS/SANS_DFPS_FOR500_v4.18_09-24.jsonl` | 217 |
| `SANS/SANS_DFPS_FOR508_v4.11_0624.jsonl` | 65 |
| `SANS/SANS_DFPS_FOR610_Malware_Analysis.jsonl` | 171 |
| `SANS/SANS_DFPS_FOR610_v1.4_2503.jsonl` | 187 |
| `SANS/SANS_Eric_Zimmerman_Tools.jsonl` | 55 |
| `SANS/SANS_Hex_Regex_Forensics.jsonl` | 83 |
| `SANS/SANS_ICS_Network_Segmentation.jsonl` | 52 |
| `SANS/SANS_Industrial_Protocols.jsonl` | 68 |
| `SANS/SANS_Intrusion_Discovery_Linux.jsonl` | 42 |
| `SANS/SANS_JSON_jq_Guide.jsonl` | 28 |
| `SANS/SANS_Kubernetes_Cloud_Native_Security_DevSecOps_Automation.jsonl` | 54 |
| `SANS/SANS_LINUX_Incident_Response_Threat_Hunting_Poster.jsonl` | 189 |
| `SANS/SANS_Linux_Shell_Survival.jsonl` | 107 |
| `SANS/SANS_Malware_Analysis_&_Reverse_Engineering_Cheat_Sheet.jsonl` | 62 |
| `SANS/SANS_Modbus_RTU_TCP.jsonl` | 39 |
| `SANS/SANS_Multicloud_cheatsheet_V1.2.1.5.jsonl` | 37 |
| `SANS/SANS_REMnux Usage_Tips_for_Malware_Analysis_on_Linux.jsonl` | 61 |
| `SANS/SANS_Ransomware_and_Cyber_Extortion.jsonl` | 169 |
| `SANS/SANS_SQLite_Reference.jsonl` | 55 |
| `SANS/SANS_TCPIP_Cheatsheet_2024.jsonl` | 141 |
| `SANS/SANS_oledump_Quick_Reference.jsonl` | 64 |
| `SANS/sans-siem-log-lifecycle.jsonl` | 40 |

The record metadata contains the source label, title, category, and platform;
the seed also adds a relative `source_ref`, record index, and stable provenance
identifier. The source reference deliberately never contains a local path.

## Optional legacy corpus and upstream sources

`SIFT_RAG_IMPORT_SOURCE=chroma` is a compatibility path, not the default.
It downloads a pinned `rag-index-*` release bundle and imports its precomputed
768-dimensional embeddings from a local Chroma collection into pgvector. The
bundle is intentionally not tracked in this repository (`data/` is ignored),
so its individual records and hashes cannot be extracted from this checkout.
The upstream release audit independently verified that
`rag-index-v2026.03.01` contains both a 22,268-record Chroma collection and
the parsed `sources/*.jsonl` records from which its non-bundled material was
built. See `RAG_UPSTREAM_RELEASE_AUDIT.md` for the exact release checksum and
the migration recommendation.

The larger legacy corpus is attributed to the following public source registry.
These sources are **not** fetched by the default installer or exposed as an MCP
refresh tool; the historical refresh subsystem is a maintenance path and its
live feeds are not content-pinned. Do not imply that every entry below exists
in a direct-seeded database.

Do not combine a direct seed with the full Chroma import on one clean target:
the full release already contains the 4,318 bundled AppliedIR/SANS records.
Doing both produces 26,586 chunks and duplicates the bundled reference
material.

| Source key | Upstream |
| --- | --- |
| `sigma` | SigmaHQ/sigma |
| `atomic` | redcanaryco/atomic-red-team |
| `mitre_attack` | mitre-attack/attack-stix-data |
| `mitre_car` | mitre-attack/car |
| `mitre_d3fend` | d3fend.mitre.org/ontologies/d3fend.json |
| `stratus_red_team` | DataDog/stratus-red-team |
| `cisa_kev` | CISA Known Exploited Vulnerabilities feed |
| `elastic` | elastic/detection-rules |
| `splunk_security` | splunk/security_content |
| `lolbas` | LOLBAS-Project/LOLBAS |
| `gtfobins` | GTFOBins/GTFOBins.github.io |
| `hijacklibs` | wietze/HijackLibs |
| `forensic_artifacts` | ForensicArtifacts/artifacts |
| `kape` | EricZimmerman/KapeFiles |
| `velociraptor` | Velocidex/velociraptor-docs |
| `mitre_atlas` | mitre-atlas/atlas-data |
| `mitre_engage` | mitre/engage |
| `loldrivers` | magicsword-io/LOLDrivers |
| `capec` | mitre/cti |
| `mbc` | MBCProject/mbc-stix2.1 |
| `chainsaw` | WithSecureLabs/chainsaw |
| `hayabusa` | Yamato-Security/hayabusa-rules |
| `forensic_clarifications` | Embedded package data (not an external repository) |

The 22 external sources, their licences, and historical record counts are
listed in `packages/forensic-rag-mcp/ATTRIBUTION.md`; the source configuration
is the code authority in `src/rag_mcp/sources.py`.

## Embedding source and reproducibility

The direct seed embeds documents with the default allowlisted model
`BAAI/bge-base-en-v1.5` (768 dimensions), pinned at revision
`a5beb1e3e68b9ab74eb54cfd186867f64f240e1a`. The model is a dependency for
seeding and querying, not a knowledge-document source. Other allowlisted models
require an intentional full re-embed before they can be queried consistently.

## Gateway MCP tool surface

The RAG pack is registered by `sift-backend.json` under the `kb` namespace and
runs inside the gateway's normal catalog, authorization, audit, and
response-guard path.

| Tool | Inputs | Result |
| --- | --- | --- |
| `kb_search_knowledge` | `query` (1–1000 chars); optional `top_k` (1–50), `source`, exact `source_ids` (max 20), `technique`, and `platform` (`windows`, `linux`, `macos`) | Ranked, provenance-linked, path-free knowledge hits. A zero-match technique filter is explicitly relaxed while preserving other filters. |
| `kb_list_knowledge_sources` | None | Distinct source labels currently present in the deployed pgvector corpus. |
| `kb_get_knowledge_stats` | None | Health plus chunk, document, collection, source, embedding dimension, and model counts. |

All three tools are read-only. Their output is supporting reference context,
never case evidence, attribution, or a finding.

## Reproducible verification and seed commands

Validate the repository corpus without a database write:

```bash
uv run --extra rag rag-mcp-seed-pgvector \
  --knowledge-dir packages/forensic-rag-mcp/knowledge \
  --embedding-mode deterministic --dry-run
(cd packages/forensic-rag-mcp/knowledge && shasum -a 256 -c manifest.sha256)
```

The dry run must report 2 collections, 44 documents, and 4,318 chunks. A real
seed is an intentional control-plane write and should use the documented
service-owned environment and model cache in
`docs/drafts/operator/rag-and-search-maintenance.md`; do not place a DSN on a
bare command line.
