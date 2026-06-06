# sift-agent Rust CLI Feasibility, Specification, and Build Plan

Status: draft
Scope: `opensearch-mcp` evolution path into a standalone Rust-first DFIR agent CLI
Target reader: SIFT/SIFTHACK maintainers, DFIR automation engineers, agent runtime builders

## Executive Summary

`sift-agent` should be a standalone, Rust-first CLI UX for autonomous DFIR workflows backed by OpenSearch. The right implementation is not a naive line-by-line rewrite of `opensearch-mcp`. The right implementation is a Rust control plane that owns:

- installation and environment validation
- OpenSearch lifecycle and templates
- high-speed query, aggregation, timeline, export, and pivot workflows
- agent-safe stdout/stderr/file output discipline
- background job control and status
- bulk indexing and retry behavior
- enrichment orchestration
- safety checks for agent-facing inputs, configs, and tool output

The current `opensearch-mcp` package should be treated as the behavioral reference implementation, especially for ingestion status, shard safety, deduplication, case summaries, compact search responses, and host identity correction. Heavy forensic engines should be wrapped first as controlled adapters instead of being rewritten immediately.

In short:

```text
Rust owns the shell-native agent workflow.
OpenSearch owns indexed evidence search.
External forensic tools remain controlled adapters where they are already best-in-class.
Parser rewrites happen only when Rust gives real operational value.
```

## Vision

`sift-agent` is the CLI that an autonomous DFIR agent would choose if it had a real terminal, not an MCP tool menu.

It should support two install modes:

```bash
sift-agent install full
sift-agent install core --opensearch-config ~/.sift/opensearch.yaml
```

Full mode provisions and manages the local OpenSearch Docker environment. Core mode accepts an existing OpenSearch config and uses that cluster.

The core user journey:

```bash
sift-agent doctor
sift-agent ingest ./evidence --case inc001 --profile balanced --background
sift-agent status --watch
sift-agent summary --case inc001 --json
sift-agent search --case inc001 'event.code:4688 AND process.name:*powershell*' --limit 50 --jsonl
sift-agent agg --case inc001 --field process.name --query 'user.name:SYSTEM'
sift-agent timeline --case inc001 --interval 30m --detect-anomalies
sift-agent pivot --case inc001 --from source.ip --to process.name --where 'event.code:4688'
sift-agent enrich hayabusa --case inc001 --rules ~/.sift/hayabusa-rules
sift-agent enrich opencti --case inc001 --config opencti.toml
sift-agent enrich virustotal --case inc001 --ioc hashes --rate public
sift-agent safety scan-agent-configs ./repo --rules atr,tirith
```

The agent should be able to run several commands in parallel, send large outputs to files, inspect logs, run follow-up `jq`/`rg`/`xargs`/`parallel` workflows, and keep a precise evidence trail.

## External References

Core implementation references:

- OpenSearch Rust client: https://docs.opensearch.org/latest/clients/rust/
- OpenSearch Rust crate docs: https://docs.rs/opensearch/latest/opensearch/
- OpenSearch API reference: https://docs.opensearch.org/latest/api-reference/
- Rust CLI argument parsing with `clap`: https://docs.rs/clap/latest/clap/
- Tokio async runtime: https://tokio.rs/
- Docker API from Rust with `bollard`: https://docs.rs/bollard/latest/bollard/
- Serde serialization: https://serde.rs/
- Rust TLS with rustls: https://github.com/rustls/rustls

DFIR engines and detection systems:

- Hayabusa: https://github.com/Yamato-Security/hayabusa
- Hayabusa rules: https://github.com/Yamato-Security/hayabusa-rules
- Sigma specification: https://github.com/SigmaHQ/sigma-specification
- Sigma project docs: https://sigmahq.io/docs/
- Volatility 3: https://github.com/volatilityfoundation/volatility3
- Eric Zimmerman tools: https://ericzimmerman.github.io/
- Plaso/log2timeline: https://github.com/log2timeline/plaso
- The Sleuth Kit: https://github.com/sleuthkit/sleuthkit
- libewf: https://github.com/libyal/libewf

Threat intelligence and enrichment:

- OpenCTI API docs: https://docs.opencti.io/latest/reference/api/
- OpenCTI platform: https://github.com/OpenCTI-Platform/opencti
- VirusTotal API v3: https://docs.virustotal.com/v3/reference/
- MISP: https://github.com/MISP/MISP
- MISP taxonomies: https://github.com/MISP/misp-taxonomies
- Abuse.ch URLhaus: https://urlhaus.abuse.ch/api/
- Abuse.ch ThreatFox: https://threatfox.abuse.ch/api/
- Abuse.ch Feodo Tracker: https://feodotracker.abuse.ch/
- CISA Known Exploited Vulnerabilities catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- OSV.dev API: https://osv.dev/docs/

Agent and supply-chain safety:

- Agent Threat Rules: https://github.com/Agent-Threat-Rule/agent-threat-rules
- ATR integration docs: https://agentthreatrule.org/en/integrate
- Tirith: https://github.com/sheeki03/tirith
- OSV-Scanner: https://github.com/google/osv-scanner
- OSV-Scanner docs: https://google.github.io/osv-scanner/
- Trivy: https://github.com/aquasecurity/trivy
- Trivy docs: https://trivy.dev/latest/docs/
- Syft: https://github.com/anchore/syft
- Grype: https://github.com/anchore/grype
- Anchore open source tools: https://oss.anchore.com/
- cargo-audit: https://github.com/rustsec/rustsec/tree/main/cargo-audit
- cargo-deny: https://github.com/EmbarkStudios/cargo-deny

Optional local analytics/search:

- Apache DataFusion: https://datafusion.apache.org/
- Apache Arrow Rust: https://github.com/apache/arrow-rs
- Tantivy: https://github.com/quickwit-oss/tantivy
- Parquet format: https://parquet.apache.org/

## Current opensearch-mcp Intelligence

The current Python package already encodes operational lessons that should not be discarded.

Relevant current files:

- `src/opensearch_mcp/server.py`
  - MCP tools for search, count, aggregate, event retrieval, timeline, field values, status, shard status, case summary, container inspection, ingest, ingest status, enrichment, detections, and host fixes.
  - Contains compact-result behavior that strips high-volume fields and truncates large values.
  - Contains query hints and case summary coverage logic.
  - Contains current async/background ingest launch behavior.

- `src/opensearch_mcp/ingest_cli.py`
  - Existing CLI for `scan`, `csv`, `memory`, `json`, `delimited`, `accesslog`, and `enrich-intel`.
  - Handles case resolution, active case state, host dictionary loading, shard preflight, status writes, background status, and direct parser calls.
  - Already solves many mundane CLI edge cases: dry runs, no matching files, per-file parser isolation, recursive host directory mode, and terminal status on crashes.

- `src/opensearch_mcp/ingest.py`
  - Shared ingest orchestrator.
  - Discovers hosts and artifacts.
  - Routes to native EVTX parsing, Zimmerman tools, Plaso artifacts, custom parsers, and Hayabusa.
  - Writes ingest manifests.

- `src/opensearch_mcp/bulk.py`
  - Bulk indexing retry logic.
  - Batch splitting under timeouts.
  - Circuit breaker for systemic cluster rejection.
  - Last bulk failure reason capture.

- `src/opensearch_mcp/ingest_status.py`
  - Atomic status file writes.
  - Monotonic terminal-state protection.
  - Dead process and zombie detection.
  - Cleanup behavior.

- `src/opensearch_mcp/tools.py`
  - Registry of Zimmerman-style tools:
    - AmcacheParser
    - AppCompatCacheParser
    - RECmd
    - SBECmd
    - JLECmd
    - LECmd
    - RBCmd
    - MFTECmd
    - WxTCmd
    - EvtxECmd CSV ingest path
  - Encodes tiers, timestamp fields, natural keys, and index suffixes.

- `src/opensearch_mcp/paths.py`
  - Case-safe paths.
  - Index component sanitization.
  - Timezone resolution for Windows timezone names.

- `scripts/setup-opensearch.sh`
  - Docker check.
  - OpenSearch password/config generation.
  - Snapshot repository setup.
  - OpenSearch startup.
  - Health wait.
  - Shard limit configuration.
  - Smoke test.
  - GeoIP pipeline setup.
  - Security Analytics setup.

The key migration lesson: do not only port parser code. Port the behavior envelope around parser code.

## Feasibility Assessment

### High Feasibility in Rust

These should be Rust-native early:

- CLI command tree
- configuration loading
- OpenSearch client
- OpenSearch health/status
- template and pipeline installation
- index lifecycle operations
- search/count/aggregate/timeline/event retrieval
- scroll/search-after export
- JSON/JSONL parsing
- CSV/TSV parsing
- W3C log parsing
- access log parsing
- SSH/auth log parsing
- PowerShell transcript parsing
- bulk indexing and retry
- background jobs and status files
- output formatting
- run manifests
- enrichment orchestration
- OpenCTI GraphQL client
- VirusTotal REST client
- local IOC pack enrichment
- simple anomaly detection over timeline buckets
- saved query packs
- safety scanning orchestration

### Medium Feasibility in Rust

These are feasible but should be phased:

- native EVTX parsing with parity to current ECS-like fields
- native Windows registry parsing parity
- native MFT/USN parsing
- Sigma rule execution against indexed OpenSearch data
- host identity correction and safe reindexing at large scale
- durable task queue inside a single binary
- local offline cache with Parquet/DataFusion
- high-quality anomaly scoring beyond simple time bucket deviations

### Low Feasibility for v1 as Pure Rust

These should remain external adapters in v1:

- Volatility 3 replacement
- Plaso/log2timeline replacement
- full ZimmermanTools replacement
- E01/VHDX mounting implementation
- full Sigma v2 correlation engine parity
- full-featured malware/sandbox analysis

## Product Principles

1. Agent-native first.
   - Commands must compose in a shell.
   - Outputs must be predictable.
   - Big outputs must not flood the agent context.

2. Small stdout, rich files.
   - stdout is for concise answers or machine-readable streams.
   - long outputs default to files.
   - stderr is for progress and diagnostics only.

3. Every mutating operation has a run ID.
   - Ingest, enrich, reindex, delete, repair, and setup writes run state.

4. No silent data loss.
   - Bulk failures must surface in status and logs.
   - Mapping conflicts must be visible.
   - Shard exhaustion must halt early.

5. External tools are untrusted by default.
   - Tool version, path, hash, command, stdout/stderr, and exit code are captured.
   - Optional sandboxing is part of the command model.

6. Search is the primary investigation interface.
   - Ingest exists to make search excellent.
   - Query UX should be better than raw OpenSearch without hiding power.

7. Config must be central and inspectable.
   - No hidden magic.
   - Secrets use references, not plaintext by default.

8. Safety is part of DFIR.
   - The agent itself is an attack surface.
   - Agent configs, MCP configs, skills, command output, and repo dependencies are scan targets.

## Install Modes

### Full Mode

```bash
sift-agent install full
```

Responsibilities:

- check Docker availability
- start or create `sift-opensearch`
- generate local credentials
- write config
- set memory and shard policy
- install templates
- install ingest pipelines
- configure optional snapshot path
- run smoke test
- write install manifest

Full mode should not hide each step behind a shell script. It should expose each as an idempotent subcommand:

```bash
sift-agent os docker-check
sift-agent os up
sift-agent os wait
sift-agent os templates install
sift-agent os pipelines install
sift-agent os smoke-test
```

### Core Mode

```bash
sift-agent install core --opensearch-config ./opensearch.toml
```

Responsibilities:

- validate OpenSearch URL and auth
- validate templates can be installed or already exist
- validate cluster shard settings
- write local `sift-agent` config
- skip Docker ownership

Core mode is important for:

- labs with shared OpenSearch
- remote OpenSearch clusters
- cloud OpenSearch
- existing SIFT installations
- CI and test harnesses

## Command Specification

### Global Flags

```bash
sift-agent [GLOBAL] <command>

Global:
  --config <path>          Config file path
  --case <case_id>         Active case override
  --profile <name>         Runtime profile
  --json                   JSON object output
  --jsonl                  JSON Lines output
  --table                  Human table output
  --csv                    CSV output
  --output <path>          Write primary result to file
  --stdout                 Force large result to stdout
  --quiet                  Suppress nonessential stderr
  --verbose                Increase diagnostics
  --trace                  Include request IDs and timing
  --no-color               Disable ANSI color
```

### Install and Doctor

```bash
sift-agent install full
sift-agent install core --opensearch-config ~/.sift/opensearch.yaml
sift-agent doctor
sift-agent doctor --json
sift-agent config show
sift-agent config validate
sift-agent config init
```

Doctor checks:

- config parse
- secret references
- OpenSearch reachability
- OpenSearch version
- template status
- pipeline status
- shard headroom
- Docker status if full mode
- external adapter availability
- Hayabusa rules path
- Volatility availability
- Python bridge availability if enabled
- case root writability
- output root writability
- safety policy status

### OpenSearch Management

```bash
sift-agent os health
sift-agent os status
sift-agent os shard-status
sift-agent os templates list
sift-agent os templates install
sift-agent os pipelines list
sift-agent os pipelines install
sift-agent os smoke-test
sift-agent os up
sift-agent os down
sift-agent os logs
```

### Ingest

```bash
sift-agent ingest <path>
  --case <id>
  --format auto|json|delimited|accesslog|w3c|evtx|memory|container
  --hostname <name>
  --host-mode auto|force|from-path|from-file
  --include <artifact,artifact>
  --exclude <artifact,artifact>
  --profile fast|balanced|full|custom
  --source-timezone <tz>
  --from <iso8601>
  --to <iso8601>
  --background
  --dry-run
  --clean
  --dedup content_hash|natural_key|none
  --batch-size <n>
  --parallel <n>
  --manifest-out <path>
```

Profiles:

- `fast`
  - EVTX reduced IDs
  - high-value logs
  - lightweight text artifacts
  - no MFT/USN by default
  - Hayabusa optional

- `balanced`
  - EVTX high-value logs
  - Amcache/Shimcache/Registry/Shellbags/Jumplists/LNK/RecycleBin
  - custom logs
  - Hayabusa if available
  - no high-cost MFT/USN unless requested

- `full`
  - all supported artifacts
  - MFT/USN
  - memory tier if memory image present
  - VSS if configured
  - full logs if requested

### Status and Logs

```bash
sift-agent status
sift-agent status --case inc001
sift-agent status --run <run_id>
sift-agent status --watch
sift-agent logs <run_id>
sift-agent logs <run_id> --stderr
sift-agent runs list
sift-agent runs inspect <run_id>
```

Status schema should include:

```json
{
  "run_id": "uuid",
  "kind": "ingest",
  "case_id": "inc001",
  "status": "running",
  "started_at": "2026-06-03T12:00:00Z",
  "updated_at": "2026-06-03T12:03:00Z",
  "pid": 12345,
  "source_path": "/cases/inc001/evidence",
  "totals": {
    "indexed": 120000,
    "skipped": 12,
    "bulk_failed": 0,
    "artifacts_total": 9,
    "artifacts_complete": 4,
    "hosts_total": 2,
    "hosts_complete": 0
  },
  "warnings": [],
  "error": null
}
```

### Query

```bash
sift-agent search --case inc001 '<query>'
sift-agent search --index 'case-inc001-evtx-*' '<query>'
sift-agent count --case inc001 '<query>'
sift-agent agg --case inc001 --field event.code --query '*'
sift-agent fields --case inc001 --artifact evtx
sift-agent values --case inc001 --field user.name --query 'event.code:4624'
sift-agent event --index case-inc001-evtx-host1 --id abc123
sift-agent timeline --case inc001 --interval 1h --query '*'
```

Search options:

```bash
  --limit <n>
  --offset <n>
  --sort '@timestamp:desc'
  --from <iso8601>
  --to <iso8601>
  --select field,field,field
  --exclude field,field
  --compact
  --full
  --highlight
  --output <path>
  --save-query <name>
```

Default output strategy:

- `limit <= 200`: stdout by default.
- `limit > 200` or export mode: write to file by default.
- `--jsonl` streams one event per line.
- `--table` is for humans, not agents.

### Pivot and Hunt

```bash
sift-agent pivot --case inc001 --from source.ip --to process.name --where 'event.code:4688'
sift-agent pivot --case inc001 --from user.name --to host.name --where 'event.code:4624'
sift-agent hunt lateral-movement --case inc001
sift-agent hunt suspicious-powershell --case inc001 --from 2026-01-01T00:00:00Z
sift-agent hunt deleted-prefetch --case inc001
sift-agent hunt timestomp --case inc001
```

Pivot output should be compact:

```json
{
  "case_id": "inc001",
  "from": "source.ip",
  "to": "process.name",
  "edges": [
    {
      "source": "10.0.0.5",
      "target": "powershell.exe",
      "count": 12,
      "sample_query": "source.ip:\"10.0.0.5\" AND process.name:\"powershell.exe\""
    }
  ]
}
```

### Timeline and Anomaly Detection

```bash
sift-agent timeline --case inc001 --interval 30m --query 'event.code:4624'
sift-agent timeline --case inc001 --interval 5m --query 'process.name:powershell.exe' --detect-anomalies
```

Initial anomaly methods:

- z-score over bucket counts
- median absolute deviation
- day/hour baseline if enough data exists
- first-seen timestamp for rare entities
- burst detection for process/user/IP combinations

Output:

```json
{
  "interval": "30m",
  "total_docs": 123456,
  "buckets": [],
  "anomalies": [
    {
      "time": "2026-01-12T03:30:00Z",
      "count": 442,
      "score": 5.7,
      "reason": "count exceeds rolling baseline"
    }
  ]
}
```

### Enrichment

```bash
sift-agent enrich hayabusa --case inc001 --rules ~/.sift/hayabusa-rules
sift-agent enrich opencti --case inc001 --config opencti.toml
sift-agent enrich virustotal --case inc001 --ioc hashes --rate public
sift-agent enrich local-ioc --case inc001 --feed feeds/iocs.jsonl
sift-agent enrich baseline --case inc001 --package windows-defaults
```

Enrichment result fields should use a new neutral convention:

```text
sift.enrichment.<provider>.checked
sift.enrichment.<provider>.matched
sift.enrichment.<provider>.verdict
sift.enrichment.<provider>.confidence
sift.enrichment.<provider>.labels
sift.enrichment.<provider>.references
sift.enrichment.<provider>.updated_at
```

Examples:

```text
sift.enrichment.opencti.verdict = "malicious"
sift.enrichment.virustotal.matched = true
sift.enrichment.hayabusa.level = "high"
sift.enrichment.baseline.verdict = "unexpected"
```

### Safety

```bash
sift-agent safety scan-agent-configs ./repo --rules atr
sift-agent safety scan-agent-configs ./repo --rules tirith
sift-agent safety scan-tool-output output.txt --rules atr
sift-agent safety scan-url https://example.com
sift-agent safety scan-supply-chain ./repo --scanner osv
sift-agent safety scan-supply-chain ./repo --scanner trivy
sift-agent safety scan-supply-chain ./repo --scanner syft-grype
```

Safety targets:

- AI instruction files
- MCP configs
- skills/plugins
- shell scripts
- package manifests and lockfiles
- Dockerfiles
- GitHub Actions
- suspicious URLs
- tool outputs that may contain prompt injection

## Config Draft

```toml
[agent]
name = "sift-agent"
state_root = "~/.sift-agent"
default_output_dir = "~/.sift-agent/output"
default_format = "json"

[opensearch]
url = "https://localhost:9200"
user = "admin"
password_ref = "keyring:sift-agent/opensearch"
verify_certs = false
request_timeout_sec = 60
template_policy = "ensure"

[opensearch.bulk]
batch_size = 1000
max_retries = 10
initial_backoff_sec = 10
max_backoff_sec = 120
circuit_breaker_threshold = 3

[docker]
enabled = true
container_name = "sift-opensearch"
image = "opensearchproject/opensearch:3.5.0"
heap = "4g"
bind = "127.0.0.1:9200"
data_volume = "sift-opensearch-data"
snapshot_dir = "/var/lib/sift/snapshots"

[paths]
cases_root = "~/.sift-agent/cases"
allowed_evidence_roots = ["~/cases", "/mnt", "/media", "/run/media", "/evidence", "/cases", "/tmp"]

[ingest]
default_profile = "balanced"
source_timezone = "UTC"
max_parallel_files = 4
dedup = "content_hash"
status_interval_sec = 5
write_manifests = true

[adapters.hayabusa]
enabled = true
binary = "hayabusa"
rules_path = "~/.sift/hayabusa-rules"
timeout_sec = 7200

[adapters.volatility]
enabled = true
binary = "vol"
default_tier = 1
timeout_sec = 3600

[adapters.zimmerman]
enabled = true
tools_root = "/opt/zimmermantools"
timeout_sec = 7200

[adapters.plaso]
enabled = true
log2timeline = "log2timeline.py"
psort = "psort.py"
timeout_sec = 14400

[enrich.opencti]
enabled = false
url = "http://localhost:8080"
token_ref = "env:OPENCTI_TOKEN"
min_interval_ms = 100
breaker_threshold = 10

[enrich.virustotal]
enabled = false
api_key_ref = "env:VT_API_KEY"
rate_limit = "4/min"
cache_ttl_days = 30

[enrich.local_ioc]
enabled = true
feed_dirs = ["~/.sift-agent/feeds"]

[safety]
enabled = true
path_policy = "case_scoped"
redact_secrets = true
scan_agent_configs = true
scan_tool_output = false
external_tool_sandbox = true

[safety.atr]
enabled = true
rules_path = "~/.sift-agent/rules/agent-threat-rules"

[safety.tirith]
enabled = false
binary = "tirith"
mode = "adapter"
```

## Proposed Index and Field Conventions

Index naming:

```text
case-{case_id}-{artifact_type}-{host_id}
```

Examples:

```text
case-inc001-evtx-dc01
case-inc001-hayabusa-dc01
case-inc001-mft-dc01
case-inc001-vol-pslist-dc01
case-inc001-json-suricata-sensor01
case-inc001-zeek-conn-sensor01
```

Metadata field convention:

```text
sift.case.id
sift.host.id
sift.host.name
sift.artifact.type
sift.artifact.source_path
sift.artifact.source_sha256
sift.ingest.run_id
sift.ingest.parser
sift.ingest.parser_version
sift.ingest.adapter
sift.ingest.adapter_version
sift.ingest.created_at
sift.ingest.timezone
sift.schema.version
sift.enrichment.*
```

Keep common ECS-compatible fields where appropriate:

```text
@timestamp
event.code
event.action
event.provider
host.name
host.id
user.name
process.name
process.command_line
process.parent.name
source.ip
destination.ip
file.path
file.name
file.hash.sha256
registry.path
```

Guidance:

- Use ECS-compatible names when they fit.
- Use `sift.*` for SIFT-specific provenance, ingest, parser, and enrichment metadata.
- Do not encode evidence semantics only in index names; store artifact type and host in document fields too.
- Keep raw source fields where they aid forensic verification, but exclude high-volume raw fields from compact search output by default.

## Run State Layout

```text
~/.sift-agent/
  config.toml
  cases/
  runs/
    20260603-120000-inc001-ingest-<uuid>/
      status.json
      manifest.json
      plan.json
      stdout.log
      stderr.log
      adapter-commands.jsonl
      bulk-failures.jsonl
      host-discovery.json
      output/
        summary.json
        results.jsonl
  feeds/
  rules/
  cache/
```

`manifest.json` should include:

```json
{
  "run_id": "uuid",
  "case_id": "inc001",
  "kind": "ingest",
  "started_at": "2026-06-03T12:00:00Z",
  "operator": "agent",
  "source_roots": [],
  "artifacts": [],
  "tools": [],
  "opensearch": {
    "url": "https://localhost:9200",
    "version": "3.5.0"
  },
  "config_hash": "sha256..."
}
```

## Adapter Model

Every external tool invocation is represented as a structured adapter run:

```json
{
  "adapter": "hayabusa",
  "binary": "/usr/local/bin/hayabusa",
  "version": "x.y.z",
  "binary_sha256": "sha256...",
  "args": ["csv-timeline", "-d", "...", "-o", "..."],
  "cwd": "/cases/inc001",
  "env_policy": "redacted",
  "started_at": "2026-06-03T12:00:00Z",
  "finished_at": "2026-06-03T12:03:00Z",
  "exit_code": 0,
  "stdout_log": "stdout.log",
  "stderr_log": "stderr.log",
  "outputs": []
}
```

Adapter requirements:

- version capture
- binary path capture
- optional binary hash
- command capture with secret redaction
- output file capture
- timeout
- kill policy
- allowlist of writable directories
- structured parser for adapter outputs
- status propagation

## Parser Strategy

### Native Rust v1 Parsers

Implement these first:

- JSON/JSONL/NDJSON
- CSV/TSV
- Zeek TSV
- bodyfile
- Apache/Nginx access logs
- W3C logs
- OpenSSH auth logs
- PowerShell transcripts
- generic line-oriented logs with timestamp detection

These are high-value because they avoid Python startup and are straightforward with Rust streaming parsers.

Recommended crates:

- `serde_json`: JSON parsing
- `csv`: CSV/TSV parsing
- `chrono` or `time`: timestamps
- `regex`: log parsing
- `encoding_rs`: encoding handling
- `walkdir` or `ignore`: filesystem discovery

### Adapter Parsers v1

Use adapters for:

- Hayabusa
- Volatility 3
- ZimmermanTools
- Plaso/log2timeline
- SleuthKit utilities
- libewf utilities

### Native Rust v2 Candidates

Consider later:

- EVTX native parser
- registry parser
- MFT parser
- USN parser
- prefetch parser
- SRUM parser

Decision rule: rewrite when it improves speed, deployability, field quality, or safety enough to justify the maintenance cost.

## Query Engine Details

Rust OpenSearch module should expose:

```rust
trait SearchBackend {
    async fn health(&self) -> Result<Health>;
    async fn search(&self, request: SearchRequest) -> Result<SearchResponse>;
    async fn count(&self, request: CountRequest) -> Result<CountResponse>;
    async fn aggregate(&self, request: AggregateRequest) -> Result<AggregateResponse>;
    async fn timeline(&self, request: TimelineRequest) -> Result<TimelineResponse>;
    async fn get_event(&self, index: &str, id: &str) -> Result<EventDocument>;
    async fn bulk(&self, actions: BulkBatch) -> Result<BulkResult>;
}
```

Important behavior to port from current package:

- index pattern must be restricted to case indices by default
- limit caps
- compact result mode
- full document retrieval by `_id`
- time range filter
- sort parsing
- aggregation field handling
- shard status preflight
- exact count command
- result truncation warnings
- field mapping discovery
- mixed-parser field hints, but implemented as docs/query-pack guidance rather than chatty output

## Enrichment Model

### Hayabusa

Role:

- detect suspicious Windows event patterns
- produce alert timeline
- index alerts into `case-{case}-hayabusa-{host}`
- optionally stamp source events when reliable linkage exists

Command:

```bash
sift-agent enrich hayabusa --case inc001 --rules ~/.sift/hayabusa-rules
```

### OpenCTI

Role:

- enrich IPs, domains, hashes, URLs, and file hashes
- use GraphQL API
- cache results
- stamp matching docs

Command:

```bash
sift-agent enrich opencti --case inc001 --config opencti.toml
```

### VirusTotal

Role:

- lookup hashes, URLs, domains, IPs
- strict public API rate limiting by default
- cache aggressively
- never upload files unless explicitly approved

Commands:

```bash
sift-agent enrich virustotal --case inc001 --ioc hashes
sift-agent enrich virustotal --case inc001 --ioc urls --no-upload
```

### Local IOC Packs

Role:

- load JSONL/STIX/CSV IOCs
- deterministic local matching
- no network dependency

Command:

```bash
sift-agent enrich local-ioc --case inc001 --feed ./intel/iocs.jsonl
```

## Safety and Agent Risk Design

The product should acknowledge that an autonomous DFIR agent is itself a target.

Safety features:

- scan AI instructions and configs before trusting a repo
- scan MCP configs
- scan tool outputs before feeding them to an LLM
- block or warn on prompt injection patterns
- detect hidden Unicode and ANSI injection in text
- detect pipe-to-shell and suspicious install scripts
- detect malicious package names and typosquats where possible
- isolate external scanner execution

ATR integration:

- raw YAML rule parsing is attractive because it avoids a Node runtime dependency
- Node SDK can be used as an adapter if raw YAML parity lags
- output should normalize to `sift.safety.findings`

Tirith integration:

- strong fit for terminal/agent safety
- treat as optional adapter because of licensing and deployment assumptions
- do not make it mandatory for open-core operation without resolving license implications

Supply-chain scanners:

- OSV-Scanner for lockfile and dependency advisories
- Trivy for filesystem/repo/container scanning, secrets, misconfig
- Syft/Grype for SBOM and vulnerability scanning
- cargo-audit/cargo-deny for Rust project self-checks

Important caution:

Security scanners are themselves supply-chain dependencies. `sift-agent` should capture scanner version and binary hash, and prefer pinned versions in high-assurance environments.

## Output Contracts

Exit codes:

```text
0  success
1  operational failure
2  invalid user input
3  partial success with warnings
4  policy blocked
5  OpenSearch unavailable
6  adapter unavailable
7  no results
8  safety finding threshold exceeded
```

stdout:

- primary machine-readable result
- no progress text when `--json` or `--jsonl`

stderr:

- progress
- warnings
- diagnostics

Files:

- large exports
- background output
- logs
- manifests
- intermediate adapter outputs

## Migration From opensearch-mcp

Recommended migration path:

1. Add Rust query CLI against existing OpenSearch indices.
2. Keep current Python ingest path available.
3. Add Rust status reader compatible with current status files.
4. Add Rust template installer.
5. Add native Rust simple-format ingest.
6. Add adapter-managed heavy ingest.
7. Add enrichment adapters.
8. Keep MCP as an optional compatibility shim that invokes the Rust service layer or binary.

Initial compatibility commands:

```bash
sift-agent compat status-from-mcp
sift-agent compat import-opensearch-config ~/.sift/opensearch.yaml
sift-agent compat summarize-case --case inc001
```

## Deeper Build Plan

### Phase 0: Contract Capture

Deliverables:

- current index naming inventory
- current mapping inventory
- current parser artifact list
- current status schema capture
- current case summary response capture
- current enrichment field capture

Tasks:

- run tests that produce sample indices
- export mappings to fixtures
- export sample search responses
- write compatibility fixtures under `tests/fixtures/opensearch-mcp-compat`

### Phase 1: Rust CLI Skeleton

Deliverables:

- `sift-agent` binary
- config loader
- command tree
- logging/tracing
- output format manager
- error and exit code model

Tasks:

- create Rust workspace
- add `clap`, `tokio`, `serde`, `serde_json`, `toml`, `tracing`
- implement `doctor`, `config show`, `config validate`
- implement `--json`, `--jsonl`, `--output`

### Phase 2: OpenSearch Query Parity

Deliverables:

- `os health`
- `os shard-status`
- `search`
- `count`
- `agg`
- `values`
- `fields`
- `timeline`
- `event`
- `summary`

Tasks:

- implement OpenSearch client factory
- implement config auth
- implement request timeout handling
- implement case index resolver
- implement compact field filtering
- implement exact count
- implement aggregations
- implement timeline histogram
- implement field mapping flattener
- implement JSONL streaming output

### Phase 3: Template and Pipeline Control

Deliverables:

- `os templates install`
- `os pipelines install`
- smoke test
- template drift report

Tasks:

- port template registry
- embed template JSON or load from installed assets
- install idempotently
- validate template body before PUT
- install single-node replica policy
- install GeoIP pipeline if configured

### Phase 4: Job State

Deliverables:

- run directories
- status writer
- status watcher
- logs
- manifests
- background jobs

Tasks:

- implement atomic writes
- implement terminal-state monotonicity
- implement process liveness checks
- implement `status --watch`
- implement `logs <run_id>`
- implement cleanup policy

### Phase 5: Bulk Indexer

Deliverables:

- Rust bulk writer
- retry/backoff
- batch splitting
- circuit breaker
- failure reason capture

Tasks:

- port behavior from `bulk.py`
- support JSON action stream
- support per-index stats
- write `bulk-failures.jsonl`
- expose warnings in status

### Phase 6: Native Simple Ingest

Deliverables:

- JSON/JSONL ingest
- CSV/TSV ingest
- access log ingest
- W3C ingest
- SSH log ingest
- transcript ingest

Tasks:

- implement streaming parsers
- implement timestamp detection
- implement source timezone conversion
- implement deterministic document IDs
- implement host dictionary lookup
- implement per-file isolation
- implement dry-run plans

### Phase 7: Adapter Framework

Deliverables:

- adapter trait
- Hayabusa adapter
- Volatility adapter
- Zimmerman adapter
- Plaso adapter
- container inspection adapter

Tasks:

- implement command builder
- implement sandbox policy
- implement timeout and kill
- implement stdout/stderr capture
- implement adapter output parser
- index adapter output
- record tool version and hash

### Phase 8: Enrichment

Deliverables:

- Hayabusa enrichment
- OpenCTI enrichment
- VirusTotal enrichment
- local IOC enrichment
- enrichment status and coverage maps

Tasks:

- extract unique IOCs from OpenSearch
- implement provider cache
- implement rate limiters
- implement provider-specific verdict mapping
- stamp matching documents
- write coverage JSON
- resume interrupted enrichment

### Phase 9: Analytics and Hunt Packs

Deliverables:

- `pivot`
- `timeline --detect-anomalies`
- saved hunts
- query packs
- export to JSONL/CSV/Parquet

Tasks:

- implement pivot as aggregation fanout
- implement anomaly scoring
- write hunt pack schema
- create initial DFIR hunt packs:
  - suspicious PowerShell
  - lateral movement
  - service install
  - explicit credentials
  - deleted prefetch
  - timestomping indicators
  - RDP logons
  - WMI persistence
  - suspicious autoruns

### Phase 10: Safety Integrations

Deliverables:

- ATR scanner
- Tirith adapter
- OSV-Scanner adapter
- Trivy adapter
- Syft/Grype adapter

Tasks:

- define normalized safety finding schema
- implement scanner adapters
- implement policy thresholds
- implement `safety scan-agent-configs`
- implement `safety scan-supply-chain`
- write safety results into OpenSearch optionally

### Phase 11: Packaging

Deliverables:

- Linux binary
- `.deb`
- `.rpm`
- Homebrew formula
- Docker image
- signed checksums
- install docs

Tasks:

- add release workflow
- add signing
- add SBOM generation
- add self-scan with cargo-audit/cargo-deny
- add integration test with Docker OpenSearch

## Initial Task Backlog

P0:

- create `sift-agent` Rust workspace
- implement config model
- implement OpenSearch health
- implement search/count/agg/timeline
- implement JSON/JSONL output
- implement `summary --case`
- implement template installer

P1:

- implement run state
- implement background jobs
- implement native JSON/CSV ingest
- implement bulk writer
- implement Hayabusa adapter
- implement OpenCTI dry-run IOC extraction

P2:

- implement VirusTotal adapter
- implement local IOC packs
- implement pivot
- implement anomaly detection
- implement ATR scanner
- implement supply-chain scanner adapters

P3:

- native EVTX investigation
- registry parser investigation
- MFT/USN parser investigation
- optional DataFusion/Parquet offline cache
- optional MCP shim over `sift-agent`

## Open Questions

1. Should `sift-agent` live inside this monorepo or as a separate Rust workspace with this package as reference?
2. Should the new metadata convention be strictly `sift.*`, or should ECS-compatible fields remain the main normalized layer with `sift.*` only for provenance?
3. Should full install use Docker API via `bollard`, shell out to `docker compose`, or support both?
4. Should Python parsers be embedded as a compatibility bridge, or should v1 only use external CLI adapters plus native Rust simple parsers?
5. How strict should safety scanning be by default: warn-only or block-high?
6. Should enrichment write directly to existing documents, separate enrichment indices, or both?
7. Should large exports use OpenSearch scroll, point-in-time + search_after, or both depending on cluster version?

## Recommended Direction

Start with query parity, not ingest parity.

The fastest way to prove the concept is a Rust CLI that points at the current OpenSearch cluster and makes investigation dramatically better:

```bash
sift-agent summary --case existing-case
sift-agent search --case existing-case 'event.code:4688' --jsonl
sift-agent agg --case existing-case --field process.name
sift-agent timeline --case existing-case --detect-anomalies
```

After that, add Rust-native simple ingest and adapter-managed heavy ingest.

This creates value immediately for autonomous agents while avoiding a risky parser rewrite. Once the Rust command contract is stable, the MCP layer can become optional: a thin compatibility surface over the same operations.

