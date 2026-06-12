# SIFT VM Tool and Path Inventory (BATCH-OR1)

Command-backed, read-only post-install inventory of the live SIFT VM. Captures
real paths, symlink targets, package/source ownership, services, Docker
resources, key config/TLS/secret paths (with **values redacted**), and a
missing-tool recommendation matrix.

- Collected: 2026-06-12, read-only over SSH (no VM writes, no restarts).
- VM: `sansforensics@192.168.122.81` — `siftworkstation`, Ubuntu 24.04.4 LTS,
  kernel 6.8.0-110-generic, x86_64.
- Login user: `sansforensics`; service user: `sift-service`; sandbox runtime
  user (configured): `agent_runtime`.
- This doc records secret **paths, modes, and ownership** on purpose. It never
  records secret **values**. `<redacted>` marks any place a value would appear.

> Reproduce read-only: an optional helper, `scripts/inventory-sift-tools.sh`,
> runs the same safe probes against the live VM and prints this data. It performs
> no writes and starts/stops nothing.

---

## 1. Service runtime and repo layout

| Fact | Value | Source |
| --- | --- | --- |
| Running services | `sift-gateway.service` (active), `sift-job-worker.service` (active), `docker.service` (active) | `systemctl list-units 'sift*' 'docker*'` |
| Service user/group | `sift-service` / `sift-service` | `systemctl show ... -p User -p Group` |
| Gateway unit file | `/etc/systemd/system/sift-gateway.service` | `-p FragmentPath` |
| Worker unit file | `/etc/systemd/system/sift-job-worker.service` | `-p FragmentPath` |
| Gateway WorkingDirectory | `/opt/sift-mcps` | `-p WorkingDirectory` |
| Gateway ExecStart | `/opt/sift-mcps/.venv/bin/sift-gateway --config /var/lib/sift/.sift/gateway.yaml` | `-p ExecStart` |
| Worker ExecStart | `/opt/sift-mcps/.venv/bin/sift-job-worker` | `-p ExecStart` |
| Gateway listen | `0.0.0.0:4508` (TLS), pid owner `sift-gateway` | `ss -tlnp` |
| Health | `GET https://127.0.0.1:4508/health` → `status=ok`; `forensic-rag-mcp` + `opensearch-mcp` stdio backends mounted, idle | `curl -sk .../health` |

Repo trees (both present, both owned by `sansforensics`, identical mtimes):

| Path | Role | Owner |
| --- | --- | --- |
| `/home/sansforensics/sift-mcps` | Clone-entry checkout (`git clone && ./install.sh`) | `sansforensics:sansforensics` |
| `/opt/sift-mcps` | Provisioned runtime root the services run from | `sansforensics:sansforensics` |

Service entry scripts under `/opt/sift-mcps/.venv/bin/` use shebang
`#!/opt/sift-mcps/.venv/bin/python3`, which is a venv symlink chain →
`/usr/bin/python3.12` (Python 3.12.3). No managed Python is used, matching VM
policy.

> **Note (cleanliness, not a fault):** `/opt/sift-mcps/.DS_Store` (14 KB) was
> deployed into the runtime root. Harmless but stray; candidate for installer
> ignore-list. See backlog candidate B-OR1-c.

---

## 2. Core / required tool path map

`command -v` + `readlink -f`, with `dpkg -S` ownership. "real" shown only where
it differs from the resolved path.

| Tool | Path | Real target | Ownership |
| --- | --- | --- | --- |
| `python3.12` | `/usr/bin/python3.12` | — | apt (base) |
| `python3` | `/usr/bin/python3` | `/usr/bin/python3.12` | apt (base) |
| `uv` | `/home/sansforensics/.local/bin/uv` | — | **manual operator install** (not on default non-login PATH) |
| `supabase` | `/usr/local/bin/supabase` | — | **manual** (root-owned, 109 MB; CLI v2.105.0) |
| `supabase-go` | `/usr/local/bin/supabase-go` | — | **manual** (root-owned, 100 MB; reports v2.105.0; **distinct binary** from `supabase`) |
| `docker` | `/usr/bin/docker` | — | apt `docker-ce-cli` (engine v29.4.1) |
| `docker compose` | plugin | — | Compose v5.1.3 (plugin) |
| `rg` | `/usr/bin/rg` | — | apt `ripgrep` |
| `hayabusa` | `/usr/local/bin/hayabusa` | `/var/lib/sift/.sift/bin/hayabusa` | **bundled by installer** (target owned `sift-service`; see §6) |
| `vol` / `volshell` | `/usr/local/bin/vol` | `/opt/volatility3/bin/vol` | **manual / SIFT distro** (Volatility 3 in its own venv at `/opt/volatility3`) |
| `fls` `mmls` `icat` `istat` `img_stat` `ffind` `blkls` | `/usr/bin/*` | — | apt `sleuthkit` |
| `tsk_comparedir` `tsk_gettimes` `tsk_imageinfo` `tsk_loaddb` `tsk_recover` | `/usr/bin/tsk_*` | — | apt `sleuthkit` |
| `ewfmount` | `/usr/bin/ewfmount` | — | apt `libewf-tools` |
| `log2timeline.py` `psort.py` `pinfo.py` | `/usr/bin/*` | — | apt `plaso-tools` (+ `python3-plaso`, `plaso-data`) |
| `bulk_extractor` | `/usr/bin/bulk_extractor` | — | apt `bulk-extractor` |
| `strings` | `/usr/bin/strings` | `/usr/bin/x86_64-linux-gnu-strings` | apt binutils |
| `jq` | `/usr/bin/jq` | — | apt `jq` |
| `curl` | `/usr/bin/curl` | — | apt `curl` |
| `openssl` | `/usr/bin/openssl` | — | apt `openssl` |
| `git` | `/usr/bin/git` | — | apt `git` |
| `sqlite3` | `/usr/bin/sqlite3` | — | apt `sqlite3` |
| `photorec` / `testdisk` | `/usr/bin/*` | — | apt `testdisk` |
| `foremost` | `/usr/bin/foremost` | — | apt `foremost` |
| `scalpel` | `/usr/bin/scalpel` | — | apt `scalpel` |
| `exiftool` | `/usr/local/bin/exiftool` | — | **manual** (root, r-xr-xr-x) |
| `opensearch-mcp` | `/opt/sift-mcps/.venv/bin/opensearch-mcp` | venv script | uv venv (`opensearch-mcp==0.6.1`) |
| `rag-mcp` | `/opt/sift-mcps/.venv/bin/rag-mcp` | venv script | uv venv (`rag-mcp==0.6.1`) |

### Naming gotchas (load-bearing)

- **`vol3` does not exist as a command name.** Volatility 3 is installed and
  working but exposed as `vol` / `volshell` (the SIFT distro convention),
  backed by `/opt/volatility3` (root-owned, separate Python). Any code/doc that
  shells out to literal `vol3` will fail; use `vol`.
- **`uv` is not on the service/non-login PATH.** It lives in
  `/home/sansforensics/.local/bin/uv` (operator-installed, owned
  `sansforensics:docker`, 61 MB). Scripts must not assume bare `uv` resolves
  for the `sift-service` user.
- **`yara` has no CLI binary.** apt installs `python3-yara` (4.5.0) +
  `libyara10`; there is no `/usr/bin/yara` executable. YARA is available only as
  a Python import, not as a CLI.
- **`supabase` vs `supabase-go` are two different binaries** (byte-distinct),
  both ~100 MB, both reporting v2.105.0. The Supabase CLI reports an available
  upgrade to v2.106.0 (informational only).

---

## 3. Forensic toolkit (apt-owned) confirmed installed

From `dpkg -l` (status `ii`): `sleuthkit`, `plaso-tools` / `python3-plaso` /
`plaso-data`, `bulk-extractor`, `libewf` / `libewf-dev` / `libewf-python3` /
`libewf-tools`, `testdisk`, `foremost`, `scalpel`, `python3-yara` /
`libyara10`, `ssdeep`, `hashdeep`, `afflib-tools` / `libafflib0t64` /
`libafflib-dev`, `exif` / `libexif12` / `libimage-exiftool-perl`.

Also present in `/usr/bin`: `tcpdump`, `wireshark`, `dc3dd`, `dcfldd`,
`ssdeep`, `sha256sum`, `md5sum`.

---

## 4. SIFT distro bundle in `/usr/local/bin` (manual / distro-managed)

`/usr/local/bin` carries the broad SANS SIFT toolset — **not dpkg-owned**
(manual / SIFT-distro installs). These are present and exposed on the login PATH
but are not products of this repo's installer. Highlights:

- **EZ Tools (Eric Zimmerman):** `MFTECmd`, `EvtxECmd`, `AmcacheParser`,
  `AppCompatCacheParser`, `RECmd`, `RBCmd`, `JLECmd`, `LECmd`, `SBECmd`,
  `SQLECmd`, `WxTCmd`, `RecentFileCacheParser`, `bstrings` (plus lowercase
  wrapper aliases).
- **Volatility 3:** `vol`, `volshell` → `/opt/volatility3`.
- **RegRipper / Perl artifact tools:** `rip.pl`, `regslack.pl`, `evtparse.pl`,
  `lnk.pl`, `pref.pl`, `jobparse.pl`, `recbin.pl`, `usnj.pl`, `tln.pl`, many
  `*.pl` (several with `.bak` siblings).
- **EVTX tooling:** `evtx_dump.py` and the full `evtx_*` (python-evtx) family.
- **Mac/iOS/Android triage:** `mac_apt.py` (+ variants), `ios_apt.py`,
  `mvt-ios`, `mvt-android`, `ufade`, `hindsight.py`/`hindsight_gui.py`.
- **PDF / malware triage:** `pdf-parser.py`, `pdfid.py`, `densityscout`,
  `packerid.py`, `pe-scanner`, `pe-carver`, `machinae`, `iocdump`,
  `stix-validator`.
- **Cloud/misc:** `aws`, `aws_completer`, `analyzemft`, `usnparser`,
  `idx-parser`, `sqlite-carver`, `INDXParse.py`, `MFTINDX.py`.

> These are operator/distro-managed. The repo installer should not assume it
> owns or upgrades them, and `run_command` policy should expect them to exist on
> a real SIFT image but **not** on a minimal base.

---

## 5. Service venv (`/opt/sift-mcps/.venv/bin`) entrypoints

Owner `sansforensics:sansforensics`; `python` → `/usr/bin/python3.12`.

| Entry script | Purpose |
| --- | --- |
| `sift-gateway` | Gateway server (systemd ExecStart) |
| `sift-job-worker` | Durable job worker (systemd ExecStart) |
| `opensearch-mcp`, `opensearch-ingest` | OpenSearch MCP backend + ingest CLI |
| `rag-mcp`, `rag-mcp-seed-pgvector`, `rag-mcp-import-chroma-pgvector` | RAG MCP backend + pgvector seed/import CLIs |
| `regipy-*` (`-parse-header`, `-dump`, `-diff`, `-plugins-run`, …) | Registry parsing (regipy 6.2.1) |
| `fastmcp`, `mcp`, `fastapi`, `uvicorn`, `httpx`, `websockets` | Runtime libs' CLIs |
| `huggingface-cli`/`hf`, `transformers`, `torchrun`, `tiny-agents` | Embedding/model tooling for RAG |

Key venv packages (`importlib.metadata`, 146 dists total): `fastmcp==3.4.2`,
`mcp==1.27.1`, `fastapi==0.136.1`, `opensearch-py==3.2.0`,
`opensearch-mcp==0.6.1`, `rag-mcp==0.6.1`, `psycopg==3.3.4` (+`-binary`),
`sentence-transformers==5.5.1`, `transformers==5.9.0`, `torch==2.10.0`,
`regipy==6.2.1`, `cryptography==48.0.0`, `pydantic==2.13.4`, `numpy==2.4.6`.

> The service venv does **not** contain `volatility3`, `yara-python`, or
> `plaso` — those forensic engines come from apt / `/opt` / `/usr/local`, not
> from the gateway venv. Confirmed via `import` failures inside the venv.

---

## 6. Hayabusa binary and rules

| Item | Path | Notes |
| --- | --- | --- |
| Launcher symlink | `/usr/local/bin/hayabusa` → `/var/lib/sift/.sift/bin/hayabusa` | root-owned symlink |
| Binary | `/var/lib/sift/.sift/bin/hayabusa` | 16 MB, `sift-service:sift-service`, mode `0755` with ACL (`+`); **installer-bundled** |
| Rules corpus | `/var/lib/sift/.sift/hayabusa-rules/` | `sift-service`, mode `0700`; 4,947 `*.yml` rules (builtin + sigma) |

> **Permissions gotcha:** to a non-`sift-service` user (e.g. the
> `sansforensics` login) the symlink *appears* "broken" because
> `/var/lib/sift/.sift/bin` is mode `0750`-class and not world-traversable. The
> target exists and resolves correctly **for the service user**. Verify hayabusa
> only as `sift-service`/root, not as the login user, to avoid a false "missing
> binary" report.

---

## 7. Volatility 3 + symbol cache

| Item | Path | Notes |
| --- | --- | --- |
| Volatility 3 install | `/opt/volatility3` | root-owned, own Python venv (`/opt/volatility3/bin/python3`) |
| CLI | `/usr/local/bin/vol`, `/usr/local/bin/volshell` | shebang → `/opt/volatility3/bin/python3` |
| Symbol cache | `/var/cache/sift/volatility-symbols` | `sift-service:sift` group, setgid (`drwxrwsr-x+`); currently ~empty (4 KB) — symbols fetched on demand |
| Sibling | `/var/cache/sift/archives` | root-owned |

> The symbol cache being empty is expected on a fresh install; Volatility
> downloads/builds symbols on first use. If the VM runs air-gapped, symbol
> availability is an operator concern (backlog candidate B-OR1-b).

---

## 8. Config, secrets, and TLS paths (values redacted)

Primary service config dir: `/var/lib/sift/.sift/` (owner `sift-service`, mode
`0700`). Referenced by systemd `EnvironmentFiles=` and `--config`.

| File | Mode | Owner | Holds (key names only) |
| --- | --- | --- | --- |
| `gateway.yaml` | `0600` | `sift-service` | gateway/case/execute/trust/auth/control_plane/token_registry/api_keys/portal/opensearch/enrichment/backends sections |
| `control-plane.env` | `0600` | `sift-service` | `SIFT_CONTROL_PLANE_DSN=<redacted>`, `SIFT_TOKEN_PEPPER=<redacted>` |
| `supabase.env` | `0600` | `sift-service` | `SUPABASE_URL`, `SUPABASE_ANON_KEY=<redacted>`, `SUPABASE_SERVICE_ROLE_KEY=<redacted>` |
| `opensearch.env` | `0600` | `sift-service` | `OPENSEARCH_CONFIG`, `OPENSEARCH_HOST` |
| `opensearch.yaml` | `0600` | `sift-service` | `host`, `user`, `password=<redacted>`, `verify_certs` |
| `forensic-knowledge.env` | `0644` | `sift-service` | `FK_DATA_DIR` (non-secret pointer) |
| `opencti-connector-mitre-id` | `0600` | `sift-service` | add-on connector id `<redacted>` |
| `opencti-connector-cisa-kev-id` | `0600` | `sift-service` | add-on connector id `<redacted>` |

Token / handoff:

| File | Mode | Owner | Notes |
| --- | --- | --- | --- |
| `/var/lib/sift/tokens/installer-handoff.txt` | `0600` | `sift-service` | temporary operator password before forced reset; **never commit contents** |

TLS / CA material — `/var/lib/sift/.sift/tls/` (dir `0700`, `sift-service`):

| File | Mode | Owner | Role |
| --- | --- | --- | --- |
| `ca-cert.pem` | `0644` | `sift-service` | local CA cert (public) |
| `ca-key.pem` | `0600` | `sift-service` | **CA private key** — secret |
| `gateway-cert.pem` | `0644` | `sift-service` | gateway TLS cert (public) |
| `gateway-key.pem` | `0600` | `sift-service` | **gateway TLS private key** — secret |

`gateway.yaml` references `opensearch.ca_cert_path:
/var/lib/sift/.sift/tls/ca-cert.pem` and `opensearch.url: http://127.0.0.1:9200`.

> **Hardening flag (S-OR1-1):** `gateway.yaml` contains a literal
> `portal.session_secret: <redacted>` value inline (not via env reference),
> unlike the DSN/pepper which are env-indirected. File is `0600`/`sift-service`,
> so not world-readable, but an inline session secret in a YAML config is a
> notable posture difference worth an operator/hardening decision. Recorded as
> fork candidate **F-OR1-1**; value is **not** reproduced here.

### Supabase project files (operator-owned)

`/home/sansforensics/.sift/supabase-project/` (owner `sansforensics:docker`):

| File | Mode | Owner | Notes |
| --- | --- | --- | --- |
| `sift-supabase.env` | `0600` | `sansforensics:docker` | sourced before `./install.sh`; keys `SUPABASE_URL`, `SUPABASE_ANON_KEY=<redacted>`, `SUPABASE_SERVICE_ROLE_KEY=<redacted>`, `SIFT_CONTROL_PLANE_DSN=<redacted>` |
| `bin/` | dir | `sansforensics:docker` | empty on this VM |

> **Do not hand-edit** the generated Supabase project env; it is an installer
> input/handoff artifact. (Full "what not to edit" guidance is OR3's job; noted
> here for path provenance.)

---

## 9. Docker resources

### Images

| Image | Size | Belongs to |
| --- | --- | --- |
| `opensearchproject/opensearch:3.5.0` | 2.94 GB | **core** (OpenSearch) |
| `public.ecr.aws/supabase/postgres:15.8.1.085` | 3.0 GB | **core** (control plane) |
| `public.ecr.aws/supabase/kong:2.8.1` | 203 MB | core (Supabase gateway) |
| `public.ecr.aws/supabase/gotrue:v2.189.0` | 81.8 MB | core (Supabase auth) |
| `public.ecr.aws/supabase/postgrest:v14.12` | 27.4 MB | core (Supabase REST) |
| `opencti/platform:latest` | 2.67 GB | **add-on** (OpenCTI) |
| `opencti/worker:latest` | 281 MB | add-on (OpenCTI) |
| `opencti/connector-mitre:latest` | 281 MB | add-on (OpenCTI) |
| `opencti/connector-cisa-known-exploited-vulnerabilities:latest` | 285 MB | add-on (OpenCTI) |
| `redis:7.4` | 170 MB | add-on dep (OpenCTI) |
| `rabbitmq:4.0-management` | 384 MB | add-on dep (OpenCTI) |
| `minio/minio:latest` | 241 MB | add-on dep (OpenCTI) |

> **Provenance note:** OpenCTI + redis/rabbitmq/minio images are **pulled and
> present** even though no OpenCTI container is running (see below). The add-on
> images linger from prior add-on bring-up. This matches "OpenCTI is an external
> add-on, not core" — but the images existing on a "core" VM is worth an
> operator note. (Backlog candidate B-OR1-a: document add-on image cleanup.)

### Containers (running)

| Name | Image | Status | Published port |
| --- | --- | --- | --- |
| `sift-opensearch` | opensearch:3.5.0 | Up, healthy | `127.0.0.1:9200->9200` (also 9300/9600 internal) |
| `supabase_db_sift-mcps` | supabase/postgres | Up, healthy | `127.0.0.1:54322->5432` |
| `supabase_kong_sift-mcps` | supabase/kong | Up, healthy | `127.0.0.1:54321->8000` |
| `supabase_auth_sift-mcps` | supabase/gotrue | Up, healthy | internal `9999` |
| `supabase_rest_sift-mcps` | supabase/postgrest | Up | internal `3000` |

No OpenCTI containers are running. All published ports bind to `127.0.0.1`
(loopback) except the Gateway's own `0.0.0.0:4508`.

### Volumes

`sift-mcps_opensearch-data`, `supabase_db_sift-mcps`, plus 3 anonymous
(`local`) volumes.

### Networks

`sift-net` (bridge), `sift-supabase-local` (bridge), plus default
`bridge`/`host`/`none`.

### Listening ports (host)

| Port | Bind | Owner |
| --- | --- | --- |
| 4508 | `0.0.0.0` | `sift-gateway` (TLS) — the only externally reachable service |
| 9200 | `127.0.0.1` | docker-proxy → OpenSearch |
| 54321 | `127.0.0.1` | docker-proxy → Supabase Kong |
| 54322 | `127.0.0.1` | docker-proxy → Supabase Postgres |

---

## 10. OpenSearch state

`curl http://127.0.0.1:9200/_cluster/health`: `cluster_name=docker-cluster`,
`status=yellow` (single node, 15 active primaries, 2 unassigned replicas —
expected for 1-node), 1 data node.

`_cat/indices` (selected): system indices
`.opendistro-job-scheduler-lock`, `.plugins-ml-config`, `.tasks`;
`top_queries-2026.06.*` (query insights); and case-seed init indices
`case-seed-accesslog-init`, `case-seed-evtx-init`, `case-seed-json-init`,
`case-seed-ssh-init` (0 docs each — seed/template scaffolding).

OpenSearch config:
- `OPENSEARCH_CONFIG` / `OPENSEARCH_HOST` in `/var/lib/sift/.sift/opensearch.env`.
- `/var/lib/sift/.sift/opensearch.yaml` (`host`, `user`, `password=<redacted>`,
  `verify_certs`).
- Gateway points at `http://127.0.0.1:9200` with
  `ca_cert_path=/var/lib/sift/.sift/tls/ca-cert.pem`.

---

## 11. RAG knowledge corpus and control-plane counts

| Item | Path / value | Notes |
| --- | --- | --- |
| Forensic-knowledge data | `/opt/sift-mcps/packages/forensic-knowledge/data` (732 KB) | repo-bundled; subdirs `tools/`, `artifacts/`, `discipline/` |
| Enrichment root | `/var/lib/sift/enrichment` | `forensic-knowledge` symlink → repo data dir; `forensic-rag` subdir present |
| RAG knowledge source | `/opt/sift-mcps/packages/forensic-rag-mcp/knowledge` (1.4 MB) | repo-bundled corpora `SANS/`, `AppliedIR/` |
| `app.rag_chunks` rows | **26,586** | `psql ... select count(*)` — RAG is populated |
| `app.mcp_backends` rows | **2** | the two stdio backends (`forensic-rag-mcp`, `opensearch-mcp`) |

Consistent with "RAG is knowledge/reference only in Supabase pgvector"; the
corpus is repo-bundled reference material, not case evidence.

---

## 12. Missing-tool matrix and recommendation

Tools probed and **not found** on this VM, with a recommended disposition.
Categories: **Required/default** (installer should ensure it), **Optional /
operator-managed** (leave to operator or SIFT distro), **Out-of-scope** (do not
install; only reachable via `run_command` if the operator added it).

| Tool | Status | Why it looked missing / reality | Recommendation |
| --- | --- | --- | --- |
| `vol3` | **Name absent; tool present** | Volatility 3 is installed as `vol`/`volshell` (`/opt/volatility3`); literal `vol3` never existed | Optional / operator-managed. **Action:** fix any code that calls `vol3` to call `vol`; do not add a `vol3` shim silently (raise if a contract requires the name). |
| `yara` (CLI) | **CLI absent; lib present** | `python3-yara` 4.5.0 installed; no `/usr/bin/yara` binary | Optional. If a tool needs the CLI, install apt `yara`; otherwise rely on the Python binding. |
| `uv` | Present but off service PATH | At `~/.local/bin/uv`, operator-installed | Required for build/maintenance, but it is operator/dev tooling — keep operator-managed; do not assume `sift-service` can run bare `uv`. |
| `hayabusa` | Present (false-negative) | Symlink target only traversable as `sift-service` | No action; documented in §6. Avoid login-user checks. |
| `node` / `npm` | Missing | Not installed | Optional. Only needed if portal is built on the VM; current portal ships built assets. Leave operator-managed unless a batch proves an on-VM build step. |
| `tshark` | Missing | `wireshark` + `tcpdump` present, but no `tshark` CLI | Optional. If pcap-to-text is needed by a tool, add apt `tshark`; else operator-managed. |
| `binwalk` | Missing | — | Optional / operator-managed (firmware carving, niche). |
| `guymager` | Missing | GUI imager; `dc3dd`/`dcfldd`/`ewfacquire` cover acquisition | Out-of-scope for a headless gateway VM. |
| `chainsaw` | Missing | Overlaps hayabusa (EVTX/sigma) | Out-of-scope (run_command only) unless a batch justifies it. |
| `capa` / `floss` | Missing | Malware capability/strings (Mandiant) | Out-of-scope / operator-managed; expose via `run_command` only if installed. |
| `afflib` (CLI name) | Missing as bare `afflib` | `afflib-tools` + `libafflib` ARE installed (provides `affconvert`, etc.) | No action; probe the right tool names. |

### Summary recommendation

- **Required/default the installer should guarantee:** the core stack it already
  installs (gateway venv, hayabusa bundle + rules, Volatility symbol-cache dir,
  Supabase + OpenSearch containers, TLS material). No missing *required* core
  tool was found — the gateway-critical path is complete.
- **Optional / operator-managed (or SIFT-distro provided):** `vol`/Volatility,
  YARA CLI, `tshark`, `node`/`npm`, the entire `/usr/local/bin` SIFT bundle,
  `uv`. Document expected presence but do not have the core installer own them.
- **Out-of-scope (run_command-only if the operator adds them):** `chainsaw`,
  `capa`, `floss`, `guymager`, `binwalk`.

---

## 13. Items for operator decision (fork/backlog candidates)

Raised for the conductor to register in `Session-Notes.md` (not decided here):

- **F-OR1-1 (hardening):** `gateway.yaml` stores `portal.session_secret`
  inline as a literal value rather than via an env reference (unlike the DSN and
  token pepper). Decide whether to env-indirect it for parity. File is
  `0600`/`sift-service`.
- **B-OR1-a:** OpenCTI + redis/rabbitmq/minio Docker images (~4.4 GB) are
  present on a core VM with no OpenCTI containers running. Document add-on image
  lifecycle / cleanup so a "core" install is not silently carrying add-on
  images.
- **B-OR1-b:** Volatility symbol cache (`/var/cache/sift/volatility-symbols`)
  is empty by default; document symbol provisioning for air-gapped operation.
- **B-OR1-c:** `/opt/sift-mcps/.DS_Store` was deployed into the runtime root;
  add to installer ignore-list.
- **Naming contract:** confirm no shipped code/tool contract calls literal
  `vol3` or a `yara` CLI; if it does, that is a real defect to fix in a code
  batch (this batch is read-only/docs).

## 14. Could-not-verify / scope notes

- Secret **values** were intentionally not read or recorded (handoff token,
  env values, private keys, DSNs). Only paths/modes/owners captured.
- `dpkg -S` on `/usr/local/bin/*` returns "not owned" by design (manual/distro
  installs); exact upstream provenance/version of each `/usr/local/bin` SIFT
  tool was not chased per-tool — they are distro-managed, out of this repo's
  installer scope.
- Anonymous Docker volumes (3 `local` unnamed) were not mapped to owning
  containers; they belong to the Supabase/OpenCTI stacks.
