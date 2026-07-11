# Quick Start / Installation

## Prerequisites

- **SANS SIFT Workstation VM** or Debian/Ubuntu with the SIFT forensic packages installed.
- **Python 3.12** via system `apt` (`/usr/bin/python3.12`). The installer uses SIFT-native Python; it does not use `uv`-managed Python releases (`install.sh:13-14`).
- **Docker daemon running** for OpenSearch and the local Supabase containers (`docker-compose.yml`).
- **Standard tools:** `git`, `curl`, `awk`, `sudo` (`install.sh:151-152`).

## Step 1: Clone and Install

```bash
git clone https://github.com/anomalyco/sift-mcps
cd sift-mcps
./install.sh
```

The installer is **idempotent** — re-running it is safe; every step checks whether work is already done (`install.sh:10`). A full install takes 5-15 minutes depending on downloads and system speed.

### What it does (in order)

The install stages the requested source to `/opt/sift-mcps`, then runs these phases:

| Phase | What happens |
|---|---|
| `stage_repo_to_install_root` | Clones/stages the repo tree into `/opt/sift-mcps`. |
| `check_os` / `check_python` | Verifies SIFT/Debian base and `/usr/bin/python3.12`. |
| `install_host_prereqs` | Installs system packages (`git`, `build-essential`, `fuse3`, auditd, AppArmor tools, etc.). |
| `ensure_docker_ready_for_supabase` | Confirms Docker daemon is reachable before local Supabase starts. |
| `preflight_supabase` | Provisions a self-hosted Supabase project (Postgres, Auth, REST API). Skipped only by `--external-supabase`. |
| `sync_workspace` | Builds the mandatory `core` runtime venv, then additively installs selected first-party packs. |
| `install_state_dirs` | Creates `/var/lib/sift` (state, secrets, enrichment) and `/cases` (evidence root). |
| `write_gateway_config` | Renders `configs/gateway.yaml.template` into the active gateway config with env-var substitution. |
| `write_supabase_env` / `write_control_plane_env` | Writes Supabase URL, keys, and the control-plane DSN into `~/.sift/supabase.env` and `~/.sift/control-plane.env` (`install.sh:221-222`). |
| `start_opensearch` | Starts secured OpenSearch 3.5.0 with TLS/authentication, then verifies and seeds the mandatory core data plane. |
| `configure_opensearch_cluster` | Seeds OpenSearch index templates, aliases, and the ingestion pipeline. |
| `install_hayabusa` / `install_zimmerman_symlinks` | Downloads Hayabusa (Sigma-based detection), places it on `PATH`, and creates symlinks for Zimmerman forensic tools. |
| `install_systemd_service` | Installs three systemd services: `sift-gateway`, `sift-job-worker`, and `sift-opensearch-worker@{1,2}`. All run as the `sift-service` user (`configs/systemd/sift-gateway.service:10`). |
| `poll_gateway "initial"` | Waits for the gateway to respond through its configured TLS endpoint. |
| `bootstrap_supabase_operator` | Creates the initial operator account in Supabase Auth and registers it in the portal's control-plane DB. Runs only after the gateway is up so Postgres is reachable (`install.sh:313`). |
| `write_handoff` | Prints operator credentials and next steps (`install.sh:322`). |

### Services installed

| Systemd unit | Purpose | Ports / listeners |
|---|---|---|
| `sift-gateway` | MCP server + REST API + Portal backend | `0.0.0.0:4508` (`configs/gateway.yaml.template:2-3`) |
| `sift-job-worker` | Durable background job executor, pinned to `run_command` lane | None — polls Postgres job queue via `FOR UPDATE SKIP LOCKED` (`configs/systemd/sift-job-worker.service:19`) |
| `sift-opensearch-worker@{1,2}` | Two parallel OpenSearch ingest/enrich workers | None — claims ingest/enrich jobs from Postgres (`configs/systemd/sift-opensearch-worker@.service:14,28`) |

All services run as the `sift-service` user. Secrets (Supabase keys, control-plane DSN, OpenSearch config) are loaded from `EnvironmentFile=` entries under `/var/lib/sift/.sift/` — never hardcoded in config files (`configs/systemd/sift-gateway.service:32-42`). The gateway unit applies `ProtectSystem=strict`, `ProtectHome=tmpfs`, and a minimal `ReadWritePaths=` to `/var/lib/sift`, `/cases`, and `/var/cache/sift` (`configs/systemd/sift-gateway.service:70-78`). The job-worker runs with `CapabilityBoundingSet=CAP_LINUX_IMMUTABLE` only — the narrowest privilege set (`configs/systemd/sift-job-worker.service:83`). The OpenSearch workers additionally carry `CAP_SYS_ADMIN` and run in the host mount namespace because FUSE forensic image mounts require both (`configs/systemd/sift-opensearch-worker@.service:97` and `:58-72`).

## Step 2: Installation Variants

Bare install is deterministic and non-interactive. It always installs the
mandatory core: gateway, portal, operations, workers, OpenSearch, and
`opensearch-mcp`. Optional packs use positive flags only.

```bash
# Use an existing self-hosted Supabase project instead of auto-provisioning one.
# Export SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY, and
# SIFT_CONTROL_PLANE_DSN before running (install.sh:102-104).
./install.sh --external-supabase

# Add both first-party packs (RAG and Windows triage).
./install.sh --with-core-addons

# Or select packs independently. The ~12 GiB registry baseline is separate.
./install.sh --with-rag
./install.sh --with-windows-triage
./install.sh --with-windows-triage-registry

# Air-gapped / hardened install: no network downloads. Each download step fails
# and points at the operator-staged artifact path it expects (install.sh:105-108).
./install.sh --offline

# Explicit interactive selection; this is the only interactive install mode.
./install.sh --interactive
```

AppArmor enforce mode and the hardened execution floor are defaults. The
`--apparmor-complain` switch is only for local profile development and is not an
acceptance posture.

**OpenCTI note:** The installer never installs OpenCTI. After the core install, run the one external
setup command from the staged runtime; it provisions the pinned shared target and emits an env-ref-only
registration payload. Validate and register that payload through Portal > Backends, then restart the gateway:

```bash
/opt/sift-mcps/scripts/setup-addon.sh opencti --provision
```

## Step 3: Wait for Gateway Health

The installer polls the gateway until it responds (`install.sh:303`). If you need to check manually:

```bash
curl --cacert /var/lib/sift/.sift/tls/ca-cert.pem https://localhost:4508/health
# Expected: HTTP 200 with JSON status body
```

The gateway listens on `0.0.0.0:4508` with TLS. Use `https://<host>:4508/health`; the
installer-managed CA lives under the SIFT TLS directory.

## Step 4: First Operator

At the end of the install, `write_handoff` prints your credentials (`install.sh:322`). The handoff block contains:

- **Operator email** and **temporary password** (must be changed on first login).
- **Portal URL:** `https://<host>:4508/portal`.
- **Gateway token** (prefix `sift_gw_`) for CLI and REST access.

The portal enforces password reset on first login (`configs/gateway.yaml.template:190`). Supabase Auth is the sole credential authority; JWTs issued by Supabase are validated at every request (`configs/gateway.yaml.template:122-129`). Agent principals need tokens that last up to 48 hours — before deploying, confirm your Supabase Auth service has `GOTRUE_JWT_EXP=172800` and `JWT_EXPIRY=172800` applied (`configs/supabase/auth-jwt.env.template:22-23`).

## Step 5: Configure Agent Client

Point your AI agent client at the MCP endpoint. The gateway serves MCP over the FastMCP streamable HTTP transport at `/mcp`:

```
http://<host>:4508/mcp     (no TLS)
https://<host>:4508/mcp    (TLS, production)
```

**Auth:** Provide a Supabase JWT as a `Bearer` token in the `Authorization` header. The gateway validates it against Supabase Auth and maps the `auth.users.id` to an operator or agent principal (`configs/gateway.yaml.template:115-117,128`).

Example for Claude Desktop / Codex / MCP Inspector:
```json
{
  "mcpServers": {
    "sift": {
      "url": "https://sift-vm:4508/mcp",
      "headers": {
        "Authorization": "Bearer <your-supabase-jwt>"
      }
    }
  }
}
```

## Step 6: Verify Capabilities

```bash
# List all registered MCP tools:
curl -H "Authorization: Bearer <gateway-token>" \
  http://localhost:4508/api/v1/tools

# Check backend health:
curl -H "Authorization: Bearer <gateway-token>" \
  http://localhost:4508/api/v1/backends
```

The `/api/v1/tools` endpoint returns every tool registered across all backends — core tools, OpenSearch MCP, forensic RAG, and any add-ons. The `/api/v1/backends` endpoint shows which backends are healthy and responding.

### Verify ingest prerequisites (optional)

If you plan to use the OpenSearch ingest pipeline (E01 disk forensic images), run the prerequisite checker:

```bash
./verify-ingest-prereqs.sh
```

This checks: `ewfmount`, `fusermount`, `fdisk`, passwordless `sudo mount`, Zimmerman tools (AmcacheParser, AppCompatCacheParser, RECmd, MFTECmd, JLECmd, LECmd, SBECmd), Hayabusa + rules, `python-evtx`, `regipy`, and OpenSearch reachability (`verify-ingest-prereqs.sh:34-89`).

## Uninstalling

The installer preserves your data. Running `--uninstall` with `-y` stops and removes the systemd services, the service user, the venv, `~/.sift` (config/TLS/secrets), and auditd/AppArmor configs — but it **never touches** your evidence or state:

- `/var/lib/sift` state dirs are preserved.
- `/cases` evidence is preserved.
- Docker volumes are preserved.
- To remove forensic state or Docker data, run `scripts/uninstall.sh` directly with non-evidence components. Evidence can only be removed through the gated evidence path in `scripts/uninstall.sh` (`install.sh:114-121`).

## Next Steps

- **[Operator Manual](15%20-%20Operator%20Manual.md)** — Work through a real forensic investigation from case creation to tool execution.
- **[Configuration Reference](16%20-%20Configuration%20Reference.md)** — Tune `gateway.yaml`, environment variables, systemd drop-ins, and cluster settings.
- **[Authentication for API and MCP](11%20-%20Authentication%20for%20API%20and%20MCP.md)** — Token formats, identity resolution, and the three auth surfaces.
- **[Troubleshooting](18%20-%20Troubleshooting.md)** — If anything fails during or after install.
