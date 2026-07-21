# Cursor Cloud dev environment

> Extracted from `AGENTS.md` (2026-07-21) to keep the always-on agent contract lean.
> This describes the **Cursor Cloud agent VM** dev environment only — NOT the
> maintainer's macOS + SIFT-VM setup in `AGENTS.md` §Deploy-and-prove. The Mac-side
> paths there (`ssh sift-vm`, `ssh sift-gateway-tunnel`, `localhost:4508`) are the
> maintainer's machines and do NOT work from this VM — ignore them. The live gateway
> IS reachable from a cloud agent, but over Tailscale (see below), not that SSH tunnel.

## Environment dashboard (where to configure your image)

Per-repo environment config lives in **two places** — repo wins over dashboard:

1. **Repo (authoritative):** `.cursor/environment.json` + `.cursor/scripts/` (this
   checkout). Committed config overrides wizard/snapshot settings on the branch the
   agent uses.
2. **Dashboard (secrets + version history):** open the **environment detail page**,
   not the top-level Cloud Agents list:
   - Environments list: https://cursor.com/dashboard/cloud-agents#environments
   - **This repo:** https://cursor.com/dashboard/cloud-agents/environments/r/github.com/xyehya/sift-mcps

On the environment detail page: **Secrets** sidebar (`TS_AUTHKEY`, `SIFT_CA_CERT` as
Runtime Secrets), network allowlist, version history, and **Start Setup Agent →
Update Existing Env** (required after secret or `environment.json` changes).

If `environment-info` reports `environment: null` / `build: null`, the agent booted
JIT from the default base image — no saved environment was applied. Fix: commit
`.cursor/environment.json` and start a new cloud agent on a branch that includes it,
or re-run setup from the dashboard.

## Toolchain (already installed in the base snapshot; refreshed by the update script)
- **uv** lives at `~/.local/bin` — the update script prepends it to `PATH`.
- **Node 24.13.1** is installed via nvm at `~/.nvm/versions/node/v24.13.1/bin`.
  A stale `/exec-daemon/node` (v22) is earlier on the default `PATH` and shadows
  it, so `node -v` in a fresh shell shows v22. The frontend requires Node 24
  (`packages/case-dashboard/frontend/package.json` engines), so **prepend the
  nvm bin** for any frontend command:
  `export PATH="$HOME/.nvm/versions/node/v24.13.1/bin:$PATH"`.

## Commands (standard invocations; authoritative source is `.github/workflows/ci.yml`)
- Python lint/typecheck/test/coverage all use `uv run --locked ... <tool>` exactly
  as in `ci.yml`. The supported pytest entrypoints are in
  `docs/new-docs/DEVELOPER_ENTRYPOINT.md` §11; CI runs the full suite via
  `pytest tests packages -m "not integration"` (importlib mode handles the
  cross-package collisions the doc warns about).
- Frontend (from `packages/case-dashboard/frontend`, Node 24 on PATH): `npm run dev`,
  `npm run lint`, `npm test` (vitest), `npm run build`.

## Docker is NOT installed here — and the standard dev/test loop does not need it
CI and the normal loop are Docker-free (`-m "not integration"`). The full backend
gateway (`sift-gateway` + OpenSearch from `docker-compose.yml` + Postgres/Supabase)
requires Docker and is out of scope for the standalone cloud dev env.

## Running the portal standalone (no backend) — the demoable app
`npm run dev` serves the examiner portal at `http://localhost:5173/portal/`.
Append `?mock=1` (`http://localhost:5173/portal/?mock=1`) to boot it fully seeded
with demo fixtures behind a mock auth context — no gateway needed. The mock/real
split lives ONLY at the API adapter (`src/api/client.js` + `src/_mock/routes.js`).
**Caveat:** only the endpoints enumerated in `src/_mock/routes.js` are mocked
(reports generate/save, backends register/validate/reload/enable, service
start/stop/restart, auth principals issue/revoke, and the GET reads). Any other
write — e.g. **findings Approve/Stage/Reject** — falls through to the real fetch,
hits the Vite `/portal` proxy, and returns **HTTP 502** with no backend. For a
standalone portal demo use report generation, backend register/validate, or agent
token issuance, not finding approval.

## Reaching the LIVE gateway over Tailscale (verified 2026-07-12)
The live SIFT gateway (libvirt VM `sift` on hypervisor `fedora44`) is reachable
from a cloud agent over the maintainer Tailscale tailnet. `fedora44` is a
Tailscale **subnet router** advertising an approved **`192.168.122.81/32`**
(only the VM). Gateway TLS: `https://192.168.122.81:4508` (`/health`, `/portal/`,
`/mcp`).

Required Cursor Cloud secrets (never commit or paste into chat/logs):
- `TS_AUTHKEY` — reusable, ephemeral auth key tagged **`tag:cursor-cloud`**.
  Tailnet ACL must grant only `tag:cursor-cloud → 192.168.122.81:tcp:4508`.
- `SIFT_CA_CERT` — PEM of the **public** SIFT CA (use `--cacert`, never `-k`).
- `SIFT_AGENT_TOKEN` — gateway bearer for `/mcp` (same env var as Codex CLI
  `codex mcp add --bearer-token-env-var SIFT_AGENT_TOKEN siftmcp ...`). Runtime
  Secret on the environment; referenced from `.cursor/mcp.json` / `.codex/config.toml`,
  never committed.

Cloud VMs cannot use kernel Tailscale. Use **userspace** networking (rootless):

```sh
mkdir -p /tmp/tailscaled.state
tailscaled --tun=userspace-networking \
  --socks5-server=localhost:1055 \
  --socket=/tmp/tailscaled.sock \
  --statedir=/tmp/tailscaled.state &
tailscale --socket=/tmp/tailscaled.sock up \
  --authkey="$TS_AUTHKEY" \
  --accept-routes \
  --hostname=cursor-cloud-agent
printf '%s\n' "$SIFT_CA_CERT" > /tmp/sift-ca.pem
curl --proxy socks5h://localhost:1055 --cacert /tmp/sift-ca.pem \
  --max-time 8 https://192.168.122.81:4508/health
```

`--accept-routes` is required to use the advertised `/32`. Least-privilege:
only `tcp:4508` on that address is intended to be reachable; OpenSearch `:9200`
and Supabase `:54321/:54322` stay loopback-only on the VM. `/mcp` returns 401
without gateway auth — reachability ≠ authorization. Hypervisor SSH from the
maintainer Mac: `ssh fedora44` (not `fedora.local`).

On cloud VM boot, `.cursor/scripts/cloud-start.sh` brings up userspace Tailscale
and exports `ALL_PROXY` / `HTTPS_PROXY` / `NODE_EXTRA_CA_CERTS` when ready. For
live MCP tools, harness config mirrors Codex CLI:

```sh
# Codex CLI equivalent:
codex mcp add --bearer-token-env-var SIFT_AGENT_TOKEN siftmcp \
  --url https://192.168.122.81:4508/mcp
```

- **Cursor:** `.cursor/mcp.json` → `siftmcp` with
  `"Authorization": "Bearer ${env:SIFT_AGENT_TOKEN}"`
- **Codex:** `.codex/config.toml` → `[mcp_servers.siftmcp]` with
  `bearer_token_env_var = "SIFT_AGENT_TOKEN"`

Set `SIFT_AGENT_TOKEN` as a Runtime Secret on the cloud environment (or export it
in your local shell for desktop). Requires Tailscale up first — HTTP MCP clients
use the proxy env from `~/.cursor-cloud-tailscale.env`.

## Known pre-existing test failures on a clean checkout (NOT environment issues)
- `tests/test_opencti_shared_target_contract.py::test_shared_check_is_read_only_and_requires_secure_core_contract`
  — requires the `docker` CLI to validate a compose contract; skips/fails when
  Docker is absent.
