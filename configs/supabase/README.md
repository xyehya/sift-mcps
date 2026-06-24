# Minimal Supabase stack for SIFT Workstation

## What this is

The SIFT forensic gateway uses the **official Supabase CLI** (`supabase start`) to bring
up a minimal local Supabase stack. The repo's `supabase/config.toml` disables every
service SIFT does not need, giving a lean, reliable stack.

**Running services:**

| Service | Role |
|---------|------|
| `db`    | PostgreSQL 15 (`supabase/postgres:15.8.1.085`) — direct DSN for SIFT control plane |
| `auth`  | GoTrue — operator/agent login + JWT validation (`/auth/v1/*`) |
| `kong`  | API gateway — routes `/auth/v1/*` to GoTrue (CLI-managed) |

**Disabled:** Studio, Inbucket, Storage, Realtime, Edge Runtime, Analytics/Vector.
Analytics/Vector is the primary cause of local-stack startup failure; disabling it
is load-bearing for reliability.

## How to run

```bash
# Bring up (idempotent — safe to re-run):
./scripts/setup-supabase.sh

# Source the generated env and run the SIFT installer:
source ~/.sift/supabase-project/sift-supabase.env
./install.sh
```

The script:
1. Checks Docker is running (dies clearly with group-fix hint if not).
2. Installs the pinned Supabase CLI (`v2.105.0`) to `/usr/local/bin` (sudo) or
   `~/.sift/bin` if no sudo, reusing it on re-runs.
3. Runs `supabase start` from the repo root (idempotent — no-op if already up).
4. Captures credentials from `supabase status -o env`.
5. Writes `~/.sift/supabase-project/sift-supabase.env` (chmod 600).

## Environment variables written on success

`~/.sift/supabase-project/sift-supabase.env`:

```bash
export SUPABASE_URL=http://127.0.0.1:54321
export SUPABASE_ANON_KEY=<from CLI>
export SUPABASE_SERVICE_ROLE_KEY=<from CLI>
export SIFT_CONTROL_PLANE_DSN=postgresql://postgres:postgres@127.0.0.1:54322/postgres
```

## Key configuration (supabase/config.toml)

| Setting | Value | Why |
|---------|-------|-----|
| `[db] major_version` | `15` | SIFT migrations target Postgres 15 |
| `[auth] jwt_expiry` | `172800` | 48h tokens for autonomous forensic agents (AUT2-B0) |
| `[auth.email] enable_confirmations` | `false` | No SMTP on SIFT VM; autoconfirm |
| `[analytics] enabled` | `false` | Primary local-stack failure point |
| `[realtime] enabled` | `false` | Not used by SIFT |
| `[studio] enabled` | `false` | Not used by SIFT |
| `[storage] enabled` | `false` | Not used by SIFT |
| `[edge_runtime] enabled` | `false` | Not used by SIFT |

## How to reset

```bash
# Drop and recreate the DB from migrations (interactive):
./scripts/setup-supabase.sh --reset

# Non-interactive:
./scripts/setup-supabase.sh --reset --yes

# Stop the stack (keep volumes):
./scripts/setup-supabase.sh --stop
```

`--reset` runs `supabase db reset`, which drops the entire database and re-applies
all migrations in `supabase/migrations/`. **All data is lost.** Only safe on a
fresh or test instance.

## Ports (from config.toml)

| Variable | Port | Endpoint |
|----------|------|----------|
| `[api] port` | `54321` | `SUPABASE_URL` (Kong / GoTrue via `/auth/v1`) |
| `[db] port`  | `54322` | `SIFT_CONTROL_PLANE_DSN` (direct Postgres) |

## Supabase CLI version

Pinned: **v2.105.0** (`linux_amd64`)
Download URL: `https://github.com/supabase/cli/releases/download/v2.105.0/supabase_2.105.0_linux_amd64.tar.gz`

The script installs it automatically if absent.

## Migration filename format

The repo's migrations use **12-digit timestamps** (e.g. `202606070101_identity_foundation.sql`).
The Supabase CLI's migration filename regex is `^([0-9]+)_(.*)\.sql$` — it matches
**any number of digits**, not a fixed 14. The 12-digit filenames are accepted as-is.
No renaming is needed.

## Troubleshooting

**`supabase start` fails:**
```bash
supabase status          # check current state
docker ps                # check containers
docker logs sift-supabase-db   # or: supabase logs db
```

**Docker daemon unreachable:**
```bash
sudo systemctl start docker
sudo usermod -aG docker $USER && newgrp docker
```

**Analytics container fails (if you see it starting despite config):**
Analytics is disabled in `config.toml`. If an older CLI version ignores the flag,
upgrade to the pinned version and re-run.

**Checking migration status:**
```bash
cd /home/yk/AI/SIFTHACK/sift-mcps
supabase migration list
```

## Files

| File | Description |
|------|-------------|
| `supabase/config.toml` | CLI project config (checked in; authoritative) |
| `supabase/migrations/*.sql` | Schema migrations applied by `supabase start` / `db reset` |
| `scripts/setup-supabase.sh` | Bring-up script (install CLI, start, write env) |
| `configs/supabase/auth-jwt.env.template` | Documents the 48h JWT requirement (AUT2-B0) |
| `configs/supabase/solana-anchor.env.template` | Documents the operator-optional Solana proof anchoring (`SIFT_SOLANA_KEYPAIR` / `SIFT_SOLANA_CLUSTER`; unset => 503, no-op) |
| `configs/supabase/README.md` | This file |
