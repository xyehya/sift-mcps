# RUN — Portal v3 full-align deploy to the SIFT VM

**Goal:** bring the live SIFT VM at `192.168.122.81` (`/opt/sift-mcps`) up to the
current `portal-v3/p0-foundation` tree (= `main`@`b995491` + the portal frontend +
the authoritative CSP fix) in **one reproducible operation**, then restart all
services and verify.

**Why a full align (not a routes-only patch).** The VM tree is **not a git repo**
(`/opt/sift-mcps/.git` is absent — it is an rsync-deployed tree) and its code
**predates `b995491`** (it lacks the D7 `ToolSurfaceSnapshot` gateway refactor and
the D4-extracted modules `case_dashboard/backends_routes.py`,
`case_dashboard/file_io.py`, `sift_common/identifiers.py`). That is why an earlier
routes-only deploy under-shipped. The fix is to rsync the **whole tree** (source +
freshly built dist) and re-sync the venv.

**Authoritative-layer CSP context.** The hardened portal CSP now lives in the
gateway (`packages/sift-gateway/src/sift_gateway/server.py` `SecureHeadersMiddleware`),
because the gateway WRAPS the mounted case_dashboard portal and its header wins for
`/portal` HTML. `case_dashboard/routes.py` is kept byte-consistent but is inert for
`/portal`. The hardened policy only reaches the browser AFTER this deploy + a
gateway restart.

> **Execution is the operator/orchestrator step.** This doc was authored after a
> READ-ONLY inspection of the VM. Run the commands below from the **portal-v3
> worktree** (`.claude/worktrees/portal-v3-p0-foundation`) on the dev host. VM creds
> live in the operator's environment (`sshpass -p 'forensics' … sansforensics@…`,
> sudo password = same). Do not hardcode beyond what is needed to run.

---

## 0. Preconditions (verified read-only on the VM, 2026-06-22)

| Fact | Value |
|------|-------|
| VM host / user | `sansforensics@192.168.122.81` (sudo pw = `forensics`) |
| Deploy tree | `/opt/sift-mcps` (editable installs → source edits take effect) |
| Tree owner | `sansforensics` |
| `uv` binary | `/home/sansforensics/.local/bin/uv` |
| Python | `/usr/bin/python3.12` (3.12.3) |
| venv | `/opt/sift-mcps/.venv` (services run as `sift-service`, must be able to read it) |
| Installed extras | **`full` + `windows-triage`** (`sift_gateway`, `case_dashboard`, `opensearch_mcp`, `rag_mcp`, `forensic_knowledge`, `windows_triage_mcp`). **opencti NOT installed.** `dev` group present (pytest in venv). |
| Services | `sift-gateway`, `sift-job-worker`, `sift-opensearch-worker@1`, `sift-opensearch-worker@2` (all `active`) |
| Control-plane DSN | `SIFT_CONTROL_PLANE_DSN` in `/var/lib/sift/.sift/control-plane.env` (also `supabase.env`) |
| Gateway config | `/var/lib/sift/.sift/gateway.yaml` — **OUTSIDE** `/opt`, untouched |
| Evidence | `/cases` (owned by `sift-service`) — **OUTSIDE** `/opt`, untouched |
| Migration ledger | **21/21 already recorded** (latest `202606160100_evidence_unseal`) = identical to repo → the migration step is currently a **no-op**, but still run it (idempotent, safety for any future drift) |
| Live CSP today (un-hardened, to be replaced) | `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com` |

Set once per shell on the dev host:

```bash
cd /home/yk/AI/SIFTHACK/sift-mcps/.claude/worktrees/portal-v3-p0-foundation
VM=sansforensics@192.168.122.81
VMPW=forensics            # SSH + sudo password (operator env)
CA=~/.sift-vm-ca-192.168.122.81.pem
SSH="sshpass -p $VMPW ssh -o StrictHostKeyChecking=no $VM"
```

---

## 1. Build the frontend FIRST (regenerates the dist that rsync ships)

The bundle lands in `packages/case-dashboard/src/case_dashboard/static/v2/`
(vite `outDir: ../src/case_dashboard/static/v2`, `base: /portal/`). The committed
copy is stale / mid-removal in the worktree — **always rebuild** so rsync ships the
current bundle.

```bash
cd packages/case-dashboard/frontend
npm ci          # or: npm install — ensure deps match package-lock
npm run build   # → ../src/case_dashboard/static/v2/ (index.html + assets/*)
cd -            # back to worktree root
# sanity: dist exists and is self-hosted (no external origins, no inline <script>)
ls packages/case-dashboard/src/case_dashboard/static/v2/index.html
grep -RIl 'fonts.gstatic\|googleapis\|<script[^>]*src="http' \
  packages/case-dashboard/src/case_dashboard/static/v2/ || echo "OK: no external script/font origins"
```

---

## 2. rsync the whole tree → VM (dry-run first, then real with `--delete`)

`--delete` is what makes the deploy truly reproducible (it removes VM-only stragglers
so the tree EXACTLY mirrors source). The excludes protect build/runtime artifacts.
Config and evidence are outside `/opt/sift-mcps`, so they are never touched.

```bash
RSYNC_EXCLUDES=(--exclude='.git' --exclude='node_modules' --exclude='.venv' \
  --exclude='__pycache__' --exclude='*.pyc' --exclude='*.egg-info' \
  --exclude='.pytest_cache')

# 2a. DRY RUN — review exactly what would change/delete. Inspect the output.
sshpass -p "$VMPW" rsync -avz -n --delete "${RSYNC_EXCLUDES[@]}" \
  -e "ssh -o StrictHostKeyChecking=no" \
  ./ "$VM:/opt/sift-mcps/"

# 2b. REAL RUN — only after the dry-run looks right.
sshpass -p "$VMPW" rsync -avz --delete "${RSYNC_EXCLUDES[@]}" \
  -e "ssh -o StrictHostKeyChecking=no" \
  ./ "$VM:/opt/sift-mcps/"
```

**Protect / review before the real run:**
- `--delete` removes anything on the VM not present in source. The dry-run (2a) lists
  every deletion — confirm it only drops stale build output, not a VM-specific file.
- `.venv` and `node_modules` are **excluded**, so they survive; the venv is rebuilt in
  step 3.
- `/cases` (evidence) and `/var/lib/sift/.sift/*` (config: `gateway.yaml`,
  `control-plane.env`, `supabase.env`, `opensearch.env`, `forensic-knowledge.env`) are
  **outside** `/opt/sift-mcps` → untouched by rsync.
- The VM tree carries `install.sh`, `harden.sh`, `configs/`, `docker-compose*.yml`,
  `uv.lock` — all tracked in git, so rsync keeps them in sync (no special handling).

---

## 3. Re-sync the venv (match the VM's real extras — NOT `--all-packages`)

Run as the tree owner (`sansforensics`) from `/opt/sift-mcps`. Avoid `--all-packages`
(it pulls torch/GPU). Reproduce exactly what the VM has — `full` + `windows-triage`:

```bash
$SSH 'cd /opt/sift-mcps && \
  UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never ~/.local/bin/uv sync \
    --extra full --extra windows-triage --group dev \
    --python /usr/bin/python3.12'
```

- `full` = `core` (sift-core, case-dashboard, forensic-knowledge, sift-common,
  sift-gateway) + `opensearch-mcp` + `rag-mcp`. `windows-triage` adds
  `windows-triage-mcp` (registered backend). `dev` matches the pytest-present venv.
- Editable installs mean the rsync'd source is live immediately; `uv sync` only
  reconciles dependencies + console scripts (`/opt/sift-mcps/.venv/bin/sift-gateway`).
- Ensure `sift-service` can still read `/opt/sift-mcps/.venv` after sync (it is the
  service runtime user). If perms drift, fix with the same ownership the tree already
  uses; do not chmod broadly.

---

## 4. Apply DB migrations (idempotent; currently a no-op, but run for reproducibility)

Mechanism (from `install.sh` `apply_db_migrations`): iterate
`supabase/migrations/*.sql` in lexicographic (timestamp) order and execute each via
**psycopg3 with `autocommit=True` + simple-query protocol** (no param binding, so
multi-statement DDL with `;` runs intact). Migrations are idempotent
(`CREATE … IF NOT EXISTS`). Versions already recorded in
`supabase_migrations.schema_migrations` are **skipped** (so re-applying the 21 the VM
already has is silent).

**Safety pre-check (per migration, no commit) — wrap in a transaction and roll back to
syntax-validate without mutating:**

```bash
# Read-only syntax check of a single new migration (rolls back — changes nothing):
$SSH 'DSN=$(sudo grep -hE "^SIFT_CONTROL_PLANE_DSN" /var/lib/sift/.sift/control-plane.env | cut -d= -f2-); \
  /opt/sift-mcps/.venv/bin/python - "$DSN" /opt/sift-mcps/supabase/migrations/<FILE>.sql <<PY
import sys, psycopg
dsn, path = sys.argv[1].strip().strip("\"\x27"), sys.argv[2]
sql = open(path).read()
with psycopg.connect(dsn) as c:      # NOT autocommit
    with c.cursor() as cur:
        cur.execute("begin")
        cur.execute(sql)
        cur.execute("rollback")      # discard — syntax/structure validated only
print("SYNTAX OK (rolled back):", path)
PY'
```

**Apply (reuses the proven install.sh phase — recommended):**

```bash
# install.sh apply_db_migrations is guarded + idempotent + version-skipping.
# Run only the migration phase by invoking the installer in its normal mode, OR run
# the equivalent standalone loop below. The simplest reproducible path is the
# standalone loop (no full reinstall):
$SSH 'DSN=$(sudo grep -hE "^SIFT_CONTROL_PLANE_DSN" /var/lib/sift/.sift/control-plane.env | cut -d= -f2-); \
  /opt/sift-mcps/.venv/bin/python - "$DSN" <<PY
import sys, glob, os, psycopg
dsn = sys.argv[1].strip().strip("\"\x27")
applied = set()
with psycopg.connect(dsn, autocommit=True) as c:
    try:
        applied = {str(r[0]) for r in c.execute(
            "select version from supabase_migrations.schema_migrations").fetchall()}
    except Exception as e:
        print("ledger unavailable (fresh DB):", str(e)[:80])
for f in sorted(glob.glob("/opt/sift-mcps/supabase/migrations/*.sql")):
    ver = os.path.basename(f).split("_", 1)[0]
    if ver in applied:
        print("skip (recorded):", os.path.basename(f)); continue
    with psycopg.connect(dsn, autocommit=True) as c:
        c.execute(open(f).read())
    print("ok:", os.path.basename(f))
PY'
```

Expected on this VM today: all 21 print `skip (recorded)` (no-op). On any future
drift the new `.sql` files apply automatically.

---

## 5. Restart ALL services (system units; sudo via `-S`)

```bash
$SSH 'echo '"$VMPW"' | sudo -S systemctl restart \
  sift-gateway sift-job-worker sift-opensearch-worker@1 sift-opensearch-worker@2'
$SSH 'echo '"$VMPW"' | sudo -S systemctl --no-pager --type=service status \
  sift-gateway sift-job-worker sift-opensearch-worker@1 sift-opensearch-worker@2 | grep -E "Active|●"'
```

---

## 6. Verify

```bash
# 6a. Health OK
curl -s --cacert "$CA" https://192.168.122.81:4508/api/v1/health | head -c 400; echo

# 6b. Portal serves 200
curl -sI --cacert "$CA" https://192.168.122.81:4508/portal/ | grep -E "HTTP/"

# 6c. NEW hardened CSP header present (THE fix) — must show default-src 'none' and NO gstatic/googleapis
curl -sI --cacert "$CA" https://192.168.122.81:4508/portal/ | grep -i content-security-policy
#   EXPECT:
#   content-security-policy: default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline';
#   font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self';
#   frame-ancestors 'none'; object-src 'none'

# 6d. tools_count intact (gateway aggregated tools)
curl -s --cacert "$CA" https://192.168.122.81:4508/api/v1/health | python3 -c 'import sys,json; d=json.load(sys.stdin); print("backends:", list(d.get("backends",{}).keys()))'

# 6e. Active case intact (evidence untouched under /cases)
$SSH 'ls /cases'
```

**Pass criteria:** 6a `status:ok`; 6b `200`; **6c shows the hardened policy (no
`googleapis`/`gstatic`, `default-src 'none'`)**; 6d backends present
(rag/opensearch/windows-triage as before); 6e active case dir still present.

**Rollback:** the previous tree is not auto-backed-up by rsync. To enable rollback,
snapshot before the real run: `$SSH 'sudo cp -a /opt/sift-mcps /opt/sift-mcps.bak-$(date +%F)'`
(then restore that dir + `uv sync` + restart if needed).

---

## Open questions / risks for the operator

1. **venv ownership after `uv sync`.** `uv sync` runs as `sansforensics`; services run
   as `sift-service`. Confirm `sift-service` can read `/opt/sift-mcps/.venv` after the
   sync (it could before). If a fresh venv tightens perms, align ownership before the
   restart.
2. **Code jump is larger than the CSP change.** The VM predates `b995491`, so this
   deploy ships the full D4/D7 gateway refactor + the portal frontend, not just CSP.
   Validate the gateway boots and `tools/list` is healthy (6a/6d) before declaring done.
3. **`--delete` blast radius.** Always run the dry-run (2a) and read the deletion list.
   Any VM-only operational file inside `/opt/sift-mcps` (not in git) would be removed.
4. **No new migrations today** (21/21 recorded). The migration step is a safety no-op;
   it becomes load-bearing only if the source gains `.sql` files beyond the VM ledger.
