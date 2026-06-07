# PR02 Token Registry Checks

PR02 implements Phase ID-2 only: DB-first hash-only MCP/service token
validation with legacy `gateway.yaml api_keys` fallback. It does not implement
Supabase human auth, active-case propagation, jobs, workers, evidence changes,
OpenSearch changes, parser changes, or frontend redesigns.

## Host Checks

Run from the repository root:

```bash
.venv/bin/python -m pytest packages/sift-gateway/tests/test_phase13_auth.py
.venv/bin/python -m pytest packages/case-dashboard/tests/test_token_lifecycle.py
git diff --check
```

## SIFT VM Checks

Sync the host workspace to the VM:

```bash
rsync -avz --exclude '.git' --exclude '.venv' --exclude '__pycache__' --exclude '*.pyc' \
  /home/yk/AI/SIFTHACK/sift-mcps/ sansforensics@192.168.122.81:~/sift-mcps-test/
```

Install only the core/dev dependency set with the system Python:

```bash
cd ~/sift-mcps-test
UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never \
  ~/.local/bin/uv sync --extra core --group dev --python /usr/bin/python3.12
```

Verify imports and run the targeted suites:

```bash
.venv/bin/python --version
.venv/bin/python - <<'PY'
import yaml
import mcp
import sift_core
import sift_gateway
print("imports_ok")
PY
.venv/bin/python -m pytest packages/sift-gateway/tests/test_phase13_auth.py
.venv/bin/python -m pytest packages/case-dashboard/tests/test_token_lifecycle.py
```

## Optional Supabase Syntax Check

PR02 does not add a schema migration. To re-check the PR01 schema against the
VM Supabase/Postgres stack without leaving tables behind:

```bash
cd ~/supabase-project
(printf "begin;\n"; cat ~/sift-mcps-test/supabase/migrations/202606070101_identity_foundation.sql; printf "\nrollback;\n") \
  | docker compose exec -T db psql -U postgres -d postgres -v ON_ERROR_STOP=1
```
