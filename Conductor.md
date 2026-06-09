# SIFT Conductor Handoff

Status: active conductor handoff.
Last updated: 2026-06-09 after live portal/MCP repair and VM sync hardening.
Root repo: `/home/yk/AI/SIFTHACK/sift-mcps`
Primary branch: `revamp/spg-v1`

This file is the fast jump-in guide for conductor sessions. It does not replace
the source-of-truth docs. Start here to get oriented, then verify current state
from the referenced files before editing, merging, deploying, or testing.

## Mission

Complete the post-MVP QA and demo-freeze phase for SIFT MCP with the hackathon
theme centered on secure AI-agent autonomy for DFIR.

The product thesis to prove:

- the operator controls cases, evidence, credentials, approvals, report export,
  and custody through the portal;
- the AI agent investigates through Gateway MCP only;
- Gateway enforces auth, active case, scopes, evidence gate, response shaping,
  audit, rate limits, and job enqueue;
- Supabase/Postgres is authority for mutable DFIR state;
- OpenSearch, pgvector RAG, OpenCTI, Windows triage, and forensic knowledge are
  derived/reference planes only;
- agent-visible outputs must stay path-free, secret-free, scoped, concise, and
  provenance-linked.

## Required Reading Order

Every conductor session should read these first:

1. `AGENTS.md`
2. `docs/migration/Migration-Spec.md`
3. `docs/migration/task-batches.md`
4. `docs/migration/Session-Notes.md`
5. `docs/product/README.md`

Then read batch-owned product docs as needed:

- Architecture/journeys: `docs/product/architecture.md`,
  `docs/product/data-flows-and-lifecycles.md`,
  `docs/product/operator-journey.md`,
  `docs/product/ai-agent-journey.md`,
  `docs/product/interaction-model.md`,
  `docs/product/code-structure.md`
- Contracts/autonomy: `docs/product/api-contracts.md`,
  `docs/product/mcp-contracts.md`,
  `docs/product/agent-autonomy-assessment.md`
- Security/freeze: `docs/product/security-architecture.md`,
  `docs/product/security-assessment.md`,
  `docs/product/known-limitations-and-improvements.md`,
  `docs/product/demo-runbook.md`

## Current Repo State

Last verified root merge before the BATCH-AUT1 tracker/session-note commit:

- `11a95f8` - `Merge BATCH-AUT1 agent autonomy assessment`

Completed post-MVP batches:

- BATCH-PQA0 - Post-MVP QA/product documentation operating model
- BATCH-PDOC1 - Product architecture, journeys, lifecycles, and code map
- BATCH-PDOC2 - API, MCP, and interaction contract documentation
- BATCH-SEC1 - Security architecture and assessment baseline
- BATCH-AUT1 - AI agent autonomy and MCP tool-surface assessment

Open batches:

- BATCH-INST1 - Installer and component hardening QA
- BATCH-AUT2 - Demo-case autonomous investigation benchmark
- BATCH-FRZ1 - Final freeze rehearsal, limitations, and demo runbook

Important local note:

- Root `.mcp.json` may exist as local MCP configuration. Treat it as local/user
  state. Do not commit it without explicit review and secret scan.

## AUT1 Integrated State

AUT1 is integrated in root `revamp/spg-v1`.

- Worktree: `/home/yk/AI/SIFTHACK/sift-mcps-aut1`
- Branch: `revamp/postmvp-aut1`
- Worker commit: `3813033` -
  `BATCH-AUT1: live MCP autonomy assessment + job_status error-leak fix`
- Conductor branch commit: `0d27706` -
  `Close AUT1 low-friction tool guidance gaps`
- Root merge: `Merge BATCH-AUT1 agent autonomy assessment`

AUT1 landed changes:

- `docs/product/agent-autonomy-assessment.md`
- `docs/product/mcp-contracts.md`
- `docs/product/ai-agent-journey.md`
- `packages/sift-core/src/sift_core/agent_tools.py`
- `packages/sift-core/src/sift_core/execute/security.py`
- `packages/sift-core/src/sift_core/execute/tools/discovery.py`
- `packages/sift-core/tests/test_execute_executor.py`
- `packages/sift-gateway/src/sift_gateway/job_tools.py`
- `packages/sift-gateway/tests/test_mvp_binding_job_tools.py`

AUT1 reported:

- 17 live MCP calls against `case-v1gate-06081857`
  (`57a06521-c9b8-4654-92ac-42b4f2bb0915`).
- Live-proven tools: `evidence_info`, `capability_guide`, `get_tool_help`,
  `list_existing_findings`, `manage_todo`, `job_status`, `run_command`,
  `run_command_job`.
- Surface scores: Discoverability 2, Sufficiency 2, Context 2,
  Composability 3, Error recovery 2, Provenance 3, Security 3,
  Autonomy friction 2.
- AUT1-B3 fixed in code: malformed `job_status` IDs now return typed
  `invalid_job_id`; durable-job tools return generic `internal_error` for
  unexpected exceptions while logging details server-side.
- AUT1-B4 fixed in the conductor pass: `run_command` and `run_command_job`
  descriptions now distinguish synchronous non-pollable `rc-*` receipts from
  durable pollable UUID jobs.
- AUT1-B5 fixed in the conductor pass: evidence-dir deletion denial now tells
  the agent to hand back to the operator/approved evidence workflow, not to
  leave the MCP harness.
- AUT1-B6 fixed in the conductor pass: `get_tool_help("run_command")` no longer
  contains a static absolute-path example that self-redacts.
- AUT1 validation: gateway job/tool tests, gateway D2/B1 suites, core executor
  tests, migration validators, `git diff --check`, and touched-file
  secret-shape scan passed before merge.

AUT1 open findings:

- AUT1-B1, HIGH, open: `case_info`/`evidence_info` orientation is file-backed
  and can contradict DB-authority evidence gate. Live AUT1 saw orientation say
  unsealed/ok=false while `run_command` executed because DB gate was OK. This is
  a stall trap for autonomous agents.
- AUT1-B2, MEDIUM, open: `rag_search_case` absent from live MCP catalog because
  `rag_query_service` was not wired in that deployment. Agent grounding through
  pgvector RAG was MCP-unreachable.
AUT1 readiness decision:

- AUT2 is conditionally unblocked only if the conductor ensures the demo Gateway
  has `rag_search_case` wired and scoped, and the demo case has file-manifest
  and DB evidence-gate state aligned or AUT1-B1 is fixed.
- AUT1-B3/B4/B5/B6 fixes are unit-proven only until the Gateway is redeployed
  and live re-verified.

## Immediate Conductor Steps

1. Finish this integration commit: root validators, `git diff --check`, secret
   scan, and clean status except local `.mcp.json` if present.
2. Run BATCH-INST1 or an equivalent conductor remediation pass before AUT2 to:
   - redeploy the AUT1-B3/B4/B5/B6 Gateway/core fixes;
   - verify `~/.sift/*.env` permissions;
   - verify per-case `agent_runtime` ACLs;
   - verify Gateway/worker restart and health;
   - verify OpenSearch setup;
   - wire and live-prove `rag_search_case`;
   - verify pgvector RAG corpus availability.
3. Resolve AUT1-B1 before AUT2 or prepare the demo case so DB gate and
   file-backed orientation agree. Prefer a real fix over case grooming if time
   allows.
4. Launch BATCH-AUT2 only when the agent can investigate the selected demo case
   through MCP alone, without hidden curl/shell/DB/OpenSearch side channels.

## Mandatory Live Sync Rule

For any fix that can affect live portal, Gateway, worker, MCP, installer,
OpenSearch, RAG, or evidence behavior, the conductor owns deployment. Do not end
the session with "user must sync manually" as the next step.

Required closeout after each live-impacting fix:

1. Sync the root repo to the active VM service tree.
2. Refresh dependencies only when source/dependency/setup changes require it.
3. Restart `sift-gateway.service` and `sift-job-worker.service`.
4. Prove both services are active and Gateway health is OK.
5. Run the smallest live smoke that matches the fix: portal login/reauth,
   per-file evidence verify, MCP initialize/tools list, RAG call, job poll, or
   installer replay.
6. Record sanitized results in `Session-Notes.md` when the live behavior or
   operational procedure changed.

The active systemd unit currently runs from
`/home/sansforensics/sift-mcps-test`. Always verify the active tree before sync:

```bash
sshpass -e ssh -o StrictHostKeyChecking=no "${SIFT_VM}" \
  "systemctl --user show -p WorkingDirectory --value sift-gateway.service"
```

Do not use the stale sibling checkout as source of truth for live service
behavior.

## Live VM References

Do not store raw secrets in this file.

- VM host/user: `192.168.122.81` / `sansforensics`
- Portal/Gateway: `https://192.168.122.81:4508/portal/`
- MCP endpoint: `https://192.168.122.81:4508/mcp`
- Deployed repo on VM: `~/sift-mcps-test`
- VM Python: `/usr/bin/python3.12`
- Required VM env discipline:
  - `UV_NO_MANAGED_PYTHON=1`
  - `UV_PYTHON_DOWNLOADS=never`
- User-level services:
  - `sift-gateway.service`
  - `sift-job-worker.service`

Use local environment variables for passwords/tokens when live testing. Do not
write them into repo files, docs, prompts, screenshots, or logs.

## Live Operations Runbook

This runbook is for conductor diagnostics, installer QA, and pre-AUT2
remediation. It is allowed to reference VM-local secret file paths and shell
variable names. It is not allowed to paste raw passwords, JWTs, DSNs,
service-role keys, OpenSearch credentials, or private keys into tracked files.

Credential handling:

- Put the VM SSH password in a local host environment variable only:
  `export SSHPASS='<test VM password from local secure channel>'`.
- Put portal smoke credentials in local or VM shell variables only:
  `export SIFT_PORTAL_EMAIL='<operator email>'` and
  `export SIFT_PORTAL_PASSWORD='<operator password>'`.
- Source service credentials only on the VM:
  `set -a; . ~/.sift/control-plane.env; set +a`.
- Agent tokens, if needed for manual MCP client configuration, stay in
  VM-local files such as `~/.sift/agent-token.txt` or local shell variables.
- If a command prints secrets, redirect or redact the output before adding it to
  notes. Store only pass/fail, counts, service status, and sanitized errors.

Host-to-VM sync:

```bash
export SSHPASS='<set locally; do not commit>'
export SIFT_VM='sansforensics@192.168.122.81'
export SIFT_REMOTE_DIR='/home/sansforensics/sift-mcps-test'

rsync -az --no-owner --no-group --info=progress2 \
  -e 'sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null' \
  --exclude '.git/' \
  --exclude '.venv/' \
  --exclude '__pycache__/' \
  --exclude '*.pyc' \
  --exclude '.mcp.json' \
  --exclude 'packages/case-dashboard/frontend/node_modules/' \
  /home/yk/AI/SIFTHACK/sift-mcps/ \
  "${SIFT_VM}:${SIFT_REMOTE_DIR}/"
```

Do not add `--delete` during normal test/dev sync. The VM holds large downloaded
forensic RAG packages, model/cache artifacts, and local diagnostic files that
must not be removed by routine source deployment. Use an explicit reset plan
only when the session is intentionally rebuilding the VM checkout.

VM command wrapper:

```bash
sshpass -e ssh -o StrictHostKeyChecking=no "${SIFT_VM}" '<command>'
```

VM dependency refresh after sync:

```bash
cd /home/sansforensics/sift-mcps-test
export UV_NO_MANAGED_PYTHON=1
export UV_PYTHON_DOWNLOADS=never
~/.local/bin/uv sync --extra full --group dev \
  --python /usr/bin/python3.12 \
  --no-managed-python \
  --no-python-downloads
```

Gateway and worker restart:

```bash
systemctl --user daemon-reload
systemctl --user restart sift-gateway.service sift-job-worker.service
systemctl --user --no-pager --full status sift-gateway.service sift-job-worker.service
curl -sk https://localhost:4508/api/v1/health | python3 -m json.tool
journalctl --user -u sift-gateway.service -u sift-job-worker.service -n 120 --no-pager
```

If the Gateway catalog is stale after a backend, RAG, scope, or env change,
restart the Gateway. MCP tool registration is startup-bound.

Standard full sync/restart/health block from the host:

```bash
export SSHPASS='<set locally; do not commit>'
export SIFT_VM='sansforensics@192.168.122.81'
export SIFT_REMOTE_DIR='/home/sansforensics/sift-mcps-test'

# If frontend source changed, build static assets before rsync.
npm --prefix /home/yk/AI/SIFTHACK/sift-mcps/packages/case-dashboard/frontend run build

rsync -az --no-owner --no-group --info=progress2 \
  -e 'sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null' \
  --exclude '.git/' \
  --exclude '.venv/' \
  --exclude '__pycache__/' \
  --exclude '*.pyc' \
  --exclude '.mcp.json' \
  --exclude 'packages/case-dashboard/frontend/node_modules/' \
  /home/yk/AI/SIFTHACK/sift-mcps/ \
  "${SIFT_VM}:${SIFT_REMOTE_DIR}/"

sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "${SIFT_VM}" "
set -euo pipefail
cd '${SIFT_REMOTE_DIR}'
export UV_NO_MANAGED_PYTHON=1
export UV_PYTHON_DOWNLOADS=never
python3 -m py_compile packages/case-dashboard/src/case_dashboard/routes.py
systemctl --user daemon-reload
systemctl --user restart sift-gateway.service sift-job-worker.service
systemctl --user is-active sift-gateway.service sift-job-worker.service
curl -sk https://127.0.0.1:4508/api/v1/health | python3 -m json.tool
journalctl --user -u sift-gateway.service -u sift-job-worker.service \
  --since '5 minutes ago' --no-pager |
  grep -Ei 'ERROR|WARNING|Traceback|Exception|failed' || true
"
```

Use dependency refresh before restart when Python dependencies, package entry
points, install scripts, extras, lockfiles, or generated package metadata
changed. Keep VM Python pinned and avoid managed downloads:

```bash
sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "${SIFT_VM}" "
set -euo pipefail
cd '${SIFT_REMOTE_DIR}'
export UV_NO_MANAGED_PYTHON=1
export UV_PYTHON_DOWNLOADS=never
~/.local/bin/uv sync --extra full --group dev \
  --python /usr/bin/python3.12 \
  --no-managed-python \
  --no-python-downloads
"
```

If proxy downloads are needed later and `uv sync` removed SOCKS helpers, restore
them in the VM venv without deleting downloaded packages:

```bash
sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "${SIFT_VM}" "
cd '${SIFT_REMOTE_DIR}'
~/.local/bin/uv pip install --python .venv/bin/python PySocks socksio
"
```

Portal login + HMAC confirmation smoke from the host:

```bash
export SIFT_PORTAL_EMAIL='<operator email>'
export SIFT_PORTAL_PASSWORD='<operator password>'

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -sk --max-time 8 -c "$tmp/cj" -o "$tmp/login.json" \
  -H 'Content-Type: application/json' \
  --data "$(python3 - <<'PY'
import json, os
print(json.dumps({
  "email": os.environ["SIFT_PORTAL_EMAIL"],
  "password": os.environ["SIFT_PORTAL_PASSWORD"],
}))
PY
)" \
  https://192.168.122.81:4508/portal/api/auth/login
curl -sk --max-time 8 -b "$tmp/cj" -o "$tmp/challenge.json" \
  https://192.168.122.81:4508/portal/api/evidence/chain/challenge
python3 - "$tmp/challenge.json" "$tmp/body.json" <<'PY'
import hashlib, hmac, json, os, sys
challenge = json.load(open(sys.argv[1]))
derived = hashlib.pbkdf2_hmac(
    "sha256",
    os.environ["SIFT_PORTAL_PASSWORD"].encode(),
    bytes.fromhex(challenge["salt"]),
    int(challenge["iterations"]),
).hex()
response = hmac.new(bytes.fromhex(derived), challenge["nonce"].encode(), "sha256").hexdigest()
json.dump({"challenge_id": challenge["challenge_id"], "response": response}, open(sys.argv[2], "w"))
PY
curl -sk --max-time 20 -b "$tmp/cj" \
  -H 'Content-Type: application/json' \
  --data @"$tmp/body.json" \
  https://192.168.122.81:4508/portal/api/evidence/chain/verify-hmac |
  python3 -m json.tool
```

Fresh agent principal + MCP catalog smoke from the VM. This stores token
material only in VM-local `~/.sift` files:

```bash
sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "${SIFT_VM}" "
set -euo pipefail
tmp=\$(mktemp -d)
trap 'rm -rf \"\$tmp\"' EXIT
umask 077
label=\"codex-live-\$(date -u +%m%d%H%M%S)\"
curl -sk --max-time 8 -c \"\$tmp/cj\" -o \"\$tmp/login.json\" \
  -H 'Content-Type: application/json' \
  --data \"{\\\"email\\\":\\\"\${SIFT_PORTAL_EMAIL:?}\\\",\\\"password\\\":\\\"\${SIFT_PORTAL_PASSWORD:?}\\\"}\" \
  https://127.0.0.1:4508/portal/api/auth/login
python3 - \"\$label\" \"\$tmp/body.json\" <<'PY'
import json, sys
json.dump({\"kind\":\"agent\",\"display_name\":sys.argv[1],\"tool_scopes\":[\"mcp:*\"]}, open(sys.argv[2], \"w\"))
PY
curl -sk --max-time 20 -b \"\$tmp/cj\" -o \"\$tmp/principal.json\" \
  -H 'Content-Type: application/json' \
  --data @\"\$tmp/body.json\" \
  https://127.0.0.1:4508/portal/api/auth/principals
python3 - \"\$tmp/principal.json\" <<'PY'
import json, os
data=json.load(open(__import__('sys').argv[1]))
os.makedirs(os.path.expanduser('~/.sift'), exist_ok=True)
json.dump(data, open(os.path.expanduser('~/.sift/codex-agent-session.json'), 'w'), indent=2)
open(os.path.expanduser('~/.sift/agent-token.txt'), 'w').write(str(data.get('access_token') or ''))
os.chmod(os.path.expanduser('~/.sift/codex-agent-session.json'), 0o600)
os.chmod(os.path.expanduser('~/.sift/agent-token.txt'), 0o600)
print({k:data.get(k) for k in ['ok','principal_type','principal_id','display_name','default_case_id','expires_at']})
PY
"
```

Then prove the fresh token can initialize MCP and see the demo-critical catalog:

```bash
sshpass -e ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "${SIFT_VM}" "
set -euo pipefail
tmp=\$(mktemp -d)
trap 'rm -rf \"\$tmp\"' EXIT
tok=\$(cat ~/.sift/agent-token.txt)
init=\$(curl -sk --max-time 10 -D \"\$tmp/h\" -o \"\$tmp/init.json\" \
  -w '%{http_code}' \
  -H \"Authorization: Bearer \$tok\" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{},\"clientInfo\":{\"name\":\"sift-live-check\",\"version\":\"1\"}}}' \
  https://127.0.0.1:4508/mcp/)
sid=\$(awk 'tolower(\$1)==\"mcp-session-id:\" {print \$2}' \"\$tmp/h\" | tr -d '\r' | tail -1)
list=\$(curl -sk --max-time 10 -o \"\$tmp/list.json\" -w '%{http_code}' \
  -H \"Authorization: Bearer \$tok\" \
  -H \"mcp-session-id: \$sid\" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}' \
  https://127.0.0.1:4508/mcp/)
printf 'initialize_http=%s\ntools_list_http=%s\n' \"\$init\" \"\$list\"
python3 - \"\$tmp/list.json\" <<'PY'
import json, sys
raw = open(sys.argv[1]).read()
if raw.startswith('event:'):
    raw = '\n'.join(line[5:].strip() for line in raw.splitlines() if line.startswith('data:'))
obj = json.loads(raw)
tools = obj.get('result', {}).get('tools', [])
names = [tool.get('name') for tool in tools]
print({'tools_count': len(names), 'has_rag_search_case': 'rag_search_case' in names, 'has_run_command_job': 'run_command_job' in names})
print(names)
PY
"
```

Installer/setup QA:

```bash
cd /home/sansforensics/sift-mcps-test
bash -n install.sh
UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never ./install.sh
UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never ./install.sh
stat -c '%a %U %G %n' ~/.sift/*.env
systemctl --user list-unit-files 'sift-*'
```

The second installer run is the idempotency check. Expected sensitive-file mode
is `600` for `~/.sift/*.env`.

Agent runtime ACL QA:

```bash
cd /home/sansforensics/sift-mcps-test
sudo scripts/setup-agent-runtime.sh \
  --runtime-user agent_runtime \
  --service-user sansforensics \
  --cases-root /cases \
  --state-root /var/lib/sift
getfacl -p /cases | sed -n '1,80p'
getfacl -p /var/lib/sift | sed -n '1,80p'
```

For a prepared case, confirm `agent_runtime` has read/traverse access to sealed
evidence and write access only to `agent/`, `extractions/`, and `tmp/`, while
authority files and `/var/lib/sift` remain denied.

OpenSearch check:

```bash
set -a; . ~/.sift/control-plane.env; set +a
curl -sk -u "${OPENSEARCH_USERNAME}:${OPENSEARCH_PASSWORD}" \
  "${OPENSEARCH_URL:-https://localhost:9200}/_cluster/health?pretty"
```

Single-node `yellow` is acceptable for the demo if indexing/search works.

RAG download/import repair:

```bash
cd /home/sansforensics/sift-mcps-test
set -a; . ~/.sift/control-plane.env; set +a
export UV_NO_MANAGED_PYTHON=1
export UV_PYTHON_DOWNLOADS=never

~/.local/bin/uv run --project . --extra full \
  --python /usr/bin/python3.12 \
  --no-managed-python \
  --no-python-downloads \
  python -m rag_mcp.scripts.download_index

SIFT_CONTROL_PLANE_DSN="${SIFT_CONTROL_PLANE_DSN}" \
~/.local/bin/uv run --project . --extra full \
  --python /usr/bin/python3.12 \
  --no-managed-python \
  --no-python-downloads \
  rag-mcp-import-chroma-pgvector \
  --chroma-dir packages/forensic-rag-mcp/data/chroma
```

If the VM needs the host proxy for the RAG release or model cache, keep a host
terminal open with a reverse tunnel:

```bash
sshpass -e ssh -N \
  -o ExitOnForwardFailure=yes \
  -o StrictHostKeyChecking=no \
  -R 10809:127.0.0.1:10808 \
  "${SIFT_VM}"
```

Then run the VM download/import commands with:

```bash
export HTTPS_PROXY='socks5h://127.0.0.1:10809'
export HTTP_PROXY='socks5h://127.0.0.1:10809'
```

If the Python stack reports missing SOCKS support during download diagnostics:

```bash
cd /home/sansforensics/sift-mcps-test
~/.local/bin/uv pip install --python .venv/bin/python PySocks socksio
```

RAG DB count proof:

```bash
cd /home/sansforensics/sift-mcps-test
set -a; . ~/.sift/control-plane.env; set +a
UV_NO_MANAGED_PYTHON=1 UV_PYTHON_DOWNLOADS=never \
~/.local/bin/uv run --project . --extra full \
  --python /usr/bin/python3.12 \
  --no-managed-python \
  --no-python-downloads \
  python - <<'PY'
import os
import psycopg

queries = {
    "total_chunks": "select count(*) from app.rag_chunks",
    "kind_case_counts": """
        select kind, count(*) as chunks, count(case_id) as case_bound
        from app.rag_chunks
        group by kind
        order by kind
    """,
    "seed_sources": """
        select coalesce(metadata->>'seed_source', '<unset>') as seed_source,
               count(*) as chunks
        from app.rag_chunks
        group by 1
        order by chunks desc
    """,
}

with psycopg.connect(os.environ["SIFT_CONTROL_PLANE_DSN"]) as conn:
    with conn.cursor() as cur:
        for name, sql in queries.items():
            cur.execute(sql)
            print(name, cur.fetchall())
PY
```

Expected full-corpus proof is approximately the BATCH-V1/B-MVP-18 baseline:
`app.rag_chunks=26586`, all shared rows `kind='knowledge'`, `case_id NULL`, and
`22268` rows from `seed_source='chroma_release_pgvector'`. Drift from that
baseline must be explained before AUT2.

RAG catalog proof:

- Gateway startup wires `rag_search_case` only when `SIFT_CONTROL_PLANE_DSN` is
  available and `PgVectorRagQueryService` initializes successfully.
- If `rag_search_case` is absent from the MCP catalog, check
  `journalctl --user -u sift-gateway.service` for `RAG query service init
  failed`, verify `~/.sift/control-plane.env`, rerun the full dependency sync,
  and restart the Gateway.
- Agent-facing proof must be a direct Gateway MCP `list_tools` and
  `rag_search_case` call through the configured MCP client. Curl, SQL, SSH, and
  local source reads are diagnostics only and do not count for autonomy.

AUT1-B1 evidence-orientation gate:

- DB authority is `app.evidence_gate_status`; Gateway policy uses
  `check_evidence_gate_db`.
- Before AUT2, `case_info` and `evidence_info` must not tell the agent a case is
  unsealed when DB policy allows execution.
- If orientation and DB gate disagree, either fix the Gateway/core orientation
  path to use DB-active evidence status or prepare the demo case through the
  portal register/seal/verify path so file manifest and DB gate agree.

## MCP Autonomy Rules

When assessing AI-agent autonomy:

- Only calls made through configured Gateway MCP count as agent capability.
- Curl, SSH, shell, direct DB, direct OpenSearch, local filesystem, and source
  reads are diagnostics only and must be labeled as diagnostics.
- Diagnostics may explain a failure, but they do not prove agent autonomy.
- If the agent needs side-channel help to proceed, record that as an autonomy
  defect.
- Context bloat, vague errors, missing recovery hints, missing provenance, and
  contradictory tool state are product defects.
- Real evidence benchmark should be portal-prepared, sealed, and handed to the
  agent only through MCP credentials and a case brief.

## Batch Graph From Here

Recommended path:

1. Run BATCH-INST1 or conductor remediation for live deploy/readiness,
   especially AUT1-B2 and live re-verification of AUT1-B3/B4/B5/B6.
2. Fix or operationally neutralize AUT1-B1.
3. Run BATCH-AUT2 against the hackathon E01/raw-memory demo case through MCP
   only.
4. Run BATCH-FRZ1 final freeze, limitations, improvement backlog, and demo
   runbook.

Parallelism:

- AUT2 should be serial after BATCH-INST1/readiness and the B1/B2 gates are
  handled.
- FRZ1 is last.

## Validation Commands

Baseline validation for conductor docs/governance changes:

```bash
python3 scripts/validate_docs.py
python3 scripts/validate_migration_docs.py
git diff --check
```

Targeted AUT1 validation:

```bash
uv run pytest packages/sift-gateway/tests/test_mvp_binding_job_tools.py
uv run pytest packages/sift-gateway/tests/test_mvp_d2_jobs_and_authority.py packages/sift-gateway/tests/test_mvp_b1_policy_redaction.py
uv run pytest packages/sift-core/tests/test_execute_executor.py
```

Docs secret-shape scan pattern:

```bash
rg -n "postgres(ql)?://|service_role\s*[:=]|anon_key\s*[:=]|password\s*[:=]|BEGIN (RSA|OPENSSH|PRIVATE)|sk-[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]{20,}" docs Conductor.md
```

## Standing Constraints

- Do not use stale K2-K5 or V1 worker directories as source of truth.
- Use clean worktrees from `revamp/spg-v1` for remaining batches.
- Parallel worker branches do not edit `docs/migration`; conductor updates
  tracker/session notes after integration.
- Keep implementation changes tightly scoped.
- Do not revert unrelated user or worker changes.
- Do not commit local MCP config or secrets.
- Product docs may be expanded under `docs/product/**`; migration state remains
  in the three-file `docs/migration` model only.
