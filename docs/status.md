# SIFT Sprint — Active Work & Open Decisions

_Last updated: 2026-06-11. Single source for everything requiring action or a decision._
_Companion to `docs/migration/task-batches.md` (batch definitions) and `docs/migration/Session-Notes.md` (change log)._

---

## Wave Execution Order

1. ~~**Cleanup wave — run BEFORE fresh install** — NW1 ∥ NW2 ∥ NW3 ∥ NW4~~ — **DONE, landed on local `main` 2026-06-11** (4 parallel workers, 0 merge conflicts, integrated sweep green; doc log `1dadb03`). **Not yet pushed** — local `main` is 12 commits ahead of `origin/main`; operator pushes manually.
2. **Fresh VM install + end-to-end gate** — operator runs `./install.sh` on bare SIFT VM (zero-argument; OpenCTI auto-detected, windows-triage removed in NW2) → satisfies PMI4 and OS6, **and now also proves BATCH-HARD1** (non-admin `sift-service` cutover + shared vol3 symbol cache — host code landed 2026-06-11). _Fresh VM ready (`192.168.122.81`, host key reset); repo to be rsynced to `/opt/sift-mcps`._
3. **PTC enablement** — NW6 after install proves `opensearch_*` + `kb_*` tools are live
4. **FRZ1 close-out** — remaining demo-prep items after the full stack is proven on VM

> **What can proceed now WITHOUT a fresh VM** is collected in [§ Host-Only Work Available Now](#host-only-work-available-now-no-fresh-vm) below — Wave 1 already landed; the fresh-VM gate (PMI4/OS6) is not the only thing left to do.

---

## Host-Only Work Available Now (No Fresh VM)

The fresh-VM gate (PMI4/OS6) is blocked until a clean VM exists, but a meaningful amount of work
needs **no VM at all** (pure host: code + targeted tests + docs) or only the **existing** (non-fresh)
VM. Ranked by value/independence:

| # | Work | Needs | Source |
|---|------|-------|--------|
| 1 | **Progress-stderr filtering** — strip `\r` `vol`-style progress spam from durable-job `result_public` stderr in the worker. Small, self-contained, explicitly "can be done before PMI4". | Host code + sift-core targeted tests | FRZ1 item 2 |
| 2 | **FRZ1 demo-runbook + known-limitations docs** — draft `docs/product/demo-runbook.md` and `docs/product/known-limitations-and-improvements.md` from known steps; refine after VM proof. | Host docs only | FRZ1 scope |
| 3 | **Offline Volatility symbol pre-warm — packaging half** — pre-stage/package ISF symbols in the repo/installer so a fresh VM's first `vol windows.info` isn't slow/failing. The packaging + installer wiring is host work; only the live timing proof needs a VM. | Host installer code (live proof deferred) | FRZ1 item 1 |
| 4 | **Non-admin service-user cutover — code half** — add the dedicated non-admin service user + drop the blanket `NOPASSWD: ALL` in `install.sh` / systemd units / sudoers. The wiring is host work; live enforcement proof needs a VM. | Host installer/systemd code (live proof deferred) | FRZ1 item 4 |
| 5 | **NW1 existing-deployment re-hash migration** — NW1 documented (did not write) the re-hash pass existing deployments need now that the hash widened to 19 keys. Write it. | Host SQL/script (apply needs a DB) | NW1 carry-forward |
| 6 | **NW4 old-overload drop migration** — append-only migration to `DROP` the now-revoked 9-arg `app.rag_search` overload once callers are confirmed migrated. | Host SQL (apply needs a DB) | NW4 carry-forward |
| 7 | **NW6 design / harness-conversion (non-live half)** — decide + implement how the agent-runtime converts Gateway/MCP tool defs into Messages-API defs with `code_execution` + `allowed_callers` opt-in. Only the live context-savings measurement needs live `opensearch_*`. | Host code/design | NW6 step 1–2 |
| 8 | **Code review / hardening of the landed wave** — `/code-review` the NW Wave-1 diff; broader host test sweeps beyond the lean per-batch targets. | Host only | quality |

**Uses the EXISTING (non-fresh) VM — possible but not a fresh-install proof:** deploy the landed wave
via `rsync` + service restart and smoke-test it; live portal click-proofs (re-acquisition FRZ1 item 5,
approval/report export FRZ1 item 6) once the operator password is reconciled; NW6 live validation
against the already-present `opensearch_*` tools.

**Genuinely BLOCKED on a fresh VM:** PMI4 destructive-install idempotency (FRZ1 item 3), OS6
no-restart-after-fresh-seed proof, `status:ok`-from-bare-install.

---

## Open Batches

### BATCH-HARD1 — Non-admin `sift-service` cutover + shared vol3 symbol cache — HOST CODE DONE, pending VM proof

Host code landed (uncommitted working tree) 2026-06-11; full detail in `task-batches.md` + `Session-Notes.md`.
4-stream team build (3 distributed + installer/systemd lead-owned), `/security-review` PASS,
`/code-review` (recall) caught + fixed a HIGH deny-ACL bug. Tests 13+85 green; validators OK; `git diff --check` clean.

| Group | Outcome |
|-------|---------|
| A — shared vol3 symbol cache | `parse_memory` + `worker` resolve `SIFT_VOL_SYMBOLS` → `/var/cache/sift/volatility-symbols` (relocated out of the `/var/lib/sift` deny-ACL sweep; default `g:sift:rwx`); `/opt/volatility3` chmod hack dropped. |
| B — non-admin cutover | gateway+worker = **system** services as `sift-service`; secrets → `sift-service:0600` under `/var/lib/sift/.sift`; deploy tree → `/opt/sift-mcps`; two narrow sudoers grants only; `systemctl --user`→system across installer + helpers; AppArmor updated (`/var/cache/sift`, hayabusa exec path). |
| C — docs | install command de-staled, VM quick-ref → `/opt/sift-mcps` + `sudo systemctl`, this batch logged. |

**VM proof (folds into PMI4/OS6):** `systemctl show sift-gateway -p User` = `sift-service`; `status:ok`; `run_command` vol3 warms `/var/cache/sift/volatility-symbols`; no-restart `opensearch_*`.
**Two items to eyeball on VM:** snapshots dir (`uid 1000`, no runtime writer found); hayabusa reachability under `agent_runtime`.

---

### NW Wave 1 (NW1–NW4) — DONE

Landed on local `main` 2026-06-11; full per-batch detail in `task-batches.md` + `Session-Notes.md`.

| Batch | Commit | Outcome |
|-------|--------|---------|
| NW1 compute_content_hash consolidation | `a9602f0` | Single `investigation_store` authority; narrow copies removed; test proves all sites hash identically. Carry-forward: existing-deployment re-hash migration (documented, not written → Host-Only #5). |
| NW2 remove windows-triage-mcp + decouple enrich-triage | `77dfb58` | Package deleted (32 files); `opensearch_enrich_triage`/`triage_remote` removed; golden regen; grep-proven no live importers. Conductor follow-up `c32a291` cleaned the stale `_RELATED_TOOLS` hint. |
| NW3 Add-on Backend Contract doc | `a200f66` | `docs/backend-contract.md` (manifest schema + lifecycle + worked example). |
| NW4 RAG knowledge-only | `068e5c6` | Migration `202606111200_rag_knowledge_only.sql` + DB triggers block `kind='derived'`. Carry-forward: drop old 9-arg overload (→ Host-Only #6). |

---

### BATCH-FRZ1 — Final freeze rehearsal, limitations, and demo runbook

**Status: IN_PROGRESS** — most of the work is done; specific items below remain open.

**Already proven live:**
- Services healthy (`sift-gateway` + `sift-job-worker` active), 13-tool catalog present
- `case_info` / `evidence_info` DB-backed aligned to `manifest_version=4`
- RAG corpus available (`app.rag_chunks=26586`)
- Bounded Volatility / E01 checks work via `run_command` with sealed `evidence_refs`
- Portal login, HMAC re-auth, fresh portal-issued agent TTL (172800 s / 48 h) live-proven
- Settings table UX: Supabase JWT token type, TTL remaining, revoke button — source-fixed and live-deployed
- `rag_search_case` replaced by `kb_*` tools; `tools/list` confirms 13 tools callable
- Installer hardening landed: `rg`, post-`uv sync` `pyewf` relink, worker unit install/restart, sudoers wiring

**Remaining open items** (tagged by VM dependency — see [Host-Only Work](#host-only-work-available-now-no-fresh-vm)):

1. **Offline Volatility symbol packaging / pre-warm** _(host packaging now; live proof needs VM)_ —
   operator-requested. Volatility downloads/generates ISF symbols live; a fresh VM has no cache, making
   `vol windows.info` slow or fail on first run. Options: pre-package symbols in repo/installer, or
   document a pre-warm runbook step.

2. **Progress-stderr filtering** _(host code now)_ — `vol` and similar tools emit `\r`-separated progress
   spam into durable-job `result_public` stderr (capped at 4 KB but noisy). A worker-side filter cleans
   this for agent context. Small change; can be done before or after PMI4.

3. **Throwaway-VM destructive install idempotency proof** _(BLOCKED — needs fresh VM)_ — `./install.sh`
   was not destructively replayed on a fresh throwaway VM. Done as part of PMI4.

4. **Non-admin service-user cutover** _(host code now; live enforcement needs VM)_ — gateway/worker still
   runs as `sansforensics` (blanket `ALL=(ALL) NOPASSWD: ALL`). The narrow `sift-ingest-mount` sudoers
   rule is deployed but masked by the blanket grant. Enforcement requires a dedicated non-admin service
   user and removal of the blanket grant.

5. **Re-acquisition click proof** _(needs existing VM + current operator password)_ — portal Evidence-tab
   Re-seal/Retire actions are unit-proven and deployed but not click-proven live (operator password
   drifted from `~/.sift`).

6. **Approval / report export live proof** _(needs existing VM + current operator password)_ — if the
   final demo script requires the full approval/report-export path live-proven (beyond AUT2 on
   2026-06-09).

**Scope:** `docs/product/demo-runbook.md`, `docs/product/known-limitations-and-improvements.md`,
`docs/product/README.md`, `docs/migration/task-batches.md`, `docs/migration/Session-Notes.md`

**Acceptance:** Demo runbook executable without hidden side-channel steps; known limitations
explicit and bounded; `python3 scripts/validate_docs.py` passes.

---

### BATCH-OS6 — Live VM OpenSearch proof

**Status: OPEN — BLOCKED on fresh VM** — all code done (OS1–OS5 landed); this is the VM smoke gate only.
**Runs as part of PMI4 (the bare-SIFT install run).**

**What to do:**
- After install, confirm aggregate `/mcp tools/list` includes `opensearch_*` **without a restart**
  (OSX1 race fix: seed runs before gateway starts)
- Confirm `app.rag_chunks` == ~26,586 (full Chroma bundle; NOT the small seed)
- Confirm Hayabusa detections queryable
- Run one read-only OpenSearch path + one sealed-evidence ingest job on the Rocba case
- Record command-level proof in `Session-Notes.md`

**Acceptance:** Live aggregate MCP shows `opensearch_*` tools callable; search/ingest uses DB
active case and sealed evidence only; no path/DSN/credential leakage.

---

### BATCH-PMI4 — VM proof: bare-SIFT → live stack → Rocba case run

**Status: OPEN — BLOCKED on fresh VM** — operator-run; the ONLY full end-to-end gate.
**Run after NW1/NW2/NW3/NW4 land (done) so the clean install is tested.**

**Steps:**
1. Bare SIFT VM: `./install.sh` (zero-argument; OpenCTI auto-detected, windows-triage removed in NW2)
2. Confirm `status:ok` (not degraded), job-worker not crash-looping
3. Confirm aggregate `/mcp` lists `opensearch_*` + `kb_*` tools after post-seed (no restart needed)
4. Confirm `app.rag_chunks` populated with full corpus (~26,586)
5. Confirm Hayabusa detections queryable
6. Portal: create case → issue agent token → register+seal Rocba disk+RAM evidence → agent end-to-end
7. Record command-level proof in `Session-Notes.md`

---

### BATCH-NW6 — Programmatic Tool Calling: enable + native-harness validation

**Status: OPEN — design/code half doable on host now; live validation needs live `opensearch_*`.**
Full batch definition + paste-ready prompt in `task-batches.md`.

**Context:** PTC runs CLIENT-SIDE in the agent harness (not on the VM). The Messages-API
`code_execution` tool + `allowed_callers:["code_execution_20250825"]` on opt-in tools lets the agent
write code that calls OpenSearch tools and filters/transforms/pipes results locally so large OS query
results never flood context. Security posture already satisfied: Gateway sanitizes all results
(proven live — `case_dir: "[REDACTED:absolute_path]"`). OSX2's per-tool `defer_loading` / advanced
metadata is the eligibility signal.

**Target tools:** `opensearch_search`, `opensearch_aggregate`, `opensearch_timeline`,
`opensearch_count`, `opensearch_field_values`, `kb_*`.

**Note:** On-VM Python sandbox (former OSX4) is a FALLBACK only if client-side PTC is rejected for
posture reasons.

---

## Backlog Items (require future decision or are deferred)

| ID | Item | Status | Notes |
|----|------|--------|-------|
| B-MVP-OS35-SEC | Post-MVP: evaluate enabling OpenSearch 3.5 security plugin (TLS + admin password + https client) | OPEN | MVP boundary is `DISABLE_SECURITY_PLUGIN=true` + loopback `:9200`; enabling security is post-demo |
| B-MVP-RAG-DERIVED | Per-case RAG ingest (case-derived text in vector store) | REJECTED → DONE via NW4 | Operator won't-do; NW4 hardened to knowledge-only + DB triggers (landed `068e5c6`) |
| B-MVP-HASH-REHASH | Re-hash pass for existing deployments after NW1 hash widening | OPEN | Migration documented in NW1, not written; Host-Only #5 |
| B-MVP-RAG-DROP-OVERLOAD | Drop revoked 9-arg `app.rag_search` overload once callers confirmed migrated | OPEN | NW4 carry-forward; Host-Only #6 |
| OSX4 / on-VM Python sandbox | Dedicated `opensearch_query_code` tool with network-jailed interpreter on VM | DEFERRED | Only needed if NW6 client-side PTC is rejected for posture reasons |

---

## Resolved Decisions — Do Not Re-open

These were open forks or backlog items now settled. Listed here to prevent a fresh session
re-litigating them.

- **B-MVP-HASH-CONSOLIDATION → NW1 → LANDED** (`a9602f0`; single `investigation_store` authority)
- **B-MVP-WINTRIAGE-SCRIPTS → NW2 → LANDED** (`77dfb58`; package removed, enrich-triage decoupled)
- **NW3 Backend Contract doc → LANDED** (`a200f66`)
- **F-MVP-RAG-DERIVED → REJECTED → NW4 LANDED** (`068e5c6`; knowledge-only + DB triggers)
- **F-MVP-OS-WIRING → RESOLVED** (OSX1: seed-before-start race fixed + double-spawn deduped; stdio add-on kept; P2/P3 not taken)
- **F-MVP-RAG-PORT → RESOLVED** (OSX-RAG: `kb_*` tools on pgvector at full parity; `rag_search_case` removed)
- **F-MVP-OS35-SEC → RESOLVED** (`DISABLE_SECURITY_PLUGIN=true` + loopback; security plugin evaluation = B-MVP-OS35-SEC backlog post-demo)
- **NW5 → RESOLVED** (opensearch-mcp has NO run_command/execute/shell tool; no duplicate to remove)
- **OSX3 → reframed as NW6** (PTC is client-side in agent harness, NOT on-VM; Gateway already sanitizes output — the "evidence leaves the VM" objection is moot)

---

## VM Quick Reference

- **VM:** `sansforensics@192.168.122.81` / password: `forensics`
- **Active service tree:** `/opt/sift-mcps` (owned by `sift-service`; HARD1 cutover)
- **Operator portal:** `https://192.168.122.81:4508/portal/` — `examiner@operators.sift.local`
- **Host repo:** `/home/yk/AI/SIFTHACK/sift-mcps`
- **Sync:** `rsync -av --exclude='.git' --exclude='node_modules' --exclude='.venv' /home/yk/AI/SIFTHACK/sift-mcps/ sansforensics@192.168.122.81:/opt/sift-mcps/`
- **Restart + health:** `sudo systemctl restart sift-gateway.service sift-job-worker.service && curl -sk https://localhost:4443/health | python3 -m json.tool`
