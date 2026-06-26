# E1 / XYE-34 — Case-Metadata Connection Reuse — Implementation Spec

> Status: ready-to-implement. Owner unit: Axis E1 under OT3 (XYE-46).
> Source plan: `docs/new-docs/AXIS_E_BUILD_PLAN.md`.
> Design basis: Supabase/Postgres best-practices review (consult, 2026-06-18) +
> the B2-1 authority-flow doc `docs/drafts/architecture/active-case-authority-flow.md`.
> Hard rule for the whole change: this is a **fail-closed authority read**
> (closed-case refusal, examiner identity, report inclusion). A fast-but-wrong
> answer is worse than a slow-but-right one. Correctness > latency, always.

---

## 1. Goal

Stop opening a fresh `psycopg` connection on every case-metadata read while
preserving DB-authority fail-closed semantics exactly. Reuse one connection per
process; re-query every call (never cache the result).

**File in scope:** `packages/sift-core/src/sift_core/investigation_store.py`
(plus its tests). No other production file changes. Do **not** alter the metadata
shape, the `resolve_case_metadata()` contract, or any caller.

## 2. Verified deployment facts (do not re-litigate)

- `psycopg[binary]>=3.2` is the only Postgres dep. **`psycopg_pool` is a separate
  package — NOT in scope.** No new dependency.
- `supabase/config.toml`: `[db.pooler] enabled = false`; `[db]` comment = "direct
  DSN for SIFT app control plane." → DSN targets Postgres **directly** today.
- DSN is deploy-time env `SIFT_CONTROL_PLANE_DSN` — an operator could repoint it at
  a pooler later, so the design must be **pooler-safe regardless**.
- Autocommit is already the house idiom (`install.sh` migrations use
  `psycopg.connect(dsn, autocommit=True)`).
- Core tool bodies already run **off the event loop** via
  `asyncio.to_thread(_run_core)` (`packages/sift-gateway/src/sift_gateway/server.py:1031`),
  so the sync read is off-loop on the hot tool path. The threadpool means
  concurrent reads can hit the shared connection → thread-safety still matters.

## 3. Current shape (anti-pattern being fixed)

```python
class PostgresCaseStore:
    def __init__(self, dsn): self._dsn = dsn
    def _connect(self):
        import psycopg
        return psycopg.connect(self._dsn)            # NEW connection per call
    def get_case_metadata(self, case_id):
        with self._connect() as conn:                # opens AND closes per call
            with conn.cursor() as cur:
                cur.execute("select ... from app.cases where id::text=%s or case_key=%s",
                            (case_id, case_id))
                row = cur.fetchone()
        return _case_meta_from_row(row) if row else None

def resolve_case_metadata():                          # contract is FROZEN
    if not db_authority_active(): return None         # file/legacy mode
    dsn = control_plane_dsn()
    if not dsn: raise InvestigationStoreError(...)     # fail closed
    ctx = current_active_case(); case_id = ctx.case_id if ctx else None
    if not case_id: raise InvestigationStoreError(...) # fail closed
    meta = PostgresCaseStore(dsn).get_case_metadata(case_id)
    if meta is None: raise InvestigationStoreError(...) # fail closed
    return meta
```

## 4. Target design

### 4.1 Per-process connection cache (the provider)

- Module-level cache: `dict[tuple[int, str], Connection]` keyed by
  `(os.getpid(), dsn)`.
- A `threading.Lock` guards the **cache dict only** (create / evict / liveness
  swap). Do **NOT** wrap `cur.execute()` in a global lock — psycopg3 `Connection`
  is already internally thread-safe; a global lock would serialize every
  case-metadata read in the process behind one connection.
- Lazy creation. A `connection_provider(dsn) -> Connection` callable is the single
  creation point and is **injectable** into `PostgresCaseStore` so tests can prove
  reuse with a fake factory.
- `os.register_at_fork(after_in_child=_clear_cache)` — on fork the child must
  **drop inherited entries WITHOUT closing them** (`cache.clear()` / set None).
  pid-keying stops the child *using* the parent connection; this stops the child's
  GC from sending a protocol-close on the duplicated fd and corrupting the
  parent's socket. Both are required.

### 4.2 Connection parameters (every created connection)

```python
psycopg.connect(
    dsn,
    autocommit=True,                 # correctness: fresh MVCC snapshot per stmt; no idle-in-txn
    prepare_threshold=None,          # disable client prepared statements (pooler-insurance)
    connect_timeout=5,               # DB outage fails closed FAST, never hangs the hot path
    application_name="sift-case-store",   # visible in pg_stat_activity for leak/idle diagnosis
    options="-c statement_timeout=5000 -c idle_in_transaction_session_timeout=10000",
)
```
- Prefer a **read-only posture**: a dedicated read-only DB role for this DSN path,
  or `SET default_transaction_read_only = on` on the connection. The authority
  *read* needs no write rights. (If a read-only role is not yet provisioned,
  document it as a deploy follow-up; do not block the code on it.)

### 4.3 Read + error handling

`get_case_metadata(case_id)`:
1. Borrow the cached connection for `(pid, dsn)` (create if absent). Do **NOT**
   close it after use — re-query the live row each call.
2. Run the SELECT, `fetchone()`, return `_case_meta_from_row(row)` or `None`.
3. **Connection-level error** (`psycopg.OperationalError` / `psycopg.InterfaceError`
   where the statement provably did not execute — e.g. dead socket after server
   idle-timeout): evict the cached connection, **reconnect once, retry the SELECT
   once**. A SELECT is idempotent so this is safe. If the retry also fails, raise
   `InvestigationStoreError` (fail closed).
4. **Any other error** (query/programming/data error): evict + raise
   `InvestigationStoreError` immediately. No retry loop.
5. Never fall back to a file, never return stale/empty on error.

`resolve_case_metadata()` keeps its contract byte-for-byte: `None` in file mode;
raise on missing DSN / missing context / missing row / DB error.

### 4.4 Invariants (enforce + comment + test)

- **No result caching.** Only the socket is cached; the row is always re-read.
- **READ COMMITTED + autocommit only.** Forbid raising the isolation level on this
  store (a non-default isolation inside a held txn would freeze the snapshot and
  could serve stale authority). Comment it and add a guard test.
- **Primary, not replica.** All MVCC-freshness reasoning assumes the DSN resolves
  to the primary. Replication lag could read a closed case as open → forensic
  fail-closed violation. Single-VM today = no replica; assert as a deploy
  invariant (doc + optional startup check).
- **Bounded connections.** Pooler disabled ⇒ gateway + N forked workers each hold
  one direct connection vs Postgres `max_connections` (~100). Keep worker count
  well under that. Revisit `psycopg_pool` only when this path sees real concurrent
  load (that is the single shared connection's bottleneck signal).

## 5. API surface changes

- `PostgresCaseStore.__init__(self, dsn, *, connection_provider=None)` — optional
  injected provider; defaults to the module pooled provider. Backwards compatible.
- New module-level: `_connection_for(dsn)` provider, `_evict(pid, dsn)`,
  `_clear_cache()` (fork hook), module cache + lock.
- `resolve_case_metadata()` signature and return type unchanged.

## 6. Pre-implementation checks (do these first)

1. Grep every caller of `resolve_case_metadata` and confirm each runs off-loop
   (via the `to_thread(_run_core)` path) or in a sync context. If any caller runs
   directly on the event loop (e.g. an async middleware path like
   `_refuse_closed_case_db` invoked on-loop), wrap that specific call in
   `asyncio.to_thread`. Document the finding either way.
2. Confirm `psycopg.OperationalError` / `InterfaceError` import paths in the
   installed psycopg 3.2.

## 7. Tests (acceptance proofs) — `packages/sift-core/tests/`

New (add a focused test module, e.g. `test_e1_case_store_conn_reuse.py`):
- **Reuse:** N calls to `resolve_case_metadata()` (or `get_case_metadata`) with a
  fake connection factory → factory invoked exactly once; connection reused.
- **prepare_threshold:** created connection is built with `prepare_threshold=None`
  (assert via fake factory capturing kwargs).
- **Dead-socket recovery:** first execute raises `OperationalError` (simulated
  server idle-close) → exactly one reconnect + retry → success; factory called
  twice, result correct.
- **No retry on query error:** a programming/data error raises
  `InvestigationStoreError` with the factory called once (no reconnect loop).
- **Fork hook:** after invoking the registered `after_in_child` callback, the
  cache is empty and the prior connection object was NOT closed.
- **Isolation guard:** the store never sets isolation above READ COMMITTED
  (assert default/autocommit).

Must still pass unchanged (fail-closed regressions):
- `test_bu1_db_case_metadata.py`, `test_bu3_file_readers_unreachable.py`,
  `test_case_ops.py`, `test_xye35_require_active_case_fail_closed.py`,
  `test_k6_file_authority_removal.py`.

Local validation command:
```bash
uv run --python 3.11 --extra dev --extra full pytest \
  packages/sift-core/tests/test_e1_case_store_conn_reuse.py \
  packages/sift-core/tests/test_bu1_db_case_metadata.py \
  packages/sift-core/tests/test_bu3_file_readers_unreachable.py \
  packages/sift-core/tests/test_case_ops.py \
  packages/sift-core/tests/test_xye35_require_active_case_fail_closed.py \
  packages/sift-core/tests/test_k6_file_authority_removal.py
```

## 8. Live deploy + verify runbook (per CLAUDE.md "Live VM Discipline")

1. Code on Mac; run the §7 suite green locally.
2. Sync only the touched file(s):
   `rsync -av packages/sift-core/src/sift_core/investigation_store.py \
     sift-vm:/opt/sift-mcps/packages/sift-core/src/sift_core/investigation_store.py`
3. Restart affected services (confirm unit names first):
   `ssh sift-vm 'sudo systemctl restart sift-gateway.service sift-job-worker.service'`
4. Health: `curl --cacert ~/.sift/sift-gateway-ca.crt https://localhost:4508/health`
   through `ssh -fN sift-gateway-tunnel`.
5. **Functional proof:** drive a few MCP calls that hit case metadata
   (`case_info`, `list_existing_findings`) via the in-session gateway MCP.
6. **Reuse proof (the E1 win):** before/after those calls, inspect Postgres:
   `select pid, application_name, state, backend_start from pg_stat_activity
    where application_name = 'sift-case-store';`
   Expect a **stable, small** set of backends (one per live process), NOT a
   growing/churning count. Capture sanitized before/after counts.
7. **Fail-closed proof:** confirm that with the DB made unreachable, the metadata
   path raises (tool returns an error / refuses) rather than serving stale/file
   data; restore and confirm recovery (exercises the reconnect-retry).
8. Record sanitized proof in the XYE-34 Linear comment (counts + health + one
   functional result; no raw DSNs/secrets/case paths).

## 9. Security testing (before merge)

- Run `/security-review` (or the security-review skill) on the diff.
- Manual checks:
  - No DSN / password / secret in logs, `application_name`, or error strings.
  - Read-only posture honored (no write path opened by this connection).
  - `statement_timeout` + `connect_timeout` actually applied (a hung DB cannot
    stall the hot path).
  - Fail-closed under DB-down and under closed-case race (no stale "open" read).
  - No connection leak / unbounded growth in `pg_stat_activity` under repeated
    calls or repeated worker spawns.

## 10. Merge gate

Merge to `main` + push only when **all** hold:
- §7 suite green (new tests + fail-closed regressions).
- §8 live proof recorded in XYE-34 (sanitized).
- §9 security review clean.
- `git diff --check` clean; targeted `bash -n` n/a (no shell touched).

On merge: move XYE-34 → Done with the handoff (branch/commit, validation, live
proof, security result). XYE-34 was the last non-G child gating nothing further,
but its closure advances OT3 (XYE-46) toward done (G axis still open).

## 11. Rollback

The change is isolated to `investigation_store.py`. Rollback = revert the commit
and re-rsync the prior file + restart services. No schema or data migration is
involved.

## 12. Scope fence (do NOT)

- Do not add `psycopg_pool` (separate dep; defer until real concurrent load).
- Do not change the metadata shape or `resolve_case_metadata()` contract.
- Do not cache the *result* — only the connection.
- Do not touch callers, middleware, or the gateway package (except a localized
  `to_thread` wrap IF §6.1 finds an on-loop caller).
