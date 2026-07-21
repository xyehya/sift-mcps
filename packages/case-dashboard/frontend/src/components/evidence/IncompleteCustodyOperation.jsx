// ─────────────────────────────────────────────────────────────────────────
// IncompleteCustodyOperation — Seal-only (SPEC: only Add & Seal has an
// incomplete-operation record; it is a resume pointer, never a case-wide
// lock. Ignore/Retire/Reprotect are each one atomic transaction with no
// persistent failure state, so there is nothing else to resume here).
// PF-009 R2: the projection is path-free — {operation_id, idempotency_key,
// staging_window_open} only — so this notice shows a generic incomplete state
// and a Resume action, never a stored phase/path/key.
// ─────────────────────────────────────────────────────────────────────────

export function IncompleteCustodyOperation({ operation, onResume }) {
  if (!operation) return null
  return (
    <section aria-label="Incomplete custody operation" className="rounded-xl border border-status-pending/30 bg-status-pending/5 p-3 text-xs">
      <div className="font-semibold text-status-pending">Add &amp; Seal is incomplete</div>
      <p className="mt-1 text-muted-foreground">
        Re-authenticate to resume the durable custody operation. It re-commits the
        current pending files under the latest Refresh snapshot.
      </p>
      <button
        type="button"
        onClick={() => onResume(operation)}
        className="mono mt-2 rounded-lg border border-status-pending/40 px-3 py-1.5 font-semibold text-status-pending"
      >
        Resume Add &amp; Seal
      </button>
    </section>
  )
}
