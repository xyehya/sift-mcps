// ─────────────────────────────────────────────────────────────────────────
// IncompleteCustodyOperation — Seal-only (SPEC: only Add & Seal has an
// incomplete-operation record; it is a resume pointer, never a case-wide
// lock. Ignore/Retire/Reprotect are each one atomic transaction with no
// persistent failure state, so there is nothing else to resume here).
// ─────────────────────────────────────────────────────────────────────────

const NEXT_ACTION = {
  REQUESTED: 'Retry Add & Seal to continue from the durable custody gate.',
  PROTECTED: 'Wait for manifest commit; retry after a service restart if it was interrupted.',
}

export function IncompleteCustodyOperation({ operation, onResume }) {
  if (!operation) return null
  const phase = String(operation.phase || 'UNKNOWN')
  const nextAction = NEXT_ACTION[phase] || 'Refresh custody status before taking another action.'
  return (
    <section aria-label="Incomplete custody operation" className="rounded-xl border border-status-pending/30 bg-status-pending/5 p-3 text-xs">
      <div className="font-semibold text-status-pending">Add &amp; Seal is incomplete</div>
      <div className="mono mt-1 text-foreground">State: {phase}</div>
      <p className="mt-1 text-muted-foreground">Next action: {nextAction}</p>
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
