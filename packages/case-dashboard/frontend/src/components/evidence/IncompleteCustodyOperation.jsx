const NEXT_ACTION = {
  GATE_BLOCKED: 'Retry Add & Seal to continue from the durable custody gate.',
  FILESYSTEM_APPLYING: 'Wait for the active service run; retry after a service restart if it was interrupted.',
  FILESYSTEM_VERIFIED: 'Wait for ledger commit; retry after a service restart if it was interrupted.',
  FAILED_RECOVERABLE: 'Retry Add & Seal with the same intent to recover safely.',
  LEDGER_COMMITTED: 'Wait for the operation result to finalize.',
}

export function IncompleteCustodyOperation({ operation }) {
  if (!operation) return null
  const phase = String(operation.phase || 'UNKNOWN')
  const nextAction = NEXT_ACTION[phase] || 'Refresh custody status before taking another action.'
  return (
    <section aria-label="Incomplete custody operation" className="rounded-xl border border-status-pending/30 bg-status-pending/5 p-3 text-xs">
      <div className="font-semibold text-status-pending">Add &amp; Seal is incomplete</div>
      <div className="mono mt-1 text-foreground">State: {phase}</div>
      {operation.failed_from_phase && <div className="mono text-muted-foreground">Interrupted from: {operation.failed_from_phase}</div>}
      <p className="mt-1 text-muted-foreground">Next action: {nextAction}</p>
    </section>
  )
}
