import { cn } from '@/lib/utils'
import { useStoreSlice } from '@/store/useStore'
import { navigateToTab } from '@/hooks/useHashRoute'
import { statusCounts, deriveAgentState } from '@/lib/agent-state'

// ─────────────────────────────────────────────────────────────────────────
// StatusBar — fixed 30px mono strip at the bottom of the shell.
// Handoff spec §Layout/Shell §Footer: static mono —
//   "● AGENT ACTIVE · INVESTIGATING" (jade)
//   │ "CUSTODY 12/14 SEALED"
//   │ "7/8 MCP ONLINE"
//   │ right: "WCAG AA ✓"
// No PORTAL V3 version string; no Commit button (those belong to the Findings
// screen header, not the global footer). The custody + MCP counts are live
// from portalState/chainStatus. Agent label is derived from the same
// deriveAgentState() selector as the hero + sidebar (they always agree).
// ─────────────────────────────────────────────────────────────────────────

function Pipe() {
  return <span aria-hidden className="px-2 text-border">│</span>
}

function agentFooterLabel(portalState, chainStatus, delta) {
  const a = deriveAgentState(portalState, chainStatus, delta)
  if (a.key === 'halt') return { label: 'AGENT HALTED · INTEGRITY STOP', tone: 'text-destructive', dot: 'bg-destructive' }
  if (a.key === 'awaiting-authorization') return { label: 'AGENT ACTIVE · AWAITING AUTH', tone: 'text-primary', dot: 'bg-primary' }
  if (a.key === 'working') return { label: 'AGENT ACTIVE · INVESTIGATING', tone: 'text-status-approved', dot: 'bg-status-approved' }
  return { label: 'AGENT IDLE', tone: 'text-muted-foreground', dot: 'bg-muted-foreground' }
}

export function StatusBar() {
  const { chainStatus, portalState, delta, setActiveTab } = useStoreSlice((s) => ({
    chainStatus: s.chainStatus,
    portalState: s.portalState,
    delta: s.delta,
    setActiveTab: s.setActiveTab,
  }))

  const agent = agentFooterLabel(portalState, chainStatus, delta)
  const counts = statusCounts(portalState, chainStatus)

  const sealLabel =
    counts.sealed != null && counts.evidenceTotal != null
      ? `${counts.sealed}/${counts.evidenceTotal} SEALED`
      : 'CUSTODY —'

  const mcpOnline =
    counts.backendsUp != null && counts.backendsTotal != null

  return (
    <div
      className="mono flex h-[30px] shrink-0 select-none items-center border-t border-border bg-card px-4 text-[11px] text-muted-foreground"
      role="status"
      aria-label="Portal status"
    >
      {/* Agent state */}
      <span className={cn('inline-flex items-center gap-1.5 uppercase tracking-[0.12em]', agent.tone)}>
        <span aria-hidden className={cn('size-1.5 rounded-full', agent.dot)} />
        {agent.label}
      </span>

      <Pipe />

      {/* Custody — clickable → Evidence */}
      <button
        type="button"
        onClick={() => navigateToTab(setActiveTab, 'evidence')}
        className="inline-flex items-center gap-1.5 rounded px-1 py-0.5 uppercase tracking-[0.12em] transition-colors hover:bg-secondary hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        title="Go to Evidence"
      >
        CUSTODY {sealLabel}
      </button>

      {mcpOnline && (
        <>
          <Pipe />
          <span
            className={cn(
              'inline-flex items-center gap-1.5 uppercase tracking-[0.12em]',
              counts.degraded > 0 ? 'text-sev-med' : 'text-status-approved',
            )}
            title={counts.degraded > 0 ? `${counts.degraded} MCP backend(s) degraded` : 'All MCP backends online'}
          >
            {counts.backendsUp}/{counts.backendsTotal} MCP ONLINE
          </span>
        </>
      )}

      <div className="flex-1" />

      {/* Identity tail — WCAG AA only */}
      <span className="hidden items-center gap-1.5 uppercase tracking-[0.12em] text-status-approved sm:inline-flex">
        <span aria-hidden className="size-1.5 rounded-full bg-status-approved" />
        WCAG AA ✓
      </span>
    </div>
  )
}
