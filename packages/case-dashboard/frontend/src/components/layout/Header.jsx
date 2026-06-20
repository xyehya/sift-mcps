import { useState } from 'react'
import { Activity, Check, ChevronsUpDown, Lock, Plus, Search } from 'lucide-react'

import { cn } from '@/lib/utils'
import { useStoreSlice } from '@/store/useStore'
import { useAuth } from '@/lib/auth-context'
import { deriveAgentState } from '@/lib/agent-state'
import { Button } from '@/components/ui/button'
import {
  Popover,
  PopoverContent,
  PopoverDescription,
  PopoverHeader,
  PopoverTitle,
  PopoverTrigger,
} from '@/components/ui/popover'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { ActivateCaseDialog, CreateCaseDialog } from '@/components/layout/CaseDialogs'

// ─────────────────────────────────────────────────────────────────────────
// Header strip (spec §4 / DESIGN-SYSTEM.md) — round-2 Mission-Control top bar:
// case-selector chip (mono id + live status dot) · centered "Search · jump ⌘K"
// command-palette trigger · agent-state mini-indicator. Operator identity,
// theme toggle and sign-out now live in the SideNav footer. RBAC: only
// examiners see "New case"; the activation/create flows are unchanged.
// (Multi-case dropdown contents are RUN-4b — this keeps the chip + active list.)
// ─────────────────────────────────────────────────────────────────────────

/**
 * processingTasks — the running background tasks behind the PROCESSING indicator,
 * derived honestly from the polled store (agent pipeline · evidence hashing · MCP
 * jobs · staged review). No fabricated work — each row maps to real state.
 */
function processingTasks(portalState, chainStatus, delta, agent) {
  const tasks = []
  const m = portalState?.agent?.metrics ?? {}
  const agentRunning = agent.key === 'working' || agent.key === 'awaiting-authorization'
  tasks.push({
    key: 'agent',
    label: 'Autonomous investigation',
    status: agentRunning ? (agent.key === 'awaiting-authorization' ? 'paused' : 'running') : 'idle',
    tone: agentRunning ? 'text-primary' : 'text-muted-foreground',
    dot: agentRunning ? 'bg-primary' : 'bg-muted-foreground',
    pulse: agent.key === 'working',
    detail: `${(m.records_parsed ?? 0).toLocaleString()} records parsed`,
  })
  const ev = portalState?.evidence
  if (ev?.total != null) {
    const full = ev.sealed === ev.total
    tasks.push({
      key: 'evidence',
      label: 'Evidence custody hashing',
      status: full ? 'verified' : 'hashing',
      tone: full ? 'text-status-approved' : 'text-sev-med',
      dot: full ? 'bg-status-approved' : 'bg-sev-med',
      pulse: !full,
      detail: `${ev.sealed ?? 0}/${ev.total} sealed`,
    })
  }
  const be = portalState?.backends
  if (be?.total != null) {
    const degraded = (be.degraded ?? []).length
    tasks.push({
      key: 'mcp',
      label: 'MCP backend jobs',
      status: degraded ? `${degraded} degraded` : 'online',
      tone: degraded ? 'text-sev-med' : 'text-status-approved',
      dot: degraded ? 'bg-sev-med' : 'bg-status-approved',
      pulse: false,
      detail: `${be.up ?? 0}/${be.total} backends up`,
    })
  }
  if ((delta ?? []).length > 0) {
    tasks.push({
      key: 'staged',
      label: 'Staged review changes',
      status: 'pending commit',
      tone: 'text-status-pending',
      dot: 'bg-status-pending',
      pulse: false,
      detail: `${delta.length} change${delta.length === 1 ? '' : 's'} awaiting commit`,
    })
  }
  return tasks
}

/** PROCESSING indicator — a keyboard-reachable Popover that explains what is
   running and lists the live background tasks (RUN-4c #41). No bare label. */
function AgentStatus({ portalState, chainStatus, delta }) {
  const agent = deriveAgentState(portalState, chainStatus, delta)
  let label = 'idle'
  let dot = 'bg-muted-foreground'
  let pulse = false
  if (chainStatus?.status === 'violation') {
    label = 'error'
    dot = 'bg-destructive'
  } else if (agent.key === 'working' || agent.key === 'awaiting-authorization' || (delta ?? []).length > 0) {
    label = 'processing'
    dot = 'bg-primary'
    pulse = agent.key !== 'awaiting-authorization'
  }
  const tasks = processingTasks(portalState, chainStatus, delta, agent)
  return (
    <Popover>
      <PopoverTrigger asChild>
        <button
          type="button"
          aria-label={`Agent status: ${label}. View running background tasks.`}
          className="mono inline-flex items-center gap-1.5 rounded px-1.5 py-1 text-[10px] uppercase tracking-wider text-muted-foreground transition-colors hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <span aria-hidden className={cn('size-1.5 rounded-full', dot, pulse && 'animate-pulse')} />
          {label}
          <Activity className="size-3 opacity-60" aria-hidden />
        </button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-80">
        <PopoverHeader>
          <PopoverTitle>Background activity</PopoverTitle>
          <PopoverDescription>What the portal is processing right now.</PopoverDescription>
        </PopoverHeader>
        <ul className="mt-3 flex flex-col gap-3">
          {tasks.map((t) => (
            <li key={t.key} className="flex items-start gap-2.5">
              <span aria-hidden className={cn('mt-1 size-1.5 shrink-0 rounded-full', t.dot, t.pulse && 'animate-pulse')} />
              <div className="min-w-0 flex-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-medium text-foreground">{t.label}</span>
                  <span className={cn('mono text-[10px] uppercase tracking-wider', t.tone)}>{t.status}</span>
                </div>
                <p className="mono mt-0.5 text-[11px] text-muted-foreground">{t.detail}</p>
              </div>
            </li>
          ))}
        </ul>
      </PopoverContent>
    </Popover>
  )
}

/** Lifecycle badge for a case row (active / inactive / sealed). Tolerant of a
    backend that only sends {id, active}: status falls back to active→inactive. */
function caseStatusMeta(c) {
  const s = (c.status || (c.active ? 'active' : 'inactive')).toLowerCase()
  if (s === 'sealed' || s === 'archived' || s === 'closed') {
    return { label: 'sealed', dot: 'bg-sev-med', text: 'text-sev-med', sealed: true }
  }
  if (s === 'active' || c.active) {
    return { label: 'active', dot: 'bg-status-approved', text: 'text-status-approved' }
  }
  return { label: 'inactive', dot: 'bg-muted-foreground', text: 'text-muted-foreground' }
}

function CaseSelector({ activeCase, cases, isExaminer, onActivate, onCreate }) {
  const activeCaseId = activeCase?.case_id || activeCase?.id
  const activeName = activeCase?.name || activeCase?.title
  const status = (activeCase?.status || (activeCaseId ? 'active' : '')).toUpperCase()
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" className="mono gap-2">
          {activeCaseId ? (
            <>
              <span aria-hidden className="size-1.5 rounded-full bg-status-approved" />
              {activeName && <span className="max-w-[140px] truncate font-semibold uppercase">{activeName}</span>}
              <span className="max-w-[160px] truncate text-muted-foreground">{activeCaseId}</span>
              {status && <span className="text-[10px] uppercase tracking-wider text-muted-foreground">{status}</span>}
            </>
          ) : (
            <span className="text-muted-foreground">No case active</span>
          )}
          <ChevronsUpDown className="size-3.5 opacity-60" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-80">
        <DropdownMenuLabel>Cases</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {cases.length === 0 && (
          <p className="px-2 py-2 text-xs text-muted-foreground">
            {isExaminer ? 'No cases yet — create one to begin.' : 'No cases found.'}
          </p>
        )}
        {cases.map((c) => {
          const meta = caseStatusMeta(c)
          return (
            <DropdownMenuItem
              key={c.id}
              disabled={c.active}
              onSelect={() => !c.active && onActivate(c)}
              className="gap-2 text-xs"
            >
              <span aria-hidden className={cn('size-1.5 shrink-0 rounded-full', meta.dot)} />
              <div className="flex min-w-0 flex-1 flex-col">
                {c.name && <span className="truncate font-semibold uppercase">{c.name}</span>}
                <span className="mono truncate text-[11px] text-muted-foreground">{c.id}</span>
              </div>
              <span className={cn('inline-flex items-center gap-1 text-[10px] uppercase tracking-wider', meta.text)}>
                {meta.sealed && <Lock className="size-3" aria-hidden />}
                {meta.label}
              </span>
              {c.active && <Check className="size-3.5 text-primary" />}
            </DropdownMenuItem>
          )
        })}
        {isExaminer && (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={onCreate} className="gap-2 text-primary">
              <Plus className="size-3.5" />
              Create case
            </DropdownMenuItem>
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

export function Header({ onOpenCommandPalette }) {
  const { user } = useAuth()
  const { activeCase, cases, delta, chainStatus, portalState } = useStoreSlice((s) => ({
    activeCase: s.activeCase,
    cases: s.cases,
    delta: s.delta,
    chainStatus: s.chainStatus,
    portalState: s.portalState,
  }))

  const [activatingCase, setActivatingCase] = useState(null)
  const [creating, setCreating] = useState(false)

  const role = (user?.role || '').toLowerCase()
  const isExaminer = role === 'examiner'

  return (
    <header className="flex h-14 shrink-0 items-center gap-3 border-b border-border bg-card px-4">
      <CaseSelector
        activeCase={activeCase}
        cases={cases}
        isExaminer={isExaminer}
        onActivate={setActivatingCase}
        onCreate={() => setCreating(true)}
      />

      {/* Centered command-palette trigger — "Search · jump ⌘K" */}
      <div className="flex flex-1 justify-center">
        <Button
          variant="outline"
          size="sm"
          onClick={onOpenCommandPalette}
          aria-label="Search · jump — open command palette (⌘K)"
          className="hidden w-full max-w-md justify-start gap-2 text-muted-foreground sm:inline-flex"
        >
          <Search className="size-3.5" aria-hidden />
          <span className="flex-1 text-left">Search · jump</span>
          <kbd className="mono rounded bg-secondary px-1.5 py-0.5 text-[10px]">⌘K</kbd>
        </Button>
      </div>

      <AgentStatus portalState={portalState} chainStatus={chainStatus} delta={delta} />

      <ActivateCaseDialog activatingCase={activatingCase} onClose={() => setActivatingCase(null)} />
      <CreateCaseDialog open={creating} onOpenChange={setCreating} />
    </header>
  )
}
