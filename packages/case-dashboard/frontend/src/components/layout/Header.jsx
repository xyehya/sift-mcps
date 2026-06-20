import { useState } from 'react'
import { Check, ChevronsUpDown, Lock, Plus, Search } from 'lucide-react'

import { cn } from '@/lib/utils'
import { useStoreSlice } from '@/store/useStore'
import { useAuth } from '@/lib/auth-context'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
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

function AgentStatus({ chainStatus, busy }) {
  let label = 'idle'
  let dot = 'bg-muted-foreground'
  let hint = 'No AI analysis tasks running.'
  if (chainStatus?.status === 'violation') {
    label = 'error'
    dot = 'bg-destructive'
    hint = 'Integrity violation or system error.'
  } else if (busy) {
    label = 'processing'
    dot = 'bg-primary animate-pulse'
    hint = 'AI analysis tasks are active.'
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="mono inline-flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-muted-foreground">
          <span aria-hidden className={cn('size-1.5 rounded-full', dot)} />
          {label}
        </span>
      </TooltipTrigger>
      <TooltipContent>Agent status: {label} — {hint}</TooltipContent>
    </Tooltip>
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
  const { activeCase, cases, delta, chainStatus } = useStoreSlice((s) => ({
    activeCase: s.activeCase,
    cases: s.cases,
    delta: s.delta,
    chainStatus: s.chainStatus,
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
          aria-label="Open command palette"
          className="hidden w-full max-w-md justify-start gap-2 text-muted-foreground sm:inline-flex"
        >
          <Search className="size-3.5" aria-hidden />
          <span className="flex-1 text-left">Search · jump</span>
          <kbd className="mono rounded bg-secondary px-1.5 py-0.5 text-[10px]">⌘K</kbd>
        </Button>
      </div>

      <AgentStatus chainStatus={chainStatus} busy={delta.length > 0} />

      <ActivateCaseDialog activatingCase={activatingCase} onClose={() => setActivatingCase(null)} />
      <CreateCaseDialog open={creating} onOpenChange={setCreating} />
    </header>
  )
}
