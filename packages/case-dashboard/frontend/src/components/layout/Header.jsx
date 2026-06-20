import { useState } from 'react'
import { Check, ChevronsUpDown, Command as CommandIcon, LogOut, Plus } from 'lucide-react'

import { cn } from '@/lib/utils'
import { useStoreSlice } from '@/store/useStore'
import { useAuth } from '@/lib/auth-context'
import { deriveSeal, SEAL_DOT_CLASS, SEAL_TONE_CLASS } from '@/lib/chain-status'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { ThemeToggle } from '@/lib/theme'
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
// Header strip (spec §4): case selector (mono id), live chain-status pill,
// agent status, role badge, theme toggle, and the ⌘K command-palette trigger.
// RBAC: only examiners see "New case". Case create/activate flows are ported
// in CaseDialogs (challenge contract preserved).
// ─────────────────────────────────────────────────────────────────────────

function ChainPill({ chainStatus }) {
  const { label, tone } = deriveSeal(chainStatus)
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          className={cn(
            'mono inline-flex items-center gap-1.5 rounded-full border border-border px-2.5 py-1 text-xs',
            SEAL_TONE_CLASS[tone],
          )}
        >
          <span aria-hidden className={cn('size-1.5 rounded-full', SEAL_DOT_CLASS[tone])} />
          {label}
        </span>
      </TooltipTrigger>
      <TooltipContent>Evidence chain status</TooltipContent>
    </Tooltip>
  )
}

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
    dot = 'bg-status-pending animate-pulse'
    hint = 'AI analysis tasks are active.'
  }
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex items-center gap-1.5 text-xs text-muted-foreground">
          <span aria-hidden className={cn('size-1.5 rounded-full', dot)} />
          {label}
        </span>
      </TooltipTrigger>
      <TooltipContent>Agent status: {label} — {hint}</TooltipContent>
    </Tooltip>
  )
}

function CaseSelector({ activeCase, cases, isExaminer, onActivate, onCreate }) {
  const activeCaseId = activeCase?.case_id || activeCase?.id
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" className="mono gap-2">
          {activeCaseId ? (
            <>
              <span aria-hidden className="size-1.5 rounded-full bg-primary" />
              <span className="max-w-[180px] truncate font-semibold">{activeCaseId}</span>
            </>
          ) : (
            <span className="text-muted-foreground">No case active</span>
          )}
          <ChevronsUpDown className="size-3.5 opacity-60" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-72">
        <DropdownMenuLabel>Cases</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {cases.length === 0 && (
          <p className="px-2 py-2 text-xs text-muted-foreground">
            {isExaminer ? 'No cases yet — create one to begin.' : 'No cases found.'}
          </p>
        )}
        {cases.map((c) => (
          <DropdownMenuItem
            key={c.id}
            disabled={c.active}
            onSelect={() => !c.active && onActivate(c)}
            className="mono gap-2 text-xs"
          >
            <span
              aria-hidden
              className={cn('size-1.5 shrink-0 rounded-full', c.active ? 'bg-primary' : 'bg-muted-foreground')}
            />
            <span className="flex-1 truncate">{c.id}</span>
            {c.active && <Check className="size-3.5 text-primary" />}
          </DropdownMenuItem>
        ))}
        {isExaminer && (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={onCreate} className="gap-2 text-primary">
              <Plus className="size-3.5" />
              New case
            </DropdownMenuItem>
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

export function Header({ onOpenCommandPalette }) {
  const { user, logout } = useAuth()
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

      <Separator orientation="vertical" className="h-6" />
      <ChainPill chainStatus={chainStatus} />

      <div className="flex-1" />

      <AgentStatus chainStatus={chainStatus} busy={delta.length > 0} />

      {/* ⌘K command palette trigger */}
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="outline"
            size="sm"
            onClick={onOpenCommandPalette}
            className="hidden gap-2 text-muted-foreground sm:inline-flex"
            aria-label="Open command palette"
          >
            <CommandIcon className="size-3.5" />
            <kbd className="mono text-[10px]">⌘K</kbd>
          </Button>
        </TooltipTrigger>
        <TooltipContent>Command palette</TooltipContent>
      </Tooltip>

      {user?.role && (
        <Badge variant="secondary" className="mono uppercase">
          {user.role}
        </Badge>
      )}

      <ThemeToggle />

      <Tooltip>
        <TooltipTrigger asChild>
          <Button variant="ghost" size="icon" onClick={logout} aria-label="Sign out">
            <LogOut className="size-4" />
          </Button>
        </TooltipTrigger>
        <TooltipContent>Sign out</TooltipContent>
      </Tooltip>

      <ActivateCaseDialog activatingCase={activatingCase} onClose={() => setActivatingCase(null)} />
      <CreateCaseDialog open={creating} onOpenChange={setCreating} />
    </header>
  )
}
