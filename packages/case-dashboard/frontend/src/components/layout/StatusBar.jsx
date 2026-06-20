import { formatDistanceToNow } from 'date-fns'
import { ArrowUpCircle, Lock } from 'lucide-react'

import { cn } from '@/lib/utils'
import { useStoreSlice } from '@/store/useStore'
import { navigateToTab } from '@/hooks/useHashRoute'
import { deriveSeal, SEAL_DOT_CLASS, SEAL_TONE_CLASS } from '@/lib/chain-status'
import { Button } from '@/components/ui/button'

// ─────────────────────────────────────────────────────────────────────────
// StatusBar (spec §4 / DESIGN-SYSTEM.md) — round-2 Mission-Control footer:
// AGENT state · CUSTODY (clickable seal → Evidence) · staged-changes count
// (→ Commit Drawer) · last-sync · WCAG-AA + portal-version identity tail.
// Mono + tabular figures throughout; tokens-only. Live SEALED-X/Y and
// MCP-online counts wire in RUN-4b (their data isn't in the frozen store yet).
// ─────────────────────────────────────────────────────────────────────────

const PORTAL_VERSION = 'PORTAL v3'

function Dot() {
  return <span aria-hidden className="px-2 text-border">·</span>
}

/** Agent state derived from the same signals the Header indicator uses. */
function agentState(chainStatus, stagedCount) {
  if (chainStatus?.status === 'violation') return { label: 'INTEGRITY HALT', dot: 'bg-destructive', tone: 'text-destructive' }
  if (stagedCount > 0) return { label: 'AWAITING AUTH', dot: 'bg-primary', tone: 'text-primary' }
  return { label: 'MONITORING', dot: 'bg-muted-foreground', tone: 'text-muted-foreground' }
}

export function StatusBar() {
  const { chainStatus, delta, lastSync, setActiveTab, setCommitDrawerOpen } = useStoreSlice((s) => ({
    chainStatus: s.chainStatus,
    delta: s.delta,
    lastSync: s.lastSync,
    setActiveTab: s.setActiveTab,
    setCommitDrawerOpen: s.setCommitDrawerOpen,
  }))

  const { label, tone } = deriveSeal(chainStatus)
  const stagedCount = delta.length
  const agent = agentState(chainStatus, stagedCount)
  const syncLabel = lastSync ? `sync ${formatDistanceToNow(lastSync, { addSuffix: true })}` : 'syncing…'

  return (
    <div className="mono flex h-8 shrink-0 select-none items-center border-t border-border bg-card px-4 text-xs text-muted-foreground">
      {/* Agent state */}
      <span className={cn('inline-flex items-center gap-1.5 uppercase tracking-wider', agent.tone)}>
        <span aria-hidden className={cn('size-1.5 rounded-full', agent.dot)} />
        AGENT · {agent.label}
      </span>

      <Dot />

      {/* Custody / seal status → Evidence tab */}
      <button
        type="button"
        onClick={() => navigateToTab(setActiveTab, 'evidence')}
        className={cn(
          'inline-flex items-center gap-1.5 rounded px-1 py-0.5 uppercase tracking-wider transition-colors hover:bg-secondary',
          SEAL_TONE_CLASS[tone],
        )}
        title="Go to Evidence"
      >
        <span aria-hidden className={cn('size-1.5 rounded-full', SEAL_DOT_CLASS[tone])} />
        CUSTODY · {label}
      </button>

      {chainStatus?.write_protected && (
        <>
          <Dot />
          <span className="inline-flex items-center gap-1 text-status-staged">
            <Lock className="size-3" aria-hidden />
            write-protected
          </span>
        </>
      )}

      <Dot />
      <span className={cn('tnum', stagedCount > 0 && 'text-status-pending')}>
        {stagedCount > 0 ? `${stagedCount} staged` : 'no staged changes'}
      </span>

      <Dot />
      <span className="tnum">{syncLabel}</span>

      <div className="flex-1" />

      {/* Identity tail */}
      <span className="hidden items-center gap-1.5 text-[10px] uppercase tracking-wider text-status-approved sm:inline-flex">
        <span aria-hidden className="size-1.5 rounded-full bg-status-approved" />
        WCAG AA
      </span>
      <Dot />
      <span className="text-[10px] uppercase tracking-wider text-muted-foreground">{PORTAL_VERSION}</span>

      {stagedCount > 0 && (
        <>
          <Dot />
          <Button
            type="button"
            size="xs"
            onClick={() => setCommitDrawerOpen(true)}
            className="gap-1.5"
            title="Open commit drawer"
          >
            <ArrowUpCircle className="size-3" />
            Commit
          </Button>
        </>
      )}
    </div>
  )
}
