import { formatDistanceToNow } from 'date-fns'
import { ArrowUpCircle, Lock } from 'lucide-react'

import { cn } from '@/lib/utils'
import { useStoreSlice } from '@/store/useStore'
import { navigateToTab } from '@/hooks/useHashRoute'
import { deriveSeal, SEAL_DOT_CLASS, SEAL_TONE_CLASS } from '@/lib/chain-status'
import { Button } from '@/components/ui/button'

// ─────────────────────────────────────────────────────────────────────────
// StatusBar (spec §4) — bottom strip: clickable seal status (→ Evidence),
// optional write-protected flag, staged-changes count (→ opens Commit Drawer),
// and last-sync time. Mono + tabular figures for the numeric bits.
// ─────────────────────────────────────────────────────────────────────────

function Dot() {
  return <span aria-hidden className="px-2 text-border">·</span>
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
  const syncLabel = lastSync ? `sync ${formatDistanceToNow(lastSync, { addSuffix: true })}` : 'syncing…'

  return (
    <div className="mono flex h-8 shrink-0 select-none items-center border-t border-border bg-card px-4 text-xs text-muted-foreground">
      {/* Seal status → Evidence tab */}
      <button
        type="button"
        onClick={() => navigateToTab(setActiveTab, 'evidence')}
        className={cn(
          'inline-flex items-center gap-1.5 rounded px-1 py-0.5 transition-colors hover:bg-secondary',
          SEAL_TONE_CLASS[tone],
        )}
        title="Go to Evidence"
      >
        <span aria-hidden className={cn('size-1.5 rounded-full', SEAL_DOT_CLASS[tone])} />
        {label}
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

      {stagedCount > 0 && (
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
      )}
    </div>
  )
}
