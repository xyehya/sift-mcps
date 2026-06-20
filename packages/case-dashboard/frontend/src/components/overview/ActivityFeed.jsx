import { useMemo, useState } from 'react'
import { formatDistanceToNow } from 'date-fns'

import { cn } from '@/lib/utils'
import { useStoreSlice } from '@/store/useStore'
import { navigateToTab } from '@/hooks/useHashRoute'
import { ACTIVITY_RANGES, recentActivity } from '@/components/overview/overview-metrics'
import { confClass, findingTs } from '@/components/findings/findings-utils'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'

// ─────────────────────────────────────────────────────────────────────────
// Recent activity feed — the latest findings within a selectable window. Each
// row deep-links to the finding (selects it + switches to Findings). Confidence
// is shown as a token-coloured dot (shape + label in the tooltip-free row keeps
// it scannable). Empty state guides the examiner.
// ─────────────────────────────────────────────────────────────────────────

export function ActivityFeed({ findings, delta, loading }) {
  const [range, setRange] = useState('24h')
  const { setActiveTab, setSelectedFindingId } = useStoreSlice((s) => ({
    setActiveTab: s.setActiveTab,
    setSelectedFindingId: s.setSelectedFindingId,
  }))

  const stagedIds = useMemo(() => new Set((delta ?? []).map((d) => d.id)), [delta])
  const items = useMemo(() => recentActivity(findings, range), [findings, range])

  function open(f) {
    setSelectedFindingId(f.id)
    navigateToTab(setActiveTab, 'findings')
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-end">
        <Select value={range} onValueChange={setRange}>
          <SelectTrigger size="sm" className="h-7 w-32 text-xs" aria-label="Activity time range">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {ACTIVITY_RANGES.map((r) => (
              <SelectItem key={r.key} value={r.key} className="text-xs">
                {r.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {loading ? (
        <ul className="space-y-2" aria-busy="true">
          {Array.from({ length: 4 }).map((_, i) => (
            <li key={i} className="h-6 animate-pulse rounded bg-secondary" />
          ))}
        </ul>
      ) : items.length === 0 ? (
        <p className="text-sm text-muted-foreground">No finding activity in this window.</p>
      ) : (
        <ul className="flex flex-col" aria-label="Recent finding activity">
          {items.map((f) => {
            const cls = confClass(f.confidence)
            const ts = findingTs(f)
            return (
              <li key={f.id}>
                <button
                  type="button"
                  onClick={() => open(f)}
                  className={cn(
                    'flex w-full items-center gap-2.5 rounded-md px-2 py-1.5 text-left text-xs transition-colors',
                    'hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                  )}
                >
                  <span aria-hidden className={cn('size-1.5 shrink-0 rounded-full', cls ? cls.bg : 'bg-muted-foreground')} />
                  <span className="mono shrink-0 text-muted-foreground">{f.id}</span>
                  <span className="flex-1 truncate text-foreground">{f.title}</span>
                  {stagedIds.has(f.id) && <span className="shrink-0 text-[10px] font-medium text-status-staged">staged</span>}
                  {ts && (
                    <span className="mono shrink-0 text-[10px] text-muted-foreground">
                      {formatDistanceToNow(new Date(ts), { addSuffix: true })}
                    </span>
                  )}
                </button>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}
