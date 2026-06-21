import { useMemo } from 'react'
import { ChevronRight } from 'lucide-react'

import { cn } from '@/lib/utils'
import { useStoreSlice } from '@/store/useStore'
import { navigateToTab } from '@/hooks/useHashRoute'
import { recentActivity } from '@/components/overview/overview-metrics'

// ─────────────────────────────────────────────────────────────────────────
// RecentFindings — right-column "Recent findings" panel (handoff §Screen 1,
// right col #3). Up to 8 findings, newest first. Each row: severity accent
// bar + id + severity chip + truncated title + chevron. Clicking a row
// opens that finding on the Findings screen (selects it + navigates).
// "Review all →" header link navigates to Findings with no filter.
// ─────────────────────────────────────────────────────────────────────────

const SEV_BAR = {
  HIGH: 'bg-sev-high',
  MEDIUM: 'bg-sev-med',
  LOW: 'bg-sev-low',
}

const SEV_CHIP_CLS = {
  HIGH: 'border-sev-high/40 text-sev-high bg-sev-high/10',
  MEDIUM: 'border-sev-med/40 text-sev-med bg-sev-med/10',
  LOW: 'border-sev-low/40 text-sev-low bg-sev-low/10',
}

function sevKey(f) {
  const raw = (f.confidence ?? '').toUpperCase()
  if (raw === 'HIGH') return 'HIGH'
  if (raw === 'MEDIUM') return 'MEDIUM'
  return 'LOW'
}

export function RecentFindings() {
  const { findings, setActiveTab, setSelectedFindingId } = useStoreSlice((s) => ({
    findings: s.findings,
    setActiveTab: s.setActiveTab,
    setSelectedFindingId: s.setSelectedFindingId,
  }))

  const items = useMemo(() => recentActivity(findings, 'all', 8), [findings])

  function openFinding(f) {
    setSelectedFindingId(f.id)
    navigateToTab(setActiveTab, 'findings')
  }

  function reviewAll() {
    navigateToTab(setActiveTab, 'findings')
  }

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      {/* Header */}
      <div className="flex items-center justify-between pb-2">
        <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
          Recent findings
        </span>
        <button
          type="button"
          onClick={reviewAll}
          className="text-[10px] font-medium text-primary transition-colors hover:text-primary/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          Review all →
        </button>
      </div>

      {/* Findings list */}
      {items.length === 0 ? (
        <p className="text-xs text-muted-foreground">No findings recorded yet.</p>
      ) : (
        <ul className="flex flex-col gap-0.5 overflow-y-auto" aria-label="Recent findings">
          {items.map((f) => {
            const sk = sevKey(f)
            const barCls = SEV_BAR[sk] ?? 'bg-muted-foreground'
            const chipCls = SEV_CHIP_CLS[sk] ?? 'border-border text-muted-foreground bg-secondary'
            return (
              <li key={f.id}>
                <button
                  type="button"
                  onClick={() => openFinding(f)}
                  className={cn(
                    'group flex w-full items-center gap-2 rounded-md px-2 py-2 text-left text-xs transition-colors',
                    'hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                  )}
                >
                  {/* Severity accent bar */}
                  <span aria-hidden className={cn('h-6 w-0.5 shrink-0 rounded-full', barCls)} />
                  {/* ID */}
                  <span className="mono shrink-0 text-[10px] text-muted-foreground">{f.id}</span>
                  {/* Severity chip */}
                  <span
                    className={cn(
                      'shrink-0 rounded-full border px-1.5 py-0 text-[10px] font-semibold',
                      chipCls,
                    )}
                  >
                    {sk[0]}
                  </span>
                  {/* Title */}
                  <span className="min-w-0 flex-1 truncate text-foreground">{f.title}</span>
                  {/* Chevron */}
                  <ChevronRight
                    className="size-3 shrink-0 text-border transition-colors group-hover:text-muted-foreground"
                    aria-hidden
                  />
                </button>
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}
