import { motion } from 'framer-motion'

import { cn } from '@/lib/utils'
import { useStoreSlice } from '@/store/useStore'
import { navigateToFindings } from '@/hooks/useHashRoute'
import { useMotionVariants } from '@/lib/motion'
import { severityCounts } from '@/components/overview/overview-metrics'
import { Skeleton } from '@/components/ui/skeleton'

// ─────────────────────────────────────────────────────────────────────────
// Severity (confidence) distribution — RUN-4c #42. The rows distribute to FILL
// the card height (flex-1 list/rows — no empty lower dead-space), each carrying
// real value: the count, a 24h-new delta, an "awaiting review" sub-count, plus a
// header callout for High-awaiting + total. INTERACTIVE: each tier is a button
// that deep-links to Findings filtered to that severity (hash `?sev=…` + status
// reset). Bars grow on mount via `severityBarFill` (scaleX from left, transform-
// only → reduced-motion shows the final state instantly; data readable at once).
// Bar widths are data-driven inline styles (the only inline style permitted),
// never raw hex.
// ─────────────────────────────────────────────────────────────────────────

export function SeverityDistribution({ findings, loading }) {
  const variants = useMotionVariants()
  const { setActiveTab, setFindingsFilter } = useStoreSlice((s) => ({
    setActiveTab: s.setActiveTab,
    setFindingsFilter: s.setFindingsFilter,
  }))

  const rows = severityCounts(findings)
  const totalFindings = rows[0]?.total ?? 0
  const highAwaiting = rows.find((r) => r.key === 'HIGH')?.awaiting ?? 0

  function open(key) {
    setFindingsFilter('all') // surface every finding of this severity, any status
    navigateToFindings(setActiveTab, { sev: key })
  }

  if (loading) {
    return (
      <div className="flex h-full flex-col gap-3" aria-busy="true">
        <Skeleton className="h-12 w-full" />
        {rows.map((r) => (
          <Skeleton key={r.key} className="h-8 w-full" />
        ))}
      </div>
    )
  }

  if (totalFindings === 0) {
    return <p className="text-sm text-muted-foreground">No findings recorded yet — confidence appears once findings exist.</p>
  }

  return (
    <div className="flex h-full flex-col gap-3">
      {/* Callout — the at-a-glance "what needs me" number + the scale. */}
      <div className="flex items-stretch gap-3">
        <div className="flex-1 rounded-lg border border-sev-high/30 bg-sev-high/5 px-3 py-2">
          <div className="tnum font-display text-2xl font-bold leading-none text-sev-high">{highAwaiting}</div>
          <div className="mt-1 text-[10px] uppercase tracking-wider text-muted-foreground">High awaiting review</div>
        </div>
        <div className="flex-1 rounded-lg border border-border bg-secondary/40 px-3 py-2">
          <div className="tnum font-display text-2xl font-bold leading-none text-foreground">{totalFindings}</div>
          <div className="mt-1 text-[10px] uppercase tracking-wider text-muted-foreground">findings total</div>
        </div>
      </div>

      <ul className="flex flex-1 flex-col gap-1.5" aria-label="Confidence distribution — select a tier to filter findings">
        {rows.map((r) => (
          <li key={r.key} className="flex-1">
            <button
              type="button"
              onClick={() => open(r.key)}
              aria-label={`${r.label}: ${r.count} finding${r.count === 1 ? '' : 's'}${r.awaiting ? `, ${r.awaiting} awaiting review` : ''}. Filter findings to ${r.label} confidence.`}
              className="flex h-full w-full flex-col justify-center gap-1 rounded-md px-2 py-1.5 text-left transition-colors hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              <div className="flex items-center justify-between gap-2 text-xs">
                <span className={cn('font-medium', r.cls.text)}>{r.label}</span>
                <span className="flex items-center gap-2.5">
                  {r.recent > 0 && <span className="tnum text-[10px] font-medium text-status-approved">+{r.recent} · 24h</span>}
                  {r.awaiting > 0 && <span className="tnum text-[10px] text-muted-foreground">{r.awaiting} awaiting</span>}
                  <span className={cn('tnum w-6 text-right font-semibold', r.cls.text)}>{r.count}</span>
                </span>
              </div>
              <div className="h-2.5 w-full overflow-hidden rounded-full bg-secondary">
                <motion.div
                  className={cn('h-full rounded-full', r.cls.bg)}
                  style={{ width: `${r.pct}%`, transformOrigin: 'left' }}
                  variants={variants.severityBarFill}
                  initial="hidden"
                  animate="show"
                />
              </div>
            </button>
          </li>
        ))}
      </ul>
    </div>
  )
}
