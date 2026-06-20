import { motion, useReducedMotion } from 'framer-motion'

import { cn } from '@/lib/utils'
import { EASE } from '@/lib/motion'
import { severityCounts } from '@/components/overview/overview-metrics'
import { Skeleton } from '@/components/ui/skeleton'

// ─────────────────────────────────────────────────────────────────────────
// Severity (confidence) distribution — horizontal bars in --sev-* tokens that
// grow on mount via scaleX (transform-only → reduced-motion collapses to the
// final state, so the data is readable immediately; spec §2). The numeric
// count uses tabular figures. Bar widths are data-driven inline styles (the
// only inline style permitted), never raw hex.
// ─────────────────────────────────────────────────────────────────────────

export function SeverityDistribution({ findings, loading }) {
  const reduced = useReducedMotion()
  const rows = severityCounts(findings)
  const totalFindings = rows.reduce((s, r) => s + r.count, 0)

  if (loading) {
    return (
      <div className="space-y-3" aria-busy="true">
        {rows.map((r) => (
          <Skeleton key={r.key} className="h-5 w-full" />
        ))}
      </div>
    )
  }

  if (totalFindings === 0) {
    return <p className="text-sm text-muted-foreground">No findings recorded yet — severity appears once findings exist.</p>
  }

  return (
    <ul className="flex flex-col gap-2.5" aria-label="Severity distribution">
      {rows.map((r) => (
        <li key={r.key} className="flex items-center gap-3 text-xs">
          <span className={cn('w-24 shrink-0 font-medium', r.cls.text)}>{r.label}</span>
          <span className={cn('tnum w-6 shrink-0 text-right font-semibold', r.cls.text)}>{r.count}</span>
          <div className="h-2 flex-1 overflow-hidden rounded-full bg-secondary">
            <motion.div
              className={cn('h-full rounded-full', r.cls.bg)}
              style={{ width: `${r.pct}%`, transformOrigin: 'left' }}
              initial={reduced ? false : { scaleX: 0 }}
              animate={{ scaleX: 1 }}
              transition={reduced ? { duration: 0 } : { duration: 0.5, ease: EASE }}
            />
          </div>
        </li>
      ))}
    </ul>
  )
}
