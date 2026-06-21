import { motion } from 'framer-motion'

import { cn } from '@/lib/utils'
import { useMotionVariants } from '@/lib/motion'

// ─────────────────────────────────────────────────────────────────────────
// EntityShell + EntityEmptyState + FilterField — the shared chrome for the
// entity tabs. EntityShell owns the ONE primary scroll (h-full overflow-y-auto,
// §8) and the fadeRise entrance; the page header (display title + count) and a
// filter-bar slot sit above the flowing content. Reused by Hosts / Accounts /
// IOCs / Timeline so the four tabs share one IA instead of four divergent ones.
// ─────────────────────────────────────────────────────────────────────────

/** Page shell: header (title + count) + optional filter bar + flowing content. */
export function EntityShell({ title, count, countLabel = 'total', filterBar, children, ariaLabel }) {
  const variants = useMotionVariants()
  return (
    <div className="h-full overflow-y-auto">
      <motion.section
        variants={variants.fadeRise}
        initial="hidden"
        animate="show"
        aria-label={ariaLabel ?? title}
        className="mx-auto flex w-full max-w-6xl flex-col gap-4 p-5"
      >
        <header className="flex flex-col gap-3 border-b border-border-faint pb-3">
          <div className="flex flex-wrap items-baseline gap-2">
            <h1 className="font-display text-lg font-bold text-foreground">{title}</h1>
            {count != null && (
              <span className="mono text-xs text-muted-foreground">
                ({count} {countLabel})
              </span>
            )}
          </div>
          {filterBar}
        </header>
        {children}
      </motion.section>
    </div>
  )
}

/** Centered empty / no-match state with an icon and guidance copy. */
export function EntityEmptyState({ icon: Icon, title, hint }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-border-soft bg-card py-16 text-center">
      {Icon && <Icon className="mb-3 size-12 text-muted-foreground opacity-30" aria-hidden />}
      <p className="mono text-sm font-semibold text-foreground">{title}</p>
      {hint && <p className="mt-1 max-w-sm text-xs text-muted-foreground">{hint}</p>}
    </div>
  )
}

/** Host/IP/account chip row used inside cells. */
export function ChipList({ items, max, empty = '—' }) {
  const list = items ?? []
  if (list.length === 0) return <span className="text-text-ghost">{empty}</span>
  return (
    <div className={cn('flex flex-wrap gap-1', max && 'max-w-[200px]')}>
      {list.map((item) => (
        <span
          key={item}
          className="mono rounded bg-bg-raised px-1 py-0.5 text-[10px] text-muted-foreground"
        >
          {item}
        </span>
      ))}
    </div>
  )
}
