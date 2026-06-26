import { motion } from 'framer-motion'

import { cn } from '@/lib/utils'
import { useMotionVariants } from '@/lib/motion'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'

// ─────────────────────────────────────────────────────────────────────────
// EntityShell + EntityEmptyState + OverflowTags + ChipList — the shared chrome
// for the entity tabs. EntityShell owns the ONE primary scroll (h-full
// overflow-y-auto, §8) and the fadeRise entrance. The page header is the
// approved bar (font-display 22px H1 + mono eyebrow); the static "(N total)"
// count chrome is removed — only a live, filter-reactive "N shown" appears, and
// only while a filter narrows the set (Design-Polish §A / §B3). Reused by
// Hosts / Accounts / IOCs / Timeline so the four tabs share one IA.
// ─────────────────────────────────────────────────────────────────────────

/**
 * Page shell. `subtitle` is the mono eyebrow under the H1. `shownCount` /
 * `totalCount` render a subtle live "N shown" only when shownCount < totalCount
 * (i.e. a filter is active); the default unfiltered view shows no count chrome.
 */
export function EntityShell({
  title,
  subtitle,
  shownCount,
  totalCount,
  filterBar,
  children,
  ariaLabel,
}) {
  const variants = useMotionVariants()
  const filtering =
    shownCount != null && totalCount != null && shownCount < totalCount

  return (
    <div className="h-full min-h-0 overflow-y-auto">
      <motion.section
        variants={variants.fadeRise}
        initial="hidden"
        animate="show"
        aria-label={ariaLabel ?? title}
        className="mx-auto flex w-full max-w-6xl flex-col gap-4 p-5 sm:p-6"
      >
        <header className="flex flex-col gap-3 border-b border-border-faint pb-4">
          <div className="flex flex-wrap items-end justify-between gap-2">
            <div className="flex flex-col gap-1">
              <h1 className="font-display text-[22px] font-bold leading-none tracking-[-0.4px] text-foreground">
                {title}
              </h1>
              {subtitle && (
                <p className="mono text-[10px] uppercase tracking-[.12em] text-muted-foreground">
                  {subtitle}
                </p>
              )}
            </div>
            {filtering && (
              <span
                className="mono text-[10px] tabular-nums text-muted-foreground"
                aria-live="polite"
              >
                {shownCount} shown
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
      {Icon && <Icon className="mb-3 size-10 text-muted-foreground opacity-30" aria-hidden />}
      <p className="text-sm font-medium text-foreground">{title}</p>
      {hint && <p className="mt-1 max-w-sm text-xs text-muted-foreground">{hint}</p>}
    </div>
  )
}

/**
 * OverflowTags — renders the first `max` chips, then a single `+N` chip whose
 * tooltip lists the remaining items (Design-Polish §B6). Never breaks the row:
 * the visible chips wrap and the overflow folds behind one affordance. Each
 * chip is rendered by `renderChip(item)` so callers control tone.
 */
export function OverflowTags({ items, max = 2, renderChip, empty = '—' }) {
  const list = items ?? []
  if (list.length === 0) return <span className="text-text-ghost">{empty}</span>

  const head = list.slice(0, max)
  const rest = list.slice(max)

  return (
    <div className="flex flex-wrap items-center gap-1">
      {head.map((item, i) => (
        <span key={typeof item === 'string' ? item : i}>{renderChip(item)}</span>
      ))}
      {rest.length > 0 && (
        <Tooltip>
          <TooltipTrigger asChild>
            <button
              type="button"
              aria-label={`${rest.length} more: ${rest.join(', ')}`}
              className="mono inline-flex shrink-0 cursor-default items-center rounded-full border border-border-soft bg-muted/40 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            >
              +{rest.length}
            </button>
          </TooltipTrigger>
          <TooltipContent className="mono max-w-[240px] text-[11px]">
            {rest.join(' · ')}
          </TooltipContent>
        </Tooltip>
      )}
    </div>
  )
}

/** Host/IP/account chip row used inside cells (wraps; never truncates a cell). */
export function ChipList({ items, max, empty = '—' }) {
  const list = items ?? []
  if (list.length === 0) return <span className="text-text-ghost">{empty}</span>
  return (
    <div className={cn('flex flex-wrap gap-1', max && 'max-w-[220px]')}>
      {list.map((item) => (
        <span
          key={item}
          className="mono rounded border border-border-faint bg-bg-raised px-1.5 py-0.5 text-[10px] text-muted-foreground"
        >
          {item}
        </span>
      ))}
    </div>
  )
}
