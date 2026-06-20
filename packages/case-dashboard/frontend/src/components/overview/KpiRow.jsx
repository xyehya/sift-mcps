import { motion } from 'framer-motion'
import { FileSearch, CheckCircle2, Clock, GitCommitVertical } from 'lucide-react'

import { cn } from '@/lib/utils'
import { useStoreSlice } from '@/store/useStore'
import { navigateToTab } from '@/hooks/useHashRoute'
import { useMotionVariants } from '@/lib/motion'
import { deriveKpis } from '@/components/overview/overview-metrics'
import { Card } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'

// ─────────────────────────────────────────────────────────────────────────
// KPI row (spec §4) — Findings / Approved / Pending / Staged. Each card is a
// click-through: status cards deep-link to the filtered Findings tab; the
// Staged card shows review progress and opens the Commit Drawer. Cards lift on
// hover (transform-only, reduced-motion safe) and carry tooltip hints.
//
// Deep-link note: the hash router validates `#/<tab>` ids and strips query
// strings, so we navigate to `#/findings` AND set the store filter (the store
// is the in-memory source of truth, per useHashRoute). This is the canonical
// KPI → filtered-tab pattern Phase-1 agents copy.
// ─────────────────────────────────────────────────────────────────────────

function KpiCard({ icon: Icon, label, value, accent, hint, onClick, children, variants }) {
  return (
    <motion.div variants={variants} initial="rest" whileHover="hover" animate="rest">
      <Tooltip>
        <TooltipTrigger asChild>
          <Card
            role="button"
            tabIndex={0}
            aria-label={hint}
            onClick={onClick}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault()
                onClick()
              }
            }}
            className={cn(
              'cursor-pointer gap-3 py-4 transition-shadow',
              'hover:ring-2 hover:ring-primary/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
            )}
          >
            <div className="flex items-center justify-between px-5">
              <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">{label}</span>
              <Icon className={cn('size-4', accent)} aria-hidden />
            </div>
            <div className="px-5">
              <span className={cn('tnum font-display text-3xl font-bold leading-none', accent)}>{value}</span>
            </div>
            {children}
          </Card>
        </TooltipTrigger>
        <TooltipContent>{hint}</TooltipContent>
      </Tooltip>
    </motion.div>
  )
}

export function KpiRow() {
  const variants = useMotionVariants()
  const { summary, findings, delta, setActiveTab, setFindingsFilter, setCommitDrawerOpen } = useStoreSlice((s) => ({
    summary: s.summary,
    findings: s.findings,
    delta: s.delta,
    setActiveTab: s.setActiveTab,
    setFindingsFilter: s.setFindingsFilter,
    setCommitDrawerOpen: s.setCommitDrawerOpen,
  }))

  const { total, approved, pending, staged, reviewPct } = deriveKpis(summary, findings, delta)

  function goFindings(filter) {
    setFindingsFilter(filter)
    navigateToTab(setActiveTab, 'findings')
  }

  return (
    <motion.div
      variants={variants.staggerContainer}
      initial="hidden"
      animate="show"
      className="grid grid-cols-2 gap-4 lg:grid-cols-4"
    >
      <KpiCard
        variants={variants.staggerItem}
        icon={FileSearch}
        label="Findings"
        value={total}
        accent="text-chart-1"
        hint="View all findings"
        onClick={() => goFindings('all')}
      />
      <KpiCard
        variants={variants.staggerItem}
        icon={CheckCircle2}
        label="Approved"
        value={approved}
        accent="text-status-approved"
        hint="View approved findings"
        onClick={() => goFindings('approved')}
      />
      <KpiCard
        variants={variants.staggerItem}
        icon={Clock}
        label="Pending"
        value={pending}
        accent="text-status-pending"
        hint="Review pending findings"
        onClick={() => goFindings('pending')}
      />
      <KpiCard
        variants={variants.staggerItem}
        icon={GitCommitVertical}
        label="Staged"
        value={staged}
        accent="text-status-staged"
        hint={staged > 0 ? 'Open the commit drawer to review staged changes' : 'No staged changes to commit'}
        onClick={() => staged > 0 && setCommitDrawerOpen(true)}
      >
        <div className="flex flex-col gap-1 px-5">
          <Progress value={reviewPct} className="h-1.5" aria-label={`${reviewPct}% of findings staged`} />
          <span className="tnum text-[11px] text-muted-foreground">{reviewPct}% of findings staged</span>
        </div>
      </KpiCard>
    </motion.div>
  )
}
