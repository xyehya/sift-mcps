import { motion } from 'framer-motion'
import { FolderOpen } from 'lucide-react'

import { useStoreSlice } from '@/store/useStore'
import { useMotionVariants } from '@/lib/motion'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { KpiRow } from '@/components/overview/KpiRow'
import { SeverityDistribution } from '@/components/overview/SeverityDistribution'
import { VelocityCard } from '@/components/overview/VelocityCard'
import { ActivityFeed } from '@/components/overview/ActivityFeed'
import { MitreMatrix } from '@/components/overview/MitreMatrix'
import { EvidenceChainSummary } from '@/components/overview/EvidenceChainSummary'
import { CaseContextCard } from '@/components/overview/CaseContextCard'

// ─────────────────────────────────────────────────────────────────────────
// Overview (spec §4) — the rich landing. Composes KPI row, severity bars,
// finding-velocity chart, recent-activity feed, MITRE matrix, evidence-chain
// summary and a case-brief readout. Reads only existing polled store slices
// (no new store keys — the useStore.interface contract is frozen). Designed
// empty / loading / no-case states, not afterthoughts. The global Header owns
// case id / chain / agent / role / theme / ⌘K — not duplicated here.
// ─────────────────────────────────────────────────────────────────────────

/** Card wrapper with a section title (consistent rhythm across the page). */
function Section({ title, action, children, className }) {
  return (
    <Card className={className}>
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-0">
        <CardTitle className="text-sm font-semibold">{title}</CardTitle>
        {action}
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  )
}

function NoCaseState() {
  return (
    <Card className="items-center gap-4 py-16 text-center">
      <CardContent className="flex flex-col items-center gap-4">
        <span aria-hidden className="flex size-14 items-center justify-center rounded-full bg-secondary text-muted-foreground">
          <FolderOpen className="size-7" />
        </span>
        <div className="flex flex-col gap-1">
          <h2 className="text-lg font-semibold text-foreground">No active case</h2>
          <p className="max-w-sm text-sm text-muted-foreground">
            Select or create a case from the case selector in the header to load findings, evidence and the
            investigation dashboard.
          </p>
        </div>
      </CardContent>
    </Card>
  )
}

export function OverviewTab() {
  const variants = useMotionVariants()
  const { activeCase, findings, delta, chainStatus, isLoading } = useStoreSlice((s) => ({
    activeCase: s.activeCase,
    findings: s.findings,
    delta: s.delta,
    chainStatus: s.chainStatus,
    isLoading: s.isLoading,
  }))

  const caseLabel = activeCase?.title || activeCase?.name || activeCase?.case_id

  return (
    <motion.section
      variants={variants.fadeRise}
      initial="hidden"
      animate="show"
      aria-label="Overview"
      className="mx-auto flex w-full max-w-7xl flex-col gap-6 p-4 sm:p-6"
    >
      <header className="flex flex-col gap-1">
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">Overview</h1>
        {caseLabel && <p className="mono text-sm text-muted-foreground">{caseLabel}</p>}
      </header>

      {!activeCase && !isLoading ? (
        <NoCaseState />
      ) : (
        <>
          <KpiRow />

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            <Section title="Finding velocity" className="lg:col-span-2">
              <VelocityCard findings={findings} loading={isLoading} />
            </Section>
            <Section title="Severity distribution">
              <SeverityDistribution findings={findings} loading={isLoading} />
            </Section>
          </div>

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
            <Section title="Recent activity" className="lg:col-span-2">
              <ActivityFeed findings={findings} delta={delta} loading={isLoading} />
            </Section>
            <div className="flex flex-col gap-6">
              <Section title="Evidence chain">
                <EvidenceChainSummary chainStatus={chainStatus} loading={isLoading} />
              </Section>
              <Section title="MITRE ATT&CK">
                <MitreMatrix findings={findings} />
              </Section>
            </div>
          </div>

          {activeCase && (
            <Section title="Case brief">
              <CaseContextCard activeCase={activeCase} />
            </Section>
          )}
        </>
      )}
    </motion.section>
  )
}
