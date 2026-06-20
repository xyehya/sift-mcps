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
import { AgentHero } from '@/components/overview/AgentHero'
import { AuthorizationQueue } from '@/components/overview/AuthorizationQueue'
import { MissionStats } from '@/components/overview/MissionStats'

// ─────────────────────────────────────────────────────────────────────────
// Overview → Mission Control (spec §4 / RUN-4b). The agent-supervision landing:
// the agent hero + the Authorization Required queue (the page hero — gated MCP
// actions the agent cannot self-approve) + the mission KPI tiles, over the
// retained RUN-3 analytics (findings KPI row, finding-velocity, severity
// distribution, recent activity, evidence-chain summary, MITRE, case brief).
// A faint ambient field (orange aurora + drifting hairline grid, reduced-motion
// gated) sits behind the content. Reads only EXISTING polled store slices +
// portalState — the useStore.interface contract stays frozen.
// ─────────────────────────────────────────────────────────────────────────

/** Card wrapper with a section title (consistent rhythm across the page). */
function Section({ title, action, children, className, contentClassName }) {
  return (
    <Card className={className}>
      <CardHeader className="flex flex-row items-center justify-between gap-2 pb-0">
        <CardTitle className="text-sm font-semibold">{title}</CardTitle>
        {action}
      </CardHeader>
      <CardContent className={contentClassName}>{children}</CardContent>
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
  const { activeCase, findings, delta, chainStatus, isLoading, user } = useStoreSlice((s) => ({
    activeCase: s.activeCase,
    findings: s.findings,
    delta: s.delta,
    chainStatus: s.chainStatus,
    isLoading: s.isLoading,
    user: s.user,
  }))

  const caseLabel = activeCase?.title || activeCase?.name || activeCase?.case_id
  const operator = user?.examiner || user?.email

  return (
    <div className="relative isolate">
      {/* Ambient field — orange aurora + drifting hairline grid, very low
          opacity, reduced-motion gated (see .ambient in globals.css). */}
      <div aria-hidden className="ambient" />

      <motion.section
        variants={variants.fadeRise}
        initial="hidden"
        animate="show"
        aria-label="Mission Control"
        className="relative z-10 mx-auto flex w-full max-w-7xl flex-col gap-6 p-4 sm:p-6"
      >
        <header className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex flex-col gap-1">
            <h1 className="text-2xl font-semibold tracking-tight text-foreground">Mission Control</h1>
            <p className="text-sm text-muted-foreground">
              Supervising the autonomous investigation · live agent state &amp; pending authorizations
            </p>
          </div>
          {(caseLabel || operator) && (
            <div className="mono text-right text-[10px] uppercase leading-relaxed tracking-wider text-muted-foreground">
              {caseLabel && <div>Case <span className="text-foreground">{caseLabel}</span></div>}
              {operator && <div>Operator <span className="text-foreground">{operator}</span></div>}
            </div>
          )}
        </header>

        {!activeCase && !isLoading ? (
          <NoCaseState />
        ) : (
          <>
            {/* Mission-Control hero: agent + authorization queue + KPI tiles. */}
            <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
              <div className="flex flex-col gap-6 lg:col-span-2">
                <AgentHero />
                <AuthorizationQueue />
              </div>
              <MissionStats />
            </div>

            <KpiRow />

            <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
              <Section title="Finding velocity" className="lg:col-span-2">
                <VelocityCard findings={findings} loading={isLoading} />
              </Section>
              <Section title="Severity distribution" contentClassName="flex-1">
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
    </div>
  )
}
