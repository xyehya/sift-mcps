import { useEffect, useRef, useState } from 'react'
import { motion } from 'framer-motion'
import { FolderOpen } from 'lucide-react'

import { useStoreSlice } from '@/store/useStore'
import { useMotionVariants } from '@/lib/motion'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { AgentHero } from '@/components/overview/AgentHero'
import { BlockedActionsPane } from '@/components/overview/BlockedActionsPane'
import { MissionStats } from '@/components/overview/MissionStats'
import { VelocityCard } from '@/components/overview/VelocityCard'
import { SeverityDistribution } from '@/components/overview/SeverityDistribution'
import { CaseContextCard } from '@/components/overview/CaseContextCard'
import { AgentActivityFeed } from '@/components/overview/AgentActivityFeed'
import { RecentFindings } from '@/components/overview/RecentFindings'

// ─────────────────────────────────────────────────────────────────────────
// Overview → Mission Control (handoff §Screen 1). Ground-up rebuild per the
// design handoff: 8fr/4fr CSS grid, session timer, agent hero → case brief →
// velocity+severity → blocked actions (left); stat tiles → agent activity →
// recent findings (right). MitreMatrix and EvidenceChainSummary are NOT on
// the Overview screen — do not import them here. The old "Recent activity"
// panel is replaced by the handoff's AgentActivityFeed + RecentFindings.
// Reads only EXISTING polled store slices + portalState — the useStore
// interface contract stays frozen.
// ─────────────────────────────────────────────────────────────────────────

/** Case nature → accent class for the chip. */
const NATURE_CLS = {
  INTRUSION: 'border-sev-high/40 text-sev-high bg-sev-high/10',
  intrusion: 'border-sev-high/40 text-sev-high bg-sev-high/10',
  EXFILTRATION: 'border-sev-med/40 text-sev-med bg-sev-med/10',
  exfiltration: 'border-sev-med/40 text-sev-med bg-sev-med/10',
  RANSOMWARE: 'border-status-staged/40 text-status-staged bg-status-staged/10',
  ransomware: 'border-status-staged/40 text-status-staged bg-status-staged/10',
}

function natureChipCls(nature) {
  return NATURE_CLS[nature] ?? 'border-border text-muted-foreground bg-secondary'
}

/** Live session elapsed clock — ticks every second, format hh:mm:ss. */
function useSessionElapsed() {
  const startRef = useRef(0)
  const [elapsed, setElapsed] = useState(0)
  useEffect(() => {
    startRef.current = Date.now()
    const id = setInterval(() => setElapsed(Math.floor((Date.now() - startRef.current) / 1000)), 1000)
    return () => clearInterval(id)
  }, [])
  const h = String(Math.floor(elapsed / 3600)).padStart(2, '0')
  const m = String(Math.floor((elapsed % 3600) / 60)).padStart(2, '0')
  const s = String(elapsed % 60).padStart(2, '0')
  return `${h}:${m}:${s}`
}

/** Minimal card with a section title. */
function Section({ title, children, className, contentClassName }) {
  return (
    <Card className={className}>
      <CardHeader className="pb-0">
        <CardTitle className="text-sm font-semibold">{title}</CardTitle>
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
  const sessionElapsed = useSessionElapsed()

  const { activeCase, findings, isLoading, user } = useStoreSlice((s) => ({
    activeCase: s.activeCase,
    findings: s.findings,
    isLoading: s.isLoading,
    user: s.user,
  }))

  const operator = user?.examiner || user?.email || 'E.VARGA'
  const operatorLabel = operator.toUpperCase()

  // Case brief: nature tag from incident_type or nature field
  const caseNature =
    (activeCase?.incident_type ?? activeCase?.nature ?? '').toUpperCase()
  const caseScope = activeCase?.affected_systems?.length > 0
    ? activeCase.affected_systems.join(' · ')
    : activeCase?.scope

  return (
    <div className="relative isolate flex min-h-full flex-col">
      {/* Ambient field — orange aurora + drifting hairline grid, reduced-motion gated. */}
      <div aria-hidden className="ambient" />

      <motion.section
        variants={variants.fadeRise}
        initial="hidden"
        animate="show"
        aria-label="Mission Control"
        className="relative z-10 mx-auto flex w-full max-w-7xl flex-1 flex-col gap-4 p-4 sm:p-6"
      >
        {/* ── Header ─────────────────────────────────────────────────────── */}
        <header className="flex flex-wrap items-start justify-between gap-3">
          <div className="flex flex-col gap-1">
            <h1 className="font-display text-[26px] font-bold leading-tight tracking-[-0.4px] text-foreground">
              Mission Control
            </h1>
            <p className="text-sm text-muted-foreground">
              Supervising the autonomous investigation · live agent state
            </p>
          </div>

          {/* Right-aligned mono session / operator readout */}
          <div className="mono flex flex-col items-end gap-0.5 text-[10px] uppercase tracking-[0.12em] text-muted-foreground">
            <span>
              Session{' '}
              <span className="tabular-nums text-foreground">{sessionElapsed}</span>{' '}
              elapsed
            </span>
            <span>
              Operator <span className="text-foreground">{operatorLabel}</span>
            </span>
          </div>
        </header>

        {!activeCase && !isLoading ? (
          <NoCaseState />
        ) : (
          /* ── Body: 8fr / 4fr grid (handoff §Screen 1) ─────────────────── */
          <div
            className="grid flex-1 gap-4"
            style={{ gridTemplateColumns: 'minmax(0,8fr) minmax(0,4fr)', alignItems: 'stretch' }}
          >
            {/* ═══════════════════════════════════
                LEFT COLUMN
                ═══════════════════════════════════ */}
            <div className="flex min-h-0 flex-col gap-4">

              {/* 1 — Hero: Autonomous Investigator */}
              <AgentHero />

              {/* 2 — Case Brief (flex:1 to fill remaining height) */}
              <Card className="flex flex-1 flex-col gap-0 p-0">
                <CardHeader className="flex flex-row flex-wrap items-center gap-2 border-b border-border p-4 pb-3">
                  {/* Doc icon */}
                  <span aria-hidden className="flex size-7 shrink-0 items-center justify-center rounded-md border border-border bg-secondary/60 text-muted-foreground">
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      className="size-3.5"
                      aria-hidden
                    >
                      <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                      <polyline points="14 2 14 8 20 8" />
                      <line x1="16" y1="13" x2="8" y2="13" />
                      <line x1="16" y1="17" x2="8" y2="17" />
                      <line x1="10" y1="9" x2="8" y2="9" />
                    </svg>
                  </span>

                  <CardTitle className="text-sm font-semibold">Case brief</CardTitle>

                  {caseNature && (
                    <span
                      className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.1em] ${natureChipCls(caseNature)}`}
                    >
                      {caseNature}
                    </span>
                  )}

                  {activeCase?.case_id && (
                    <span className="mono ml-auto text-[10px] text-muted-foreground">
                      {activeCase.case_id}
                    </span>
                  )}
                </CardHeader>

                <CardContent className="flex-1 overflow-y-auto p-4 pt-3">
                  {/* Scope line */}
                  {caseScope && (
                    <p className="mono mb-3 text-[11px] uppercase tracking-[0.1em] text-muted-foreground">
                      Scope {caseScope}
                    </p>
                  )}
                  <CaseContextCard activeCase={activeCase} />
                </CardContent>
              </Card>

              {/* 3 — Finding velocity + Severity (side-by-side) */}
              <div className="grid grid-cols-2 gap-4">
                <Section title="Finding velocity">
                  <VelocityCard findings={findings} loading={isLoading} />
                </Section>
                <Section title="Confidence" contentClassName="flex-1">
                  <SeverityDistribution findings={findings} loading={isLoading} />
                </Section>
              </div>

              {/* 4 — Blocked actions (read-only pane, flex-fills remaining left-col height) */}
              <div className="flex min-h-0 flex-1 flex-col">
                <BlockedActionsPane fill />
              </div>
            </div>

            {/* ═══════════════════════════════════
                RIGHT COLUMN
                ═══════════════════════════════════ */}
            <div className="flex min-h-0 flex-col gap-4">

              {/* 1 — 2×2 stat tiles (fixed height, no grow) */}
              <MissionStats />

              {/* 2 — Agent activity (live tail, flex-fills column) */}
              <Card className="flex min-h-0 flex-1 flex-col gap-0 p-4">
                <AgentActivityFeed />
              </Card>

              {/* 3 — Recent findings (flex-fills column) */}
              <Card className="flex min-h-0 flex-1 flex-col gap-0 p-4">
                <RecentFindings />
              </Card>
            </div>
          </div>
        )}
      </motion.section>
    </div>
  )
}
