import { useState } from 'react'
import { motion } from 'framer-motion'
import { ChevronDown, ChevronUp } from 'lucide-react'

import { cn } from '@/lib/utils'
import { useStoreSlice } from '@/store/useStore'
import { useMotionVariants, useCountUp } from '@/lib/motion'
import { deriveAgentState, agentSynopsis, blockedActions } from '@/lib/agent-state'
import { Card } from '@/components/ui/card'
import { MiniSparkline } from '@/components/overview/MiniSparkline'

// ─────────────────────────────────────────────────────────────────────────
// AgentHero — the Mission-Control hero. The living agent orb (breathingOrb core
// + two staggered pingRings), the current agent state (an understated dot+label,
// NOT a bordered badge — RUN-4c #38 removed the redundant "awaiting auth" chip),
// a DATA-DRIVEN case synopsis (agentSynopsis() — composed from case/portalState
// metadata, never hardcoded; long text truncates with a Show-more toggle), the
// gated-action stat strip (count-up numerals), and a finding-velocity glance.
// The card MINIMIZES: the orange status dot is the clickable re-expand toggle,
// and the collapsed bar always surfaces the gated-action count so the critical
// state stays visible (RUN-4c #40). When awaiting authorization the whole card
// gets the slow authGlowPulse. All motion is reduced-motion gated.
// ─────────────────────────────────────────────────────────────────────────

const SYNOPSIS_CLAMP = 150 // chars beyond which the Show-more toggle appears

/** The living agent orb — breathing core + two staggered ping rings. */
function AgentOrb({ variants }) {
  return (
    <div className="relative size-16 shrink-0" aria-hidden>
      {[0, 1.4].map((delay) => (
        <motion.span
          key={delay}
          variants={variants.pingRing}
          animate="animate"
          transition={{ ...variants.pingRing.animate?.transition, delay }}
          className="absolute inset-0 rounded-full border border-primary/70"
        />
      ))}
      <motion.span
        variants={variants.breathingOrb}
        animate="animate"
        className="absolute inset-3 rounded-full bg-gradient-to-br from-primary to-primary/60 shadow-[0_0_24px_var(--primary)]"
      />
    </div>
  )
}

function StatCell({ value, label }) {
  const counted = useCountUp(Number(value) || 0)
  const rounded = Math.round(counted)
  const display = rounded >= 1_000_000 ? `${(rounded / 1_000_000).toFixed(2)}M` : rounded.toLocaleString()
  return (
    <div className="min-w-0">
      <div className="tnum font-display text-2xl font-bold leading-none text-foreground">{display}</div>
      <div className="mt-1 text-[10px] uppercase tracking-[0.12em] text-muted-foreground">{label}</div>
    </div>
  )
}

/** State dot — pulses when awaiting auth; colour carried by the state token class. */
function StateDot({ variants, agent, className }) {
  return (
    <motion.span
      aria-hidden
      variants={variants.statusDotPulse}
      animate="animate"
      className={cn('rounded-full', agent.dot, className)}
    />
  )
}

export function AgentHero() {
  const variants = useMotionVariants()
  const [collapsed, setCollapsed] = useState(false)
  const [synopsisOpen, setSynopsisOpen] = useState(false)
  const { portalState, chainStatus, delta, findings, activeCase } = useStoreSlice((s) => ({
    portalState: s.portalState,
    chainStatus: s.chainStatus,
    delta: s.delta,
    findings: s.findings,
    activeCase: s.activeCase,
  }))

  const agent = deriveAgentState(portalState, chainStatus, delta)
  const synopsis = agentSynopsis(portalState, activeCase, agent)
  const blocked = blockedActions(portalState)
  const blockedCount = blocked.length
  const gatedLabel =
    blockedCount > 0
      ? `${blockedCount} tool call${blockedCount === 1 ? '' : 's'} blocked by policy guards`
      : 'No blocked actions'

  // ── Collapsed: a compact bar that still surfaces state + the gated count. ──
  if (collapsed) {
    return (
      <Card className={cn('relative gap-0 overflow-hidden p-0', agent.glow && 'ring-1 ring-primary/30')}>
        <button
          type="button"
          onClick={() => setCollapsed(false)}
          aria-expanded={false}
          aria-label={`Expand agent panel — ${agent.label}, ${gatedLabel}`}
          className="flex w-full items-center gap-3 rounded-xl p-3.5 text-left transition-colors hover:bg-secondary/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          {/* The orange status dot is the clickable re-expand toggle (RUN-4c #40). */}
          <StateDot variants={variants} agent={agent} className="size-2.5 shrink-0" />
          <span className="mono text-[10px] font-semibold uppercase tracking-[0.14em] text-primary">
            Autonomous Investigator
          </span>
          <span aria-hidden className="text-border">·</span>
          <span className={cn('truncate text-xs font-medium', blockedCount > 0 ? 'text-sev-high' : 'text-muted-foreground')}>
            {gatedLabel}
          </span>
          <ChevronDown className="ml-auto size-4 shrink-0 text-muted-foreground" aria-hidden />
        </button>
      </Card>
    )
  }

  // ── Expanded ──
  return (
    <Card className={cn('relative gap-0 overflow-hidden p-5', agent.glow && 'ring-1 ring-primary/30')}>
      {/* Awaiting-auth glow wash (authGlowPulse) — decorative, behind content. */}
      {agent.glow && (
        <motion.div
          aria-hidden
          variants={variants.authGlowPulse}
          animate="animate"
          className="pointer-events-none absolute -inset-px -z-0 bg-gradient-to-br from-primary/15 via-transparent to-transparent"
        />
      )}

      {/* Minimize control (top-right). */}
      <button
        type="button"
        onClick={() => setCollapsed(true)}
        aria-expanded
        aria-label="Minimize agent panel"
        className="absolute right-3 top-3 z-10 flex size-7 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <ChevronUp className="size-4" aria-hidden />
      </button>

      <div className="relative z-[1] flex gap-5">
        <AgentOrb variants={variants} />

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 pr-8">
            <span className="mono text-[10px] font-semibold uppercase tracking-[0.14em] text-primary">
              Autonomous Investigator
            </span>
            {/* State = quiet dot + label (the bordered badge was removed, #38). */}
            <span className="inline-flex items-center gap-1.5 text-[11px] font-medium">
              <StateDot variants={variants} agent={agent} className="size-1.5" />
              <span className={agent.text}>{agent.label}</span>
            </span>
          </div>

          {synopsis && (
            <div className="mt-2">
              <p
                className={cn(
                  'max-w-[60ch] text-sm leading-relaxed text-foreground',
                  !synopsisOpen && 'line-clamp-2',
                )}
              >
                {synopsis}
              </p>
              {synopsis.length > SYNOPSIS_CLAMP && (
                <button
                  type="button"
                  onClick={() => setSynopsisOpen((v) => !v)}
                  aria-expanded={synopsisOpen}
                  className="mt-1 rounded text-xs font-medium text-primary transition-colors hover:text-primary/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  {synopsisOpen ? 'Show less' : 'Show more'}
                </button>
              )}
            </div>
          )}

          <div className="mt-4 flex flex-wrap items-end gap-x-6 gap-y-3">
            {agent.metrics.map((m) => (
              <StatCell key={m.key} value={m.value} label={m.label} />
            ))}
            <div className="ml-auto hidden self-center sm:block">
              <MiniSparkline findings={findings} />
            </div>
          </div>
        </div>
      </div>
    </Card>
  )
}
