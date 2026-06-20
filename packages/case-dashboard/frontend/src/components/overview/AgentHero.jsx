import { motion } from 'framer-motion'

import { cn } from '@/lib/utils'
import { useStoreSlice } from '@/store/useStore'
import { useMotionVariants, useCountUp } from '@/lib/motion'
import { deriveAgentState } from '@/lib/agent-state'
import { Card } from '@/components/ui/card'
import { MiniSparkline } from '@/components/overview/MiniSparkline'

// ─────────────────────────────────────────────────────────────────────────
// AgentHero — the Mission-Control hero. The living agent orb (breathingOrb core
// + two staggered pingRings), the current agent state, the headline, the gated-
// action stat strip (count-up numerals), and a finding-velocity glance. When the
// agent is awaiting authorization the whole card gets the slow authGlowPulse so
// the operator's eye is pulled to the pending-authorization state. All motion is
// reduced-motion gated through useMotionVariants / useCountUp; the data reads
// immediately. Agent fields come from the EXISTING portalState slice (contract
// in lib/agent-state.js); nothing here fabricates a live backend.
// ─────────────────────────────────────────────────────────────────────────

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

export function AgentHero() {
  const variants = useMotionVariants()
  const { portalState, chainStatus, delta, findings } = useStoreSlice((s) => ({
    portalState: s.portalState,
    chainStatus: s.chainStatus,
    delta: s.delta,
    findings: s.findings,
  }))

  const agent = deriveAgentState(portalState, chainStatus, delta)

  return (
    <Card
      className={cn(
        'relative gap-0 overflow-hidden p-5',
        agent.glow && 'ring-1 ring-primary/30',
      )}
    >
      {/* Awaiting-auth glow wash (authGlowPulse) — decorative, behind content. */}
      {agent.glow && (
        <motion.div
          aria-hidden
          variants={variants.authGlowPulse}
          animate="animate"
          className="pointer-events-none absolute -inset-px -z-0 bg-gradient-to-br from-primary/15 via-transparent to-transparent"
        />
      )}

      <div className="relative z-10 flex gap-5">
        <AgentOrb variants={variants} />

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2.5">
            <span className="mono text-[10px] font-semibold uppercase tracking-[0.14em] text-primary">
              Autonomous Investigator
            </span>
            <span className={cn('inline-flex items-center gap-1.5 rounded-full border border-primary/30 bg-primary/10 px-2 py-0.5 text-[11px] font-medium', agent.text)}>
              <motion.span
                aria-hidden
                variants={variants.statusDotPulse}
                animate="animate"
                className={cn('size-1.5 rounded-full', agent.dot)}
              />
              {agent.label}
            </span>
          </div>

          <p className="mt-2 max-w-[56ch] text-sm leading-relaxed text-foreground">{agent.headline}</p>

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
