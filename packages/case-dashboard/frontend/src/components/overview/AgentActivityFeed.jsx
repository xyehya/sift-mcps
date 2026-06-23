import { AnimatePresence, motion } from 'framer-motion'

import { cn } from '@/lib/utils'
import { useMotionVariants } from '@/lib/motion'
import { useStoreSlice } from '@/store/useStore'

// ─────────────────────────────────────────────────────────────────────────
// AgentActivityFeed — right-column live tail (handoff §Screen 1, right col #2).
// Renders the DB-backed audit tail populated by useDataPolling. Each row: mono
// time + colored kind-dot + event text, reduced-motion gated via variants.
// ─────────────────────────────────────────────────────────────────────────

const FEED_CAP = 60

const KIND_DOT = {
  analysis: 'bg-primary',
  discovery: 'bg-status-approved',
  io: 'bg-sev-low',
  alert: 'bg-sev-high',
  info: 'bg-muted-foreground',
}

function formatEventTime(ts) {
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return '--:--:--'
  return [d.getHours(), d.getMinutes(), d.getSeconds()]
    .map((n) => String(n).padStart(2, '0'))
    .join(':')
}

/** Single activity row — mono time + dot + event text. */
function ActivityRow({ event, variants }) {
  return (
    <motion.li
      layout
      variants={variants.activityTailItem}
      initial="hidden"
      animate="show"
      exit="exit"
      className="flex items-start gap-2 py-1.5 text-xs"
    >
      <span className="mono shrink-0 text-[10px] leading-4 text-muted-foreground">{formatEventTime(event.ts)}</span>
      <span
        aria-hidden
        className={cn('mt-1.5 size-1.5 shrink-0 rounded-full', KIND_DOT[event.kind] ?? KIND_DOT.info)}
      />
      <span className="min-w-0 flex-1 break-words leading-4 text-foreground">{event.text}</span>
    </motion.li>
  )
}

export function AgentActivityFeed() {
  const variants = useMotionVariants()
  const events = useStoreSlice((s) => (s.agentActivity ?? []).slice(0, FEED_CAP))

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      {/* Header */}
      <div className="flex items-center gap-2 pb-2">
        <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-muted-foreground">
          Agent activity
        </span>
        <span className="inline-flex items-center gap-1 rounded-full border border-status-approved/30 bg-status-approved/10 px-2 py-0.5 text-[10px] font-medium text-status-approved">
          <span aria-hidden className="size-1.5 animate-pulse rounded-full bg-status-approved" />
          Live · tail
        </span>
      </div>

      {/* Scrollable feed */}
      <div className="min-h-0 flex-1 overflow-y-auto">
        <ul className="flex flex-col" aria-label="Agent activity feed" aria-live="polite" aria-atomic="false">
          {events.length > 0 ? (
            <AnimatePresence initial={false}>
              {events.map((ev) => (
                <ActivityRow key={ev.id} event={ev} variants={variants} />
              ))}
            </AnimatePresence>
          ) : (
            <li className="py-3 text-xs leading-5 text-muted-foreground">No agent activity recorded yet.</li>
          )}
        </ul>
      </div>
    </div>
  )
}
