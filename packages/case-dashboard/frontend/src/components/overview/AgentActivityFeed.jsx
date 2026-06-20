import { useEffect, useRef, useState } from 'react'
import { AnimatePresence, motion } from 'framer-motion'

import { cn } from '@/lib/utils'
import { useMotionVariants } from '@/lib/motion'

// ─────────────────────────────────────────────────────────────────────────
// AgentActivityFeed — right-column live tail (handoff §Screen 1, right col #2).
// Retains up to 60 events; newest prepends on top with the shared `activityTailItem`
// slide-in. Each row: mono time + colored kind-dot + event text. Gated behind
// prefers-reduced-motion via useMotionVariants. Feed runs on an interval;
// driven from a pool of sample events in mock mode.
// ─────────────────────────────────────────────────────────────────────────

const FEED_CAP = 60

const KIND_DOT = {
  analysis: 'bg-primary',
  discovery: 'bg-status-approved',
  io: 'bg-sev-low',
  alert: 'bg-sev-high',
  info: 'bg-muted-foreground',
}

/** Sample event pool — provides realistic-looking live tail in mock/demo mode. */
const POOL = [
  { kind: 'analysis', text: 'MFT parsing: 412,309 records processed' },
  { kind: 'discovery', text: 'New artefact located: NTUSER.DAT (WS-07)' },
  { kind: 'analysis', text: 'EVTX correlation pass complete — 3 sources fused' },
  { kind: 'io', text: 'Evidence index updated: disk.img ← sector 2,048,512' },
  { kind: 'discovery', text: 'Lateral movement indicator: RDP session to DC-01' },
  { kind: 'alert', text: 'Policy guard triggered: mcp:acquire.memory blocked' },
  { kind: 'analysis', text: 'Registry hive parsed: SYSTEM\\CurrentControlSet' },
  { kind: 'io', text: 'Timeline entry written: 2026-06-14T04:12:39Z' },
  { kind: 'discovery', text: 'IOC match: 185.66.0.12 in threat intel feed' },
  { kind: 'analysis', text: 'Prefetch files scanned: 187 entries' },
  { kind: 'io', text: 'Shellbag analysis: 44 paths resolved' },
  { kind: 'discovery', text: 'Scheduled task artefact: svchost_helper found' },
  { kind: 'analysis', text: 'Volume shadow copy enumeration complete' },
  { kind: 'io', text: 'Jump list parsed: RecentDocs 29 entries' },
  { kind: 'discovery', text: 'Credential access pattern: LSASS read attempt' },
  { kind: 'info', text: 'Backend yara: scanner reloaded (rule update)' },
  { kind: 'analysis', text: 'WMI event subscription scan: 2 subscriptions found' },
  { kind: 'discovery', text: 'Persistence mechanism: Run key modification' },
]

function nowHHMMSS() {
  const d = new Date()
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
      <span className="mono shrink-0 text-[10px] leading-4 text-muted-foreground">{event.time}</span>
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
  const [events, setEvents] = useState(() =>
    POOL.slice(0, 8).map((e, i) => ({
      id: `init-${i}`,
      time: nowHHMMSS(),
      kind: e.kind,
      text: e.text,
    })),
  )
  const poolIdxRef = useRef(8)

  useEffect(() => {
    const id = setInterval(() => {
      const poolItem = POOL[poolIdxRef.current % POOL.length]
      poolIdxRef.current += 1
      const next = { id: `ev-${Date.now()}`, time: nowHHMMSS(), kind: poolItem.kind, text: poolItem.text }
      setEvents((prev) => [next, ...prev].slice(0, FEED_CAP))
    }, 4200)
    return () => clearInterval(id)
  }, [])

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
          <AnimatePresence initial={false}>
            {events.map((ev) => (
              <ActivityRow key={ev.id} event={ev} variants={variants} />
            ))}
          </AnimatePresence>
        </ul>
      </div>
    </div>
  )
}
