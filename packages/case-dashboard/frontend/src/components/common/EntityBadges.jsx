import { Triangle, Diamond, Circle } from 'lucide-react'

import { cn } from '@/lib/utils'
import { confClass } from './entity-utils'

// ─────────────────────────────────────────────────────────────────────────
// Shared entity badges (Mission-Control reskin of the legacy ConfidenceIcon +
// inline Badge that were copy-pasted across Hosts / Accounts / IOCs). Colour
// is carried ONLY by static token classes (no raw hex, no inline style), per
// AGENTS §3/§5. Shapes double-encode severity so meaning never rides on colour
// alone (ui-ux a11y `color-not-only`).
//   HIGH → filled triangle · MEDIUM → filled diamond · LOW → filled circle.
// ─────────────────────────────────────────────────────────────────────────

const CONF_ICON = {
  HIGH: Triangle,
  MEDIUM: Diamond,
  LOW: Circle,
  SPECULATIVE: Circle,
}

/** Small severity glyph (token text-colour inherited from the parent badge). */
export function ConfidenceIcon({ confidence }) {
  const Glyph = CONF_ICON[(confidence ?? '').toUpperCase()] ?? Circle
  return <Glyph className="size-3 shrink-0 fill-current" aria-hidden />
}

/**
 * EntityBadge — pill with a token colour `tone`. `tone` selects a static
 * class bundle so the JIT always emits the utilities.
 */
const TONE = {
  high: 'text-sev-high bg-sev-high/10 border-sev-high/30',
  med: 'text-sev-med bg-sev-med/10 border-sev-med/30',
  low: 'text-sev-low bg-sev-low/10 border-sev-low/30',
  approved: 'text-status-approved bg-status-approved/10 border-status-approved/30',
  pending: 'text-status-pending bg-status-pending/10 border-status-pending/30',
  rejected: 'text-status-rejected bg-status-rejected/10 border-status-rejected/30',
  muted: 'text-muted-foreground bg-muted/40 border-border-soft',
  accent: 'text-primary bg-primary/10 border-primary/30',
}

export function EntityBadge({ tone = 'muted', className, children }) {
  return (
    <span
      className={cn(
        'mono inline-flex w-fit items-center gap-1 rounded-full border px-1.5 py-0.5 text-[10px] uppercase tracking-wider',
        TONE[tone] ?? TONE.muted,
        className,
      )}
    >
      {children}
    </span>
  )
}

/** Confidence pill: severity glyph + label, coloured via the shared class map. */
export function ConfidenceBadge({ confidence }) {
  const meta = confClass(confidence)
  return (
    <span
      className={cn(
        'mono inline-flex w-fit items-center gap-1 rounded-full border px-1.5 py-0.5 text-[10px] uppercase tracking-wider',
        meta.text,
        meta.tint,
        meta.ring,
      )}
    >
      <ConfidenceIcon confidence={confidence} />
      {meta.label}
    </span>
  )
}

/** Status-summary cluster — only renders the non-zero counts. */
export function StatusSummary({ statuses }) {
  const { approved = 0, draft = 0, rejected = 0 } = statuses ?? {}
  if (!approved && !draft && !rejected) {
    return <span className="text-text-ghost">—</span>
  }
  return (
    <div className="flex flex-wrap gap-1.5">
      {approved > 0 && <EntityBadge tone="approved">{approved} Approved</EntityBadge>}
      {draft > 0 && <EntityBadge tone="pending">{draft} Draft</EntityBadge>}
      {rejected > 0 && <EntityBadge tone="rejected">{rejected} Rejected</EntityBadge>}
    </div>
  )
}
