import { Copy } from 'lucide-react'

import { cn } from '@/lib/utils'
import { confClass } from './entity-utils'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'

// ─────────────────────────────────────────────────────────────────────────
// Shared entity badges (Mission-Control reskin of the legacy ConfidenceIcon +
// inline Badge copy-pasted across Hosts / Accounts / IOCs). Colour is carried
// ONLY by static token classes (no raw hex, no inline style), per AGENTS §3/§5.
//
// Design-Polish §B2: the decorative severity SHAPE glyphs (triangle/diamond/
// circle) were ornament — confidence is already carried by a TEXT label paired
// with a token colour (satisfies §B5 color-not-only), so the glyph was dropped.
// Chips follow the approved bar: rounded-full border, 10px uppercase, font-
// semibold (Design-Polish §A · ui-ux `weight-hierarchy`).
// ─────────────────────────────────────────────────────────────────────────

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
  // IOC type dimension — violet, deliberately distinct from the sev/host hues
  // so "type/category" never reads as the same encoding as severity (§B5).
  type: 'text-status-staged bg-status-staged/10 border-status-staged/30',
}

export function EntityBadge({ tone = 'muted', className, children }) {
  return (
    <span
      className={cn(
        'mono inline-flex w-fit items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[.1em]',
        TONE[tone] ?? TONE.muted,
        className,
      )}
    >
      {children}
    </span>
  )
}

/** Confidence pill: token-coloured label only (no shape glyph — §B2). */
export function ConfidenceBadge({ confidence }) {
  const meta = confClass(confidence)
  return (
    <span
      className={cn(
        'mono inline-flex w-fit items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[.1em]',
        meta.text,
        meta.tint,
        meta.ring,
      )}
    >
      {meta.label}
    </span>
  )
}

/** Status-summary cluster — only renders the non-zero counts, wraps tidily. */
export function StatusSummary({ statuses }) {
  const { approved = 0, draft = 0, rejected = 0 } = statuses ?? {}
  if (!approved && !draft && !rejected) {
    return <span className="text-text-ghost">—</span>
  }
  return (
    <div className="flex flex-wrap items-center gap-1">
      {approved > 0 && <EntityBadge tone="approved">{approved} Approved</EntityBadge>}
      {draft > 0 && <EntityBadge tone="pending">{draft} Draft</EntityBadge>}
      {rejected > 0 && <EntityBadge tone="rejected">{rejected} Rejected</EntityBadge>}
    </div>
  )
}

/**
 * TruncatedValue — long monospace value (sha256, IOC value, long path):
 * truncates with ellipsis, exposes the FULL value via tooltip, and offers a
 * copy affordance (Design-Polish §B6). `onCopy(value)` is owned by the caller.
 */
export function TruncatedValue({ value, onCopy, maxWidthClass = 'max-w-[280px]', copyLabel }) {
  return (
    <div className="flex items-center gap-1.5">
      <Tooltip>
        <TooltipTrigger asChild>
          <span
            className={cn('mono cursor-default truncate text-[11px] text-foreground', maxWidthClass)}
          >
            {value}
          </span>
        </TooltipTrigger>
        <TooltipContent className="mono max-w-[360px] break-all text-[11px]">
          {value}
        </TooltipContent>
      </Tooltip>
      {onCopy && (
        <button
          type="button"
          onClick={() => onCopy(value)}
          aria-label={copyLabel ?? 'Copy value to clipboard'}
          className="rounded p-0.5 text-muted-foreground opacity-0 transition-opacity hover:bg-bg-raised group-hover:opacity-100 focus-visible:opacity-100 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
        >
          <Copy className="size-3" aria-hidden />
        </button>
      )}
    </div>
  )
}
