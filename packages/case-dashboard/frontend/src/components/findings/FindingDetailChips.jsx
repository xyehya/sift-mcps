// ─────────────────────────────────────────────────────────────────────────
// FindingDetail header chips — confidence (colored dot + categorical label),
// hash (jade seal + EV-id), and ATT&CK technique. Static chrome
// (border/background/text) and the confidence dot/label color use literal token
// utility classes (the confClass bundle carries `bg`/`text` strings — §5
// CONF_CLASS pattern).
// ─────────────────────────────────────────────────────────────────────────

import { cn } from '@/lib/utils'
import { confClass } from '@/components/findings/findings-utils'

const CHIP_BASE = 'mono inline-flex cursor-default items-center gap-1.5 rounded-[7px] border border-border-soft bg-bg-raised px-2 py-1 text-[11px] font-semibold'

// ── Confidence chip (colored dot + categorical label) ───────────────────
// P35-11: shows the model's CATEGORICAL confidence (High/Medium/Low) as text —
// never a numeric % derived from CONF_SCORE, which fabricated precision the
// model never reported. Color stays a token (category → CONF_CLASS), not raw.

export function ConfChip({ confidence }) {
  const meta = confClass(confidence)
  if (!meta) return null
  return (
    <span title={`Model confidence · ${meta.label}`} className={`${CHIP_BASE} text-text-muted`}>
      <span aria-hidden className={cn('inline-block size-[7px] shrink-0 rounded-full', meta.bg)} />
      <span className={meta.text}>Confidence: {meta.label}</span>
    </span>
  )
}

// ── Hash chip (jade seal icon + EV-id, hover = full sha256) ────────────

export function HashChip({ evId, sha }) {
  if (!evId && !sha) return null
  const label = evId ?? 'EV'
  const title = sha ? `sha256:${sha} · ${label}` : label
  return (
    <span title={title} className={`${CHIP_BASE} text-text-muted`}>
      {/* jade seal / shield-check icon */}
      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--jade)" strokeWidth="1.9" aria-hidden>
        <path d="M12 3l7 3v6c0 4.4-3 7.4-7 9-4-1.6-7-4.6-7-9V6z"/>
        <path d="m9 12 2 2 4-4"/>
      </svg>
      {label}
    </span>
  )
}

// ── ATT&CK chip ─────────────────────────────────────────────────────────

export function AttChip({ attId }) {
  if (!attId) return null
  return (
    <span className={`${CHIP_BASE} text-text-muted`}>
      ATT&amp;CK {attId}
    </span>
  )
}

// ── MITRE ATT&CK chip row (ALL techniques) ─────────────────────────────
// P35-12: the mounted detail must list EVERY technique id, not just the first.
// Read-only, escaped text. Renders nothing when there are no techniques.

export function MitreChips({ ids }) {
  if (!ids?.length) return null
  return (
    <div className="flex flex-wrap gap-1.5">
      {ids.map((id) => (
        <span key={id} className={`${CHIP_BASE} text-text-muted`}>
          ATT&amp;CK {id}
        </span>
      ))}
    </div>
  )
}
