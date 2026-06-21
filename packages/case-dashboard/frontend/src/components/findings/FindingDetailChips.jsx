// ─────────────────────────────────────────────────────────────────────────
// FindingDetail header chips — confidence (colored dot + NN%), hash (jade seal
// + EV-id), and ATT&CK technique. Static chrome (border/background/text) and
// the graded confidence dot/score color both use literal token utility classes
// (the grade object carries `dot`/`text` class strings — §5 CONF_CLASS pattern).
// ─────────────────────────────────────────────────────────────────────────

import { cn } from '@/lib/utils'

const CHIP_BASE = 'mono inline-flex cursor-default items-center gap-1.5 rounded-[7px] border border-border-soft bg-bg-raised px-2 py-1 text-[11px] font-semibold'

// ── Confidence chip (colored dot + NN%) ────────────────────────────────

export function ConfChip({ score, grade }) {
  if (score == null) return null
  const title = `Model confidence · ${score}%`
  // Graded color comes from literal token classes on the grade object; falls
  // back to muted when the score is ungraded.
  const dotCls = grade?.dot ?? 'bg-text-muted'
  const textCls = grade?.text ?? 'text-text-muted'
  return (
    <span title={title} className={`${CHIP_BASE} text-text-muted`}>
      <span aria-hidden className={cn('inline-block size-[7px] shrink-0 rounded-full', dotCls)} />
      <span className={textCls}>{score}%</span>
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
