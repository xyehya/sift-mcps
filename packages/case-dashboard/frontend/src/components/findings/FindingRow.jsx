import { Check, X } from 'lucide-react'

import { cn } from '@/lib/utils'
import { normStatus } from '@/components/findings/findings-utils'

// ─────────────────────────────────────────────────────────────────────────
// FindingsList row + active-host/account pill. The severity accent bar and the
// dual letter badges (severity over status) are colored from literal token
// class maps (§5 CONF_CLASS pattern) — no interpolated classes, no inline
// color. Numeric geometry on the accent bar (3px width) is a data-driven style.
// ─────────────────────────────────────────────────────────────────────────

// ── Severity meta + literal token classes ──────────────────────────────
// P0 model-shift: SPECULATIVE tier removed; only High / Medium / Low are valid.
const SEV_META = {
  HIGH:   { letter: 'H', label: 'High',   bar: 'bg-sev-high', badge: 'text-sev-high bg-sev-high/14 border-sev-high/28' },
  MEDIUM: { letter: 'M', label: 'Medium', bar: 'bg-sev-med',  badge: 'text-sev-med bg-sev-med/14 border-sev-med/28' },
  LOW:    { letter: 'L', label: 'Low',    bar: 'bg-sev-low',  badge: 'text-sev-low bg-sev-low/14 border-sev-low/28' },
}
const SEV_FALLBACK = { letter: '?', label: 'Unknown', bar: 'bg-text-muted', badge: 'text-text-muted bg-text-muted/14 border-text-muted/28' }

// ── Status meta + literal token classes ────────────────────────────────
const ST_META = {
  draft:    { letter: 'P', label: 'Pending',  badge: 'text-status-pending bg-status-pending/18 border-status-pending/28' },
  pending:  { letter: 'P', label: 'Pending',  badge: 'text-status-pending bg-status-pending/18 border-status-pending/28' },
  approved: { letter: 'A', label: 'Approved', badge: 'text-status-approved bg-status-approved/14 border-status-approved/28' },
  staged:   { letter: 'S', label: 'Staged',   badge: 'text-status-staged bg-status-staged/14 border-status-staged/28' },
  rejected: { letter: 'R', label: 'Rejected', badge: 'text-status-rejected bg-status-rejected/14 border-status-rejected/28' },
}

// ── Status/severity letter badge ───────────────────────────────────────

function LetterBadge({ tone, letter, title }) {
  return (
    <span
      title={title}
      className={cn(
        'mono inline-grid size-[22px] shrink-0 place-items-center rounded-[6px] border text-[10px] font-bold leading-none',
        tone,
      )}
    >
      {letter}
    </span>
  )
}

// ── Row (export) ───────────────────────────────────────────────────────

export function Row({ finding, active, selected, selectMode, staged, onClick }) {
  const sev = (finding.confidence ?? finding.severity ?? '').toUpperCase()
  const sevMeta = SEV_META[sev] ?? SEV_FALLBACK

  const rawStatus = normStatus(finding)
  // If there's a staged delta, reflect that status
  const displayStatus = staged ? staged.action : rawStatus
  const stMeta = ST_META[displayStatus] ?? ST_META.draft

  const rejected = rawStatus === 'rejected' && !staged

  // ATT&CK technique: first mitre_id if present
  const attId = finding.mitre_ids?.[0] ?? null

  // host · confidence
  const confNum = finding.confidence_score != null
    ? Math.round(finding.confidence_score)
    : sev === 'HIGH' ? 92 : sev === 'MEDIUM' ? 74 : sev === 'LOW' ? 48 : null

  const meta = finding.host && confNum != null
    ? `${finding.host} · ${confNum}%`
    : finding.host ?? (confNum != null ? `${confNum}%` : '')

  return (
    <button
      type="button"
      onClick={onClick}
      aria-current={active ? 'true' : undefined}
      className={cn(
        'group relative flex w-full items-stretch gap-0 text-left text-xs transition-colors',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring',
        active ? 'bg-bg-raised shadow-[inset_2px_0_0_0_var(--orange)]' : 'hover:bg-secondary/60',
        rejected && 'opacity-60',
      )}
    >
      {/* Severity accent bar (3px) — geometry is a data-driven numeric style */}
      <span
        aria-hidden
        className={cn('block w-[3px] shrink-0 self-stretch rounded-r-[2px] opacity-70', sevMeta.bar)}
      />

      <div className="flex flex-1 flex-col gap-0.5 overflow-hidden px-2.5 py-2.5">
        {/* ID row + ATT&CK chip */}
        <div className="flex items-center gap-1.5">
          {selectMode && (
            <span
              aria-hidden
              className={cn(
                'flex size-3.5 shrink-0 items-center justify-center rounded border',
                selected ? 'border-primary bg-primary text-primary-foreground' : 'border-border',
              )}
            >
              {selected && <Check className="size-2.5" />}
            </span>
          )}
          <span className="mono shrink-0 text-[10px] font-semibold text-text-muted">
            {finding.id}
          </span>
          {attId && (
            <span className="mono shrink-0 rounded border border-border-hard bg-transparent px-1 py-px text-[9px] font-semibold text-text-ghost">
              {attId}
            </span>
          )}
        </div>

        {/* Title */}
        <span className="truncate text-[12px] font-medium leading-snug text-text-bright">
          {finding.title}
        </span>

        {/* host · conf% */}
        {meta && (
          <span className="mono truncate text-[10px] text-text-ghost">
            {meta}
          </span>
        )}
      </div>

      {/* Dual letter badges: severity over status */}
      <div className="flex shrink-0 flex-col items-center justify-center gap-1 pr-2.5">
        <LetterBadge letter={sevMeta.letter} tone={sevMeta.badge} title={`${sevMeta.label} severity`} />
        <LetterBadge letter={stMeta.letter} tone={stMeta.badge} title={stMeta.label} />
      </div>
    </button>
  )
}

// ── ActivePill (host/account filter banners) (export) ──────────────────

export function ActivePill({ label, value, onClear }) {
  return (
    <div className="flex items-center justify-between border-b border-border-soft bg-bg-raised/60 px-3 py-1.5 text-[11px]">
      <span className="mono text-text-muted">
        {label}: <strong className="text-text-bright">{value}</strong>
      </span>
      <button type="button" onClick={onClear} aria-label={`Clear ${label} filter`} className="text-muted-foreground hover:text-destructive">
        <X className="size-3" />
      </button>
    </div>
  )
}
