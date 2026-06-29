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

// ── Confidence chip (colored dot + categorical label + cap affordance) ──
// P35-11: shows the model's CATEGORICAL confidence (High/Medium/Low) as text —
// never a numeric % derived from CONF_SCORE, which fabricated precision the
// model never reported. Color stays a token (category → CONF_CLASS), not raw.
// When the two-axis ceiling clamped the agent's self-assessed confidence
// (`confidence_derivation.clamped`), a muted "· capped" affordance is appended
// so an examiner can tell at a glance the shown value was lowered by provenance,
// not asserted. The cap detail rides the title only (escaped React attribute).

export function ConfChip({ confidence, derivation }) {
  const meta = confClass(confidence)
  if (!meta) return null
  const clamped = derivation?.clamped === true
  return (
    <span title={`Model confidence · ${meta.label}`} className={`${CHIP_BASE} text-text-muted`}>
      <span aria-hidden className={cn('inline-block size-[7px] shrink-0 rounded-full', meta.bg)} />
      <span className={meta.text}>Confidence: {meta.label}</span>
      {clamped && (
        <span
          className="text-text-muted"
          title={`model said ${derivation.agent ?? 'unknown'} → capped to ${derivation.final ?? meta.label}`}
        >
          · capped
        </span>
      )}
    </span>
  )
}

// ── Grounding chip (Axis-B external-knowledge corroboration) ────────────
// Surfaces how many DISTINCT external-knowledge backends corroborated the
// finding (forensic-rag / windows-triage / opencti). Legacy-safe: renders
// nothing when the finding carries no well-formed `grounding` block (rows that
// predate the two-axis model). The consulted-source list rides the title only —
// escaped as a React attribute value, so an injected source string can't break
// out; the level/count render as escaped text nodes.

export function GroundingChip({ grounding }) {
  if (typeof grounding?.level !== 'string') return null
  const count = Number.isFinite(grounding.sources_count) ? grounding.sources_count : 0
  const sources = Array.isArray(grounding.sources_consulted) ? grounding.sources_consulted : []
  const title = sources.length ? `Sources consulted: ${sources.join(', ')}` : 'No external-knowledge sources cited'
  return (
    <span title={title} className={`${CHIP_BASE} text-text-muted`}>
      Grounding: {grounding.level} ({count})
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
