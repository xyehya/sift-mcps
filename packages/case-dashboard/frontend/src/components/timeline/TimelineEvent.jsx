import { Check } from 'lucide-react'

import { cn } from '@/lib/utils'
import {
  normEventType,
  humanizeGap,
  TIMELINE_TYPE_CLASS,
  TIMELINE_TYPE_BG,
} from '@/components/common/entity-utils'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'

// ─────────────────────────────────────────────────────────────────────────
// TimelineEvent — a single chronological row (legacy parity): optional gap +
// date separators, a type-coloured dot, UTC time, a fixed-width [type] tag, the
// description, finding cross-links, and an approved check.
//
// Design-Polish (Timeline §C): the columns sit on a fixed rhythm so the type
// tag (e.g. "persistence") reads as its own column and is NOT overshadowed by
// the event description — time and type are fixed-width, the description flexes,
// links and the check trail at a stable right edge. The finding cross-links use
// body-weight mono (not exaggerated). The trailing check carries a Radix
// Tooltip + aria-label ("Approved finding") so the glyph's meaning is explicit
// (§B9). Type colours come straight from the shared token map (§B5).
// ─────────────────────────────────────────────────────────────────────────

const GAP_THRESHOLD_MS = 30 * 60 * 1000 // 30 min

function FindingLink({ fid, onNavigate, label }) {
  return (
    <button
      type="button"
      onClick={() => onNavigate(fid)}
      className="mono rounded text-[11px] font-medium text-primary transition-colors hover:underline focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
    >
      [{label ?? fid}]
    </button>
  )
}

export function TimelineEvent({ ev, prev, showDateSep, onNavigate }) {
  const typeKey = normEventType(ev)
  const dotClass = TIMELINE_TYPE_BG[typeKey] ?? TIMELINE_TYPE_BG.other
  const typeTextClass = TIMELINE_TYPE_CLASS[typeKey] ?? TIMELINE_TYPE_CLASS.other

  const gap = prev ? new Date(ev.timestamp).getTime() - new Date(prev.timestamp).getTime() : 0
  const showGap = gap > GAP_THRESHOLD_MS

  const relatedFindings = (ev.related_findings ?? []).filter((fid) => fid !== ev.auto_created_from)
  const hasAutoLink = !!ev.auto_created_from
  const hasRelated = relatedFindings.length > 0
  const rawType = ev.event_type || ev.type

  return (
    <div>
      {showGap && (
        <div className="my-1.5 flex items-center gap-2">
          <div className="h-px flex-1 bg-border-faint" />
          <span className="mono shrink-0 rounded-full border border-sev-med/40 bg-sev-med/10 px-2 py-0.5 text-[10px] text-sev-med">
            {humanizeGap(gap)} gap
          </span>
          <div className="h-px flex-1 bg-border-faint" />
        </div>
      )}
      {showDateSep && (
        <div className="mb-2 mt-4 flex items-center gap-3">
          <span className="mono whitespace-nowrap text-[10px] uppercase tracking-[.1em] text-muted-foreground">
            {new Date(ev.timestamp).toISOString().substring(0, 10)}
            {ev.host && ` · ${ev.host}`}
          </span>
          <div className="h-px flex-1 bg-border-faint" />
        </div>
      )}

      <div className="group grid grid-cols-[auto_4.5rem_6rem_minmax(0,1fr)_auto] items-center gap-x-3 rounded-md px-2 py-1.5 transition-colors hover:bg-secondary/50">
        {/* type-coloured dot */}
        <span className={cn('size-1.5 shrink-0 rounded-full', dotClass)} aria-hidden />

        {/* time — fixed column */}
        <span className="mono text-[11px] tabular-nums text-muted-foreground">
          {new Date(ev.timestamp).toISOString().substring(11, 19)}
        </span>

        {/* type tag — its own fixed column so persistence/lateral/etc read clearly */}
        <span className={cn('mono truncate text-[10px] font-semibold uppercase tracking-[.08em]', typeTextClass)}>
          {rawType || ''}
        </span>

        {/* description + cross-links — flexes */}
        <div className="min-w-0">
          <div className="truncate text-[13px] text-foreground">{ev.description}</div>
          {(hasAutoLink || hasRelated) && (
            <div className="mono mt-0.5 flex flex-wrap items-center gap-x-2 text-[10px] text-muted-foreground">
              {hasAutoLink && (
                <span className="flex items-center gap-1">
                  auto-linked from <FindingLink fid={ev.auto_created_from} onNavigate={onNavigate} />
                </span>
              )}
              {hasRelated && (
                <span className="flex flex-wrap items-center gap-x-1">
                  related:
                  {relatedFindings.map((fid) => (
                    <FindingLink key={fid} fid={fid} onNavigate={onNavigate} />
                  ))}
                </span>
              )}
            </div>
          )}
        </div>

        {/* trailing: finding refs + approved check, stable right edge */}
        <div className="flex shrink-0 items-center gap-2">
          {ev.finding_refs?.map((fid) => (
            <FindingLink key={fid} fid={fid} onNavigate={onNavigate} />
          ))}
          {ev.status === 'approved' && (
            <Tooltip>
              <TooltipTrigger asChild>
                <span
                  className="inline-flex cursor-default text-status-approved"
                  aria-label="Approved finding"
                >
                  <Check className="size-3.5" aria-hidden />
                </span>
              </TooltipTrigger>
              <TooltipContent>Approved finding</TooltipContent>
            </Tooltip>
          )}
        </div>
      </div>
    </div>
  )
}
