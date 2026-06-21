import { Check } from 'lucide-react'

import { cn } from '@/lib/utils'
import {
  normEventType,
  humanizeGap,
  TIMELINE_TYPE_CLASS,
  TIMELINE_TYPE_BG,
} from '@/components/common/entity-utils'

// ─────────────────────────────────────────────────────────────────────────
// TimelineEvent — a single chronological row (legacy parity): optional gap +
// date separators, a type-coloured dot, UTC time, the [type] tag, the
// description, finding cross-links (auto-linked-from · related · finding_refs),
// and an approved check. Mission-Control reskin: token classes only, lucide
// check, hover row tint. Finding links call onNavigate(fid).
// ─────────────────────────────────────────────────────────────────────────

const GAP_THRESHOLD_MS = 30 * 60 * 1000 // 30 min

function FindingLink({ fid, onNavigate, label }) {
  return (
    <button
      type="button"
      onClick={() => onNavigate(fid)}
      className="mono rounded text-primary transition-colors hover:underline focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
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
        <div className="my-1 flex items-center gap-2">
          <div className="h-px flex-1 bg-border-faint" />
          <span className="mono shrink-0 rounded-full border border-sev-med bg-sev-med/10 px-1.5 py-px text-[10px] text-sev-med">
            ▲ {humanizeGap(gap)} gap
          </span>
          <div className="h-px flex-1 bg-border-faint" />
        </div>
      )}
      {showDateSep && (
        <div className="my-3 flex items-center gap-3">
          <span className="mono whitespace-nowrap text-[10px] text-muted-foreground">
            {new Date(ev.timestamp).toISOString().substring(0, 10)}
            {ev.host && ` · ${ev.host}`}
          </span>
          <div className="h-px flex-1 bg-border-faint" />
        </div>
      )}

      <div className="group flex items-start gap-2 rounded px-2 py-1 transition-colors hover:bg-secondary/50">
        <span className={cn('mt-1.5 size-1.5 shrink-0 rounded-full', dotClass)} />
        <span className="mono w-16 shrink-0 text-[11px] text-muted-foreground">
          {new Date(ev.timestamp).toISOString().substring(11, 19)}
        </span>
        <span className={cn('mono w-16 shrink-0 text-[10px] capitalize', typeTextClass)}>
          {rawType ? `[${rawType}]` : ''}
        </span>

        <div className="min-w-0 flex-1">
          <div className="text-xs text-foreground">{ev.description}</div>
          {(hasAutoLink || hasRelated) && (
            <div className="mono mt-0.5 flex flex-wrap gap-x-2 text-[10px] text-muted-foreground">
              {hasAutoLink && (
                <span>
                  auto-linked from <FindingLink fid={ev.auto_created_from} onNavigate={onNavigate} />
                </span>
              )}
              {hasRelated && (
                <span className="flex flex-wrap gap-x-1">
                  related:
                  {relatedFindings.map((fid) => (
                    <FindingLink key={fid} fid={fid} onNavigate={onNavigate} />
                  ))}
                </span>
              )}
            </div>
          )}
        </div>

        {ev.finding_refs?.map((fid) => (
          <span key={fid} className="shrink-0">
            <FindingLink fid={fid} onNavigate={onNavigate} />
          </span>
        ))}
        {ev.status === 'approved' && (
          <Check className="size-3 shrink-0 text-status-approved" aria-label="approved" />
        )}
      </div>
    </div>
  )
}
