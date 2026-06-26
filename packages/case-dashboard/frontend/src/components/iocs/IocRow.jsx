import { Fragment } from 'react'
import { ChevronRight } from 'lucide-react'

import { cn } from '@/lib/utils'
import { fmtTs } from '@/components/common/entity-utils'
import { ConfidenceBadge, EntityBadge, TruncatedValue } from '@/components/common/EntityBadges'
import { OverflowTags } from '@/components/common/EntityShell'
import { iocHosts, iocStatusTone } from './iocs-utils'

// ─────────────────────────────────────────────────────────────────────────
// IocRow — one IOC table row plus its expandable detail (legacy parity). Main
// row: expand chevron, value (truncate + tooltip-full + copy, §B6), type,
// category, confidence, hosts (hidden when single-host), source-finding cross-
// links, status. Expanded panel: MITRE techniques (sub-techniques dimmed),
// tags, and an ID/examiner/created footer.
//
// Design-Polish §B5 colour semantics: the IOC *type* dimension uses the violet
// `type` tone, deliberately distinct from the severity/host hues so type never
// reads as the same encoding as confidence or a host chip. Category is plain
// muted text; host chips are neutral raised pills — three different encodings.
// ─────────────────────────────────────────────────────────────────────────

export function IocRow({ ioc, isExpanded, isSingleHost, colSpan, onToggle, onCopy, onFindingClick }) {
  const hosts = iocHosts(ioc)

  return (
    <Fragment>
      <tr className="group text-foreground transition-colors hover:bg-secondary/40">
        <td className="px-4 py-3 align-middle">
          <button
            type="button"
            onClick={() => onToggle(ioc.id)}
            aria-expanded={isExpanded}
            aria-label={isExpanded ? 'Collapse IOC detail' : 'Expand IOC detail'}
            className="text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
          >
            <ChevronRight className={cn('size-3.5 transition-transform', isExpanded && 'rotate-90')} aria-hidden />
          </button>
        </td>

        <td className="px-4 py-3 align-middle">
          <TruncatedValue value={ioc.value} onCopy={onCopy} copyLabel="Copy IOC value to clipboard" />
        </td>

        <td className="px-4 py-3 align-middle">
          <EntityBadge tone="type">{ioc.type}</EntityBadge>
        </td>

        <td className="px-4 py-3 align-middle">
          <span className="mono text-[11px] text-muted-foreground">{ioc.category}</span>
        </td>

        <td className="px-4 py-3 align-middle">
          <ConfidenceBadge confidence={ioc.confidence} />
        </td>

        {!isSingleHost && (
          <td className="px-4 py-3 align-middle">
            <OverflowTags
              items={hosts}
              max={2}
              renderChip={(h) => (
                <span className="mono rounded border border-border-faint bg-bg-raised px-1.5 py-0.5 text-[10px] text-muted-foreground">
                  {h}
                </span>
              )}
            />
          </td>
        )}

        <td className="px-4 py-3 align-middle">
          <div className="flex flex-wrap gap-1">
            {(ioc.source_findings ?? []).map((fid) => (
              <button
                key={fid}
                type="button"
                onClick={(e) => {
                  e.stopPropagation()
                  onFindingClick(fid)
                }}
                className="mono rounded bg-primary/10 px-1.5 py-0.5 text-[11px] text-primary transition-colors hover:bg-primary/20 hover:underline focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
              >
                {fid}
              </button>
            ))}
          </div>
        </td>

        <td className="px-4 py-3 align-middle">
          <EntityBadge tone={iocStatusTone(ioc.status)}>{ioc.status}</EntityBadge>
        </td>
      </tr>

      {isExpanded && (
        <tr className="bg-secondary/30">
          <td colSpan={colSpan} className="border-b border-border-faint p-4">
            <div className="space-y-2">
              {(ioc.mitre_techniques ?? []).length > 0 && (
                <div className="flex items-start gap-2">
                  <span className="mono mt-0.5 shrink-0 text-[10px] uppercase tracking-wider text-muted-foreground">
                    MITRE:
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {ioc.mitre_techniques.map((t) => {
                      const isSub = t.includes('.')
                      return (
                        <span
                          key={t}
                          className={cn(
                            'mono rounded bg-primary/10 px-1.5 py-0.5 text-[10px] text-primary',
                            isSub && 'ml-1 text-[9px] opacity-65',
                          )}
                        >
                          {t}
                        </span>
                      )
                    })}
                  </div>
                </div>
              )}

              {(ioc.tags ?? []).length > 0 && (
                <div className="flex items-start gap-2">
                  <span className="mono mt-0.5 shrink-0 text-[10px] uppercase tracking-wider text-muted-foreground">
                    Tags:
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {ioc.tags.map((t) => (
                      <span key={t} className="mono rounded bg-sev-med/10 px-1.5 py-0.5 text-[10px] text-sev-med">
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <div className="mono flex flex-wrap gap-4 text-[10px] text-text-ghost">
                <span>ID: {ioc.id}</span>
                {ioc.examiner && <span>Examiner: {ioc.examiner}</span>}
                {ioc.created_at && <span>Created: {fmtTs(ioc.created_at)}</span>}
              </div>
            </div>
          </td>
        </tr>
      )}
    </Fragment>
  )
}
