import { Fragment } from 'react'
import { ChevronRight, Copy } from 'lucide-react'

import { cn } from '@/lib/utils'
import { fmtTs } from '@/components/common/entity-utils'
import { ConfidenceBadge, EntityBadge } from '@/components/common/EntityBadges'
import { iocHosts, iocStatusTone } from './iocs-utils'

// ─────────────────────────────────────────────────────────────────────────
// IocRow — one IOC table row plus its expandable detail (legacy parity). Main
// row: expand chevron, value + copy-to-clipboard, type, category, confidence,
// hosts (hidden when single-host), source-finding cross-links, status. Expanded
// panel: MITRE techniques (sub-techniques dimmed), tags, and an ID/examiner/
// created footer. Mission-Control reskin — token classes only, lucide icons.
// ─────────────────────────────────────────────────────────────────────────

export function IocRow({ ioc, isExpanded, isSingleHost, colSpan, onToggle, onCopy, onFindingClick }) {
  const hosts = iocHosts(ioc)

  return (
    <Fragment>
      <tr className="group text-foreground transition-colors hover:bg-secondary/40">
        <td className="px-3 py-3 align-top">
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

        <td className="px-3 py-3 align-top">
          <div className="flex items-center gap-1.5">
            <span className="mono max-w-[280px] truncate text-[11px] text-foreground" title={ioc.value}>
              {ioc.value}
            </span>
            <button
              type="button"
              onClick={() => onCopy(ioc.value)}
              aria-label="Copy IOC value to clipboard"
              className="rounded p-0.5 text-muted-foreground opacity-0 transition-opacity hover:bg-bg-raised group-hover:opacity-100 focus-visible:opacity-100 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            >
              <Copy className="size-3" aria-hidden />
            </button>
          </div>
        </td>

        <td className="px-3 py-3 align-top">
          <EntityBadge tone="muted">{ioc.type}</EntityBadge>
        </td>

        <td className="px-3 py-3 align-top">
          <span className="mono text-[11px] text-muted-foreground">{ioc.category}</span>
        </td>

        <td className="px-3 py-3 align-top">
          <ConfidenceBadge confidence={ioc.confidence} />
        </td>

        {!isSingleHost && (
          <td className="px-3 py-3 align-top">
            {hosts.length === 0 ? (
              <span className="text-text-ghost">—</span>
            ) : (
              <div className="flex max-w-[160px] flex-wrap gap-1">
                {hosts.map((h) => (
                  <span key={h} className="mono rounded bg-bg-raised px-1 py-0.5 text-[10px] text-muted-foreground">
                    {h}
                  </span>
                ))}
              </div>
            )}
          </td>
        )}

        <td className="px-3 py-3 align-top">
          <div className="flex flex-wrap gap-1">
            {(ioc.source_findings ?? []).map((fid) => (
              <button
                key={fid}
                type="button"
                onClick={(e) => {
                  e.stopPropagation()
                  onFindingClick(fid)
                }}
                className="mono rounded bg-primary/10 px-1 py-0.5 text-[11px] text-primary transition-colors hover:bg-primary/20 hover:underline focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
              >
                {fid}
              </button>
            ))}
          </div>
        </td>

        <td className="px-3 py-3 align-top">
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
