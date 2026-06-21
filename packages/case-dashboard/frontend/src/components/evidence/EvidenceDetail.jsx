import { Archive } from 'lucide-react'

import { cn } from '@/lib/utils'
import { Badge } from '@/components/ui/badge'
import { ScrollArea } from '@/components/ui/scroll-area'
import { Separator } from '@/components/ui/separator'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { custodyClass, typeMeta, formatAcquired, formatSize } from './evidence-utils'

// ─────────────────────────────────────────────────────────────────────────
// EvidenceDetail — right-pane artifact inspector. Shows full metadata:
// full sha256 · acquisition method · custody events · write-protect state ·
// manifest entry · referencing findings. Rendered when an item is selected in
// EvidenceList; the empty-state prompts the user to select an artifact.
// ─────────────────────────────────────────────────────────────────────────

/** Labelled metadata row. */
function MetaRow({ label, value, mono = false, className }) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
        {label}
      </dt>
      <dd className={cn('text-xs break-all', mono && 'mono', className)}>{value ?? '—'}</dd>
    </div>
  )
}

/** Custody event timeline rendered vertically. */
function CustodyTimeline({ events }) {
  if (!events?.length) {
    return <p className="text-xs text-muted-foreground">No custody events recorded.</p>
  }
  return (
    <ol className="space-y-3">
      {events.map((ev, i) => (
        <li key={i} className="flex gap-3">
          <div className="flex flex-col items-center">
            <span className="mt-0.5 size-2 shrink-0 rounded-full bg-primary" aria-hidden />
            {i < events.length - 1 && (
              <span className="mt-1 w-px flex-1 bg-border" aria-hidden />
            )}
          </div>
          <div className="min-w-0 pb-3">
            <p className="mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              {ev.action} · {formatAcquired(ev.at)}
            </p>
            <p className="mt-0.5 text-xs" style={{ color: 'var(--text-primary)' }}>
              {ev.note}
            </p>
            <p className="mono text-[10px] text-muted-foreground">by {ev.by}</p>
          </div>
        </li>
      ))}
    </ol>
  )
}

/** Full sha256 chip — hover tooltip shows the full hash; chip shows first 32 chars. */
function HashChip({ sha256, custodyStatus }) {
  if (!sha256) {
    return <span className="mono text-xs text-muted-foreground">Not yet recorded</span>
  }
  const isSealed = (custodyStatus ?? '').toLowerCase() === 'sealed'
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          className={cn(
            'mono inline-block rounded-md border px-2 py-1 text-[11px] font-semibold cursor-default break-all',
            isSealed
              ? 'border-status-approved/40 bg-status-approved/10 text-status-approved'
              : 'border-border bg-secondary text-muted-foreground',
          )}
          aria-label={`SHA-256: ${sha256}`}
        >
          {sha256.slice(0, 32)}…
        </span>
      </TooltipTrigger>
      <TooltipContent className="mono max-w-xs break-all text-[10px]">
        SHA-256: {sha256}
      </TooltipContent>
    </Tooltip>
  )
}

/** Empty state: prompt to select an item. */
function EmptyDetail() {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-3 text-center text-muted-foreground">
      <Archive className="size-10 opacity-30" aria-hidden />
      <p className="text-sm font-semibold">Select an artifact to inspect</p>
      <p className="max-w-xs text-xs opacity-70">
        Chain-of-custody detail, acquisition method, sha256, and custody events appear here.
      </p>
    </div>
  )
}

export function EvidenceDetail({ item }) {
  if (!item) return <EmptyDetail />

  const custody = custodyClass(item.custody_status)
  const { label: typeLabel } = typeMeta(item.type)

  return (
    <ScrollArea className="h-full">
      <div className="space-y-5 p-5">
        {/* Header */}
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <span className="mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              {item.id}
            </span>
            <Badge variant="secondary" className="mono text-[10px] font-semibold uppercase">
              {typeLabel}
            </Badge>
            <Badge
              variant="outline"
              className={cn('mono text-[10px]', custody.text, custody.ring)}
            >
              <span className={cn('mr-1 inline-block size-1.5 rounded-full', custody.dot)} aria-hidden />
              {custody.label}
            </Badge>
            {item.write_protected ? (
              <Badge variant="outline" className="mono text-[10px] text-status-approved border-status-approved/40">
                Write-protect on
              </Badge>
            ) : (
              <Badge variant="outline" className="mono text-[10px] text-status-pending border-status-pending/40">
                Write-protect off
              </Badge>
            )}
          </div>
          <h2
            className="mono text-sm font-bold leading-snug break-all"
            style={{ color: 'var(--text-bright)' }}
          >
            {item.name}
          </h2>
          <p className="text-xs text-muted-foreground">{item.description}</p>
        </div>

        <Separator />

        {/* Artifact metadata */}
        <section aria-label="Artifact metadata">
          <h3 className="mb-3 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            Artifact metadata
          </h3>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-3">
            <MetaRow label="Host" value={item.host} mono />
            <MetaRow label="Type" value={typeLabel} />
            <MetaRow label="Size" value={item.size_label ?? formatSize(item.size_bytes)} mono />
            <MetaRow label="Acquired at" value={formatAcquired(item.acquired_at)} mono />
            <MetaRow label="Acquired by" value={item.acquired_by} mono />
            <MetaRow
              label="Manifest entry"
              value={item.manifest_entry ?? '—'}
              mono
              className={item.manifest_entry ? 'text-status-approved' : undefined}
            />
          </dl>
        </section>

        {/* Acquisition method */}
        <section aria-label="Acquisition method">
          <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            Acquisition method
          </h3>
          <p className="mono rounded-md border border-border bg-secondary px-3 py-2 text-xs">
            {item.acquisition_method ?? 'Not specified'}
          </p>
        </section>

        {/* SHA-256 */}
        <section aria-label="SHA-256 hash">
          <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            SHA-256
          </h3>
          <HashChip sha256={item.sha256} custodyStatus={item.custody_status} />
          {item.hmac_ok === false && (
            <p
              role="alert"
              className="mono mt-2 text-[11px]"
              style={{ color: 'var(--amber)' }}
            >
              HMAC verification pending — re-verify the chain on the Custody tab.
            </p>
          )}
        </section>

        {/* Referencing findings */}
        {item.finding_refs?.length > 0 && (
          <section aria-label="Referencing findings">
            <h3 className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              Referencing findings
            </h3>
            <div className="flex flex-wrap gap-1.5">
              {item.finding_refs.map((ref) => (
                <Badge
                  key={ref}
                  variant="outline"
                  className="mono cursor-default text-[10px] border-border"
                >
                  {ref}
                </Badge>
              ))}
            </div>
          </section>
        )}

        <Separator />

        {/* Custody events */}
        <section aria-label="Custody events">
          <h3 className="mb-3 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            Custody events
          </h3>
          <CustodyTimeline events={item.custody_events} />
        </section>
      </div>
    </ScrollArea>
  )
}
