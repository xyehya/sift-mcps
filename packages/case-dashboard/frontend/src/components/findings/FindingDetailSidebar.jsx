import { cn } from '@/lib/utils'
import { EditableField } from '@/components/findings/EditableField'
import { AuditTrailPanel } from '@/components/findings/AuditTrailPanel'

// ─────────────────────────────────────────────────────────────────────────
// Finding detail — evidence & context column (the old "Zone 2"). Timeline
// window, primary artifacts, supporting commands, MITRE/IOC (editable),
// read-only tags, related findings, the audit trail and crypto integrity.
// Presentational: edit state + persistence are owned by FindingDetail and
// threaded through `edit`. All values render as escaped text.
// ─────────────────────────────────────────────────────────────────────────

function Label({ children }) {
  return <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">{children}</p>
}

function fmtTime(iso) {
  try {
    return new Date(iso).toISOString().substring(11, 19)
  } catch {
    return ''
  }
}

export function FindingDetailSidebar({ finding, eff, stagedItem, contextEvents, edit, onNavigate }) {
  const mods = stagedItem?.modifications ?? {}
  return (
    <div className="flex w-full flex-col gap-5 border-t border-border pt-4 md:w-80 md:shrink-0 md:border-l md:border-t-0 md:pl-5 md:pt-0">
      {contextEvents.length > 0 && (
        <section className="space-y-2">
          <Label>Timeline context (±2h)</Label>
          <div className="max-h-48 space-y-1 overflow-y-auto pr-1">
            {contextEvents.map((ev) => {
              const isThis = ev.finding_refs?.includes(finding.id)
              return (
                <div
                  key={ev.id}
                  className={cn(
                    'mono flex items-start gap-2 rounded px-2 py-1 text-[10px]',
                    isThis ? 'bg-primary/10 text-primary' : 'text-muted-foreground',
                  )}
                >
                  <span className="shrink-0">{fmtTime(ev.timestamp)}</span>
                  <span className="w-12 shrink-0 truncate">[{ev.type}]</span>
                  <span className={cn('flex-1 truncate', isThis ? 'text-primary' : 'text-foreground')}>{ev.description}</span>
                </div>
              )
            })}
          </div>
        </section>
      )}

      {finding.artifacts?.length > 0 && (
        <section className="space-y-2">
          <Label>Evidence artifacts</Label>
          <div className="space-y-2">
            {finding.artifacts.map((art, i) => (
              <div key={i} className="mono space-y-1 rounded-md border border-border bg-card p-2.5 text-xs">
                <div className="truncate font-semibold text-foreground">{art.source}</div>
                {art.extraction && <div className="text-[11px] text-primary">$ {art.extraction}</div>}
                {art.content && (
                  <pre className="max-h-40 overflow-auto whitespace-pre-wrap rounded border border-border bg-background p-2 text-foreground">
                    {art.content}
                  </pre>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      {finding.supporting_commands?.length > 0 && (
        <section className="space-y-2">
          <Label>Supporting commands</Label>
          <div className="space-y-2">
            {finding.supporting_commands.map((cmd, i) => (
              <div key={i} className="mono space-y-1 rounded-md border border-border bg-card p-2.5 text-xs">
                <div className="text-primary">$ {cmd.command}</div>
                {cmd.output_excerpt && (
                  <pre className="max-h-40 overflow-auto whitespace-pre-wrap rounded border border-border bg-background p-2 text-foreground">
                    {cmd.output_excerpt}
                  </pre>
                )}
              </div>
            ))}
          </div>
        </section>
      )}

      <section className="space-y-1.5">
        <Label>MITRE ATT&CK</Label>
        <EditableField
          kind="tags"
          label="MITRE techniques"
          value={eff.mitre_ids}
          modification={mods.mitre_ids}
          editing={edit.editingField === 'mitre_ids'}
          canEdit={edit.canEdit}
          onStartEdit={() => edit.onStartEdit('mitre_ids')}
          onSave={(v) => edit.onSave('mitre_ids', v)}
          onCancel={edit.onCancel}
        />
      </section>

      <section className="space-y-1.5">
        <Label>Indicators of compromise</Label>
        <EditableField
          kind="tags"
          label="IOCs"
          value={eff.iocs}
          modification={mods.iocs}
          editing={edit.editingField === 'iocs'}
          canEdit={edit.canEdit}
          onStartEdit={() => edit.onStartEdit('iocs')}
          onSave={(v) => edit.onSave('iocs', v)}
          onCancel={edit.onCancel}
        />
      </section>

      {finding.tags?.length > 0 && (
        <section className="space-y-1.5">
          <Label>Tags</Label>
          <div className="flex flex-wrap gap-1">
            {finding.tags.map((t) => (
              <span key={t} className="mono rounded border border-border bg-card px-1.5 py-0.5 text-[10px] text-muted-foreground">
                {t}
              </span>
            ))}
          </div>
        </section>
      )}

      {finding.related_findings?.length > 0 && (
        <section className="space-y-1.5">
          <Label>Related findings</Label>
          <div className="flex flex-wrap gap-1">
            {finding.related_findings.map((rid) => (
              <button
                key={rid}
                type="button"
                onClick={() => onNavigate(rid)}
                className="mono rounded border border-primary/50 px-1.5 py-0.5 text-[10px] text-primary transition-colors hover:bg-primary/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                [{rid}]
              </button>
            ))}
          </div>
        </section>
      )}

      {finding.audit_ids?.length > 0 && <AuditTrailPanel finding={finding} />}

      <section className="space-y-1 border-t border-border pt-3">
        <Label>Cryptographic integrity</Label>
        <dl className="mono grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-[10px] text-muted-foreground">
          <dt>Verification</dt>
          <dd className={finding.verification === 'confirmed' ? 'text-status-approved' : 'text-status-pending'}>
            {finding.verification || 'draft'}
          </dd>
          <dt>Provenance</dt>
          <dd className="text-foreground">{finding.provenance || 'NONE'}</dd>
          {finding.content_hash && (
            <>
              <dt>Hash</dt>
              <dd className="truncate text-foreground">{finding.content_hash.slice(0, 16)}…</dd>
            </>
          )}
        </dl>
      </section>
    </div>
  )
}
