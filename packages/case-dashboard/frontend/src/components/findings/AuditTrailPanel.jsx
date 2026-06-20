import { useEffect, useMemo, useState } from 'react'
import { ChevronRight } from 'lucide-react'

import { cn } from '@/lib/utils'
import { getAudit } from '@/api/endpoints'

// ─────────────────────────────────────────────────────────────────────────
// Audit trail — the tool-call provenance behind a finding's audit_ids. Loads
// lazily (only mounts when the Evidence & Context section is expanded), groups
// entries by audit id, and renders command/params + a result summary. Ported
// from the old monolith, tokenised. All values are escaped React text; result
// previews are rendered in <pre> as text (no HTML sink).
// ─────────────────────────────────────────────────────────────────────────

function ResultSummary({ summary }) {
  if (!summary) return <span className="text-muted-foreground">No result summary.</span>
  if (typeof summary === 'string') return <span>{summary}</span>
  return (
    <div className="mono mt-1 space-y-1 text-[11px]">
      {summary.exit_code !== undefined && (
        <div>
          <span className="text-muted-foreground">Exit:</span>{' '}
          <span className={summary.exit_code === 0 ? 'text-status-approved' : 'text-destructive'}>{summary.exit_code}</span>
        </div>
      )}
      {summary.output_file && (
        <div>
          <span className="text-muted-foreground">File:</span> <span className="text-foreground">{summary.output_file}</span>
        </div>
      )}
      {summary.output_sha256 && (
        <div className="truncate">
          <span className="text-muted-foreground">SHA-256:</span> <span className="text-foreground">{summary.output_sha256.slice(0, 16)}…</span>
        </div>
      )}
      {summary.stdout_head && (
        <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap rounded border border-border bg-background p-2 text-foreground">
          {summary.stdout_head}
        </pre>
      )}
    </div>
  )
}

function AuditEntry({ eid, entry, open, onToggle }) {
  const backend = entry._backend || 'unknown'
  const isShell = backend.includes('exec') || (entry.mcp || '').includes('shell') || (entry.source || '').includes('shell')
  return (
    <div className="overflow-hidden rounded-md border border-border">
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        className="mono flex w-full items-center gap-2 bg-secondary px-3 py-2 text-left text-xs text-foreground transition-colors hover:bg-muted"
      >
        <ChevronRight className={cn('size-3 shrink-0 text-muted-foreground transition-transform', open && 'rotate-90')} aria-hidden />
        <span className="font-semibold">{eid}</span>
        <span className="text-muted-foreground">({backend})</span>
      </button>
      {open && (
        <div className="mono space-y-2 border-t border-border p-3 text-[11px] text-foreground">
          {isShell && entry.params?.command && (
            <div>
              <span className="mb-1 block font-semibold text-muted-foreground">Command</span>
              <pre className="overflow-x-auto whitespace-pre-wrap rounded border border-border bg-background p-2">{entry.params.command}</pre>
            </div>
          )}
          {!isShell && entry.tool && (
            <div>
              <span className="font-semibold text-muted-foreground">Tool:</span> <span>{entry.tool}</span>
            </div>
          )}
          {!isShell && entry.params && (
            <div>
              <span className="mb-1 block font-semibold text-muted-foreground">Params</span>
              <pre className="overflow-x-auto whitespace-pre-wrap rounded border border-border bg-background p-2">
                {JSON.stringify(entry.params, null, 2)}
              </pre>
            </div>
          )}
          {entry.result_summary && (
            <div>
              <span className="mb-1 block font-semibold text-muted-foreground">Result</span>
              <ResultSummary summary={entry.result_summary} />
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export function AuditTrailPanel({ finding }) {
  const eids = useMemo(() => finding.audit_ids ?? [], [finding.audit_ids])
  const [data, setData] = useState([])
  // Init loading from the (mount-time) presence of audit ids, so the effect
  // body holds no synchronous setState — only the async fetch callbacks do.
  const [loading, setLoading] = useState(() => eids.length > 0)
  const [open, setOpen] = useState(() => new Set(eids.slice(0, 1)))

  useEffect(() => {
    if (!finding.id || eids.length === 0) return
    let active = true
    getAudit(finding.id)
      .then((d) => {
        if (active) setData(d || [])
      })
      .catch(() => {})
      .finally(() => {
        if (active) setLoading(false)
      })
    return () => {
      active = false
    }
  }, [finding.id, eids.length])

  if (eids.length === 0) return null

  const byEid = {}
  for (const e of data) (byEid[e.audit_id || ''] ||= []).push(e)

  return (
    <div className="space-y-2">
      <span className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Full audit trail</span>
      {loading ? (
        <p className="mono text-xs text-muted-foreground">Loading audit trail…</p>
      ) : (
        <div className="max-h-96 space-y-2 overflow-y-auto pr-1">
          {eids.map((eid) => (
            <AuditEntry
              key={eid}
              eid={eid}
              entry={(byEid[eid] || [])[0] || {}}
              open={open.has(eid)}
              onToggle={() =>
                setOpen((prev) => {
                  const next = new Set(prev)
                  if (next.has(eid)) next.delete(eid)
                  else next.add(eid)
                  return next
                })
              }
            />
          ))}
        </div>
      )}
    </div>
  )
}
