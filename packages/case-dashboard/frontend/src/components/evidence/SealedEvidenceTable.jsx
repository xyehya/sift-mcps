import { Archive, CheckCircle2, AlertTriangle } from 'lucide-react'
import { useState } from 'react'

import { getEvidenceHistory } from '@/api/endpoints'
import { SkeletonBlock } from '@/components/common/Skeleton'
import { Button } from '@/components/ui/button'
import { formatTime, shortHash } from './evidence-utils'

// ─────────────────────────────────────────────────────────────────────────
// SealedEvidenceTable — the sealed custody registry (legacy IA
// parity §6). Sortable columns (Path · SHA-256 · Description · Registered At ·
// Registered By · Referenced By · Action). Referenced-by chips deep-link to
// Findings. Action cell exposes durable per-item Replace/Reacquire, verification,
// and path-free append-only Evidence Version history.
// ─────────────────────────────────────────────────────────────────────────

const COLUMNS = [
  { key: 'path', label: 'Path' },
  { key: 'sha256', label: 'SHA-256' },
  { key: 'description', label: 'Description' },
  { key: 'registered_at', label: 'Registered At' },
  { key: 'registered_by', label: 'Registered By' },
]

function VerifyCell({ status, onVerify, path }) {
  if (status === 'checking') {
    return <span className="mono animate-pulse text-xs text-muted-foreground">Checking…</span>
  }
  if (status === 'verified') {
    return (
      <span className="mono inline-flex items-center gap-1 text-xs font-semibold text-status-approved">
        Verified <CheckCircle2 className="size-3" aria-hidden />
      </span>
    )
  }
  if (status === 'failed') {
    return (
      <span className="mono inline-flex items-center gap-1 text-xs font-semibold text-destructive">
        FAILED <AlertTriangle className="size-3" aria-hidden />
      </span>
    )
  }
  if (status === 'error') {
    return <span className="mono text-xs text-destructive">Error</span>
  }
  if (status) {
    return <span className="mono text-xs text-muted-foreground">{status}</span>
  }
  return (
    <Button
      type="button"
      variant="outline"
      size="xs"
      onClick={() => onVerify(path)}
      className="mono text-[10px] text-muted-foreground hover:text-foreground hover:border-border-hard"
    >
      Verify
    </Button>
  )
}

function EvidenceHistory({ objectId }) {
  const [history, setHistory] = useState(null)
  const [error, setError] = useState('')
  async function load() {
    if (history) {
      setHistory(null)
      return
    }
    try {
      setError('')
      setHistory(await getEvidenceHistory(objectId))
    } catch (err) {
      setError(err.message || 'History unavailable')
    }
  }
  return (
    <div className="mt-1">
      <button type="button" onClick={load} className="mono text-[10px] text-muted-foreground underline-offset-2 hover:underline">
        {history ? 'Hide history' : 'Version history'}
      </button>
      {error && <div className="text-[10px] text-destructive">{error}</div>}
      {history && (
        <div data-testid={`evidence-history-${objectId}`} className="mt-1 min-w-72 rounded border border-border-soft bg-bg-raised p-2 text-left">
          <div className="mono text-[10px] font-semibold">Evidence Versions</div>
          {(history.versions || []).map((version) => (
            <div key={version.evidence_version_id} className="mono mt-1 text-[10px] text-muted-foreground">
              v{version.manifest_version} · {shortHash(version.sha256, 12)} · {version.bytes} bytes
            </div>
          ))}
          <div className="mono mt-2 text-[10px] font-semibold">Custody Events</div>
          {(history.events || []).map((event) => (
            <div key={event.event_id} className="mono mt-1 text-[10px] text-muted-foreground">
              #{event.seq} · {event.event_type}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export function SealedEvidenceTable({
  evidence,
  evidenceLoading,
  evidenceError,
  chainStatus,
  verifyStatus,
  sortCol,
  sortAsc,
  onSort,
  onReplace,
  onVerify,
  onNavigateFinding,
  onRefresh,
}) {
  const sealedPaths = chainStatus?.ok ?? []

  return (
    <div className="space-y-3">
      <h3 className="mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
        Sealed Evidence ({evidence.length} file{evidence.length === 1 ? '' : 's'})
      </h3>

      {evidenceError && (
        <div className="rounded-lg border border-destructive/20 bg-destructive/5 p-2.5 text-xs text-destructive">
          {evidenceError}
        </div>
      )}

      {evidenceLoading ? (
        <SkeletonBlock rows={5} gap={8} />
      ) : evidence.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-lg border border-border-soft bg-card py-12 text-center">
          <Archive className="mb-3 size-12 text-muted-foreground opacity-30" aria-hidden />
          <p className="text-sm font-semibold text-foreground">No evidence files registered.</p>
          <p className="mb-4 mt-1 max-w-xs text-xs text-muted-foreground">
            Refresh custody status after an operator-authorized evidence workflow.
          </p>
          <Button type="button" size="sm" onClick={onRefresh} className="text-xs font-semibold">
            Refresh custody status
          </Button>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border-soft bg-card">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-border-soft bg-secondary/40 text-muted-foreground">
                {COLUMNS.map(({ key, label }) => (
                  <th
                    key={key}
                    scope="col"
                    className="mono cursor-pointer select-none px-3 py-2 font-semibold hover:text-foreground"
                    onClick={() => onSort(key)}
                    aria-sort={sortCol === key ? (sortAsc ? 'ascending' : 'descending') : 'none'}
                  >
                    {label} {sortCol === key ? (sortAsc ? '▲' : '▼') : ''}
                  </th>
                ))}
                <th scope="col" className="mono px-3 py-2 font-semibold">Referenced By</th>
                <th scope="col" className="mono px-3 py-2 text-right font-semibold">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-faint">
              {evidence.map((ev) => (
                <tr key={ev.path} className="text-foreground transition-colors hover:bg-secondary/40">
                  <td className="mono break-all px-3 py-2">{ev.path}</td>
                  <td className="mono px-3 py-2" title={ev.sha256}>
                    {ev.sha256 ? shortHash(ev.sha256, 12) : '—'}
                  </td>
                  <td className="px-3 py-2">{ev.description || '—'}</td>
                  <td className="mono whitespace-nowrap px-3 py-2">{formatTime(ev.registered_at)}</td>
                  <td className="mono px-3 py-2">{ev.registered_by || '—'}</td>
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap gap-1">
                      {ev.referenced_by?.length > 0 ? (
                        ev.referenced_by.map((rid) => (
                          <button
                            key={rid}
                            type="button"
                            onClick={() => onNavigateFinding(rid)}
                            className="mono rounded bg-primary/10 px-1.5 py-0.5 text-[10px] text-primary transition-colors hover:bg-primary/20 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                          >
                            {rid}
                          </button>
                        ))
                      ) : (
                        <span className="text-text-ghost">—</span>
                      )}
                    </div>
                  </td>
                  <td className="whitespace-nowrap px-3 py-2 text-right">
                    {sealedPaths.includes(ev.path) && (
                      <button
                        type="button"
                        data-testid={`replace-btn-${ev.path}`}
                        onClick={() => onReplace(ev.path)}
                        className="mono mr-2 rounded border border-border-hard px-2 py-1 text-[10px] font-semibold text-muted-foreground transition-colors hover:border-status-pending hover:text-status-pending focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                        title="Begin a durable Replace/Reacquire operation; the custody gate blocks before protection changes"
                      >
                        Replace/Reacquire
                      </button>
                    )}
                    <VerifyCell status={verifyStatus[ev.path]} onVerify={onVerify} path={ev.path} />
                    {ev.evidence_id && <EvidenceHistory objectId={ev.evidence_id} />}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
