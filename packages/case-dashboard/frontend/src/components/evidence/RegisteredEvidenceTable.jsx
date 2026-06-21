import { Archive, CheckCircle2, AlertTriangle } from 'lucide-react'

import { SkeletonBlock } from '@/components/common/Skeleton'
import { Button } from '@/components/ui/button'
import { formatTime, shortHash } from './evidence-utils'

// ─────────────────────────────────────────────────────────────────────────
// RegisteredEvidenceTable — the sealed/registered evidence registry (legacy IA
// parity §6). Sortable columns (Path · SHA-256 · Description · Registered At ·
// Registered By · Referenced By · Action). Referenced-by chips deep-link to
// Findings. Action cell: per-item Unseal (gated on chainStatus.ok membership —
// the frozen EvidenceUnseal.test.jsx keys off ok[], not the aggregate seal
// status) carrying data-testid="unseal-btn-{path}", plus a Verify control with
// checking / verified / failed / error states.
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

export function RegisteredEvidenceTable({
  evidence,
  evidenceLoading,
  evidenceError,
  chainStatus,
  verifyStatus,
  sortCol,
  sortAsc,
  onSort,
  onUnseal,
  onVerify,
  onNavigateFinding,
  onRescan,
}) {
  const sealedPaths = chainStatus?.ok ?? []

  return (
    <div className="space-y-3">
      <h3 className="mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
        Registered Evidence ({evidence.length} file{evidence.length === 1 ? '' : 's'})
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
            Use the Rescan button or add files to the evidence directory.
          </p>
          <Button type="button" size="sm" onClick={onRescan} className="text-xs font-semibold">
            Rescan Directory
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
                        data-testid={`unseal-btn-${ev.path}`}
                        onClick={() => onUnseal(ev.path)}
                        className="mono mr-2 rounded border border-border-hard px-2 py-1 text-[10px] font-semibold text-muted-foreground transition-colors hover:border-status-pending hover:text-status-pending focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                        title="Unseal: clear the immutable flag so this evidence can be replaced/re-imaged; blocks agent tools until re-sealed"
                      >
                        Unseal
                      </button>
                    )}
                    <VerifyCell status={verifyStatus[ev.path]} onVerify={onVerify} path={ev.path} />
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
