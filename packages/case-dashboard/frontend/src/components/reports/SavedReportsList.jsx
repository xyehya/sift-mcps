import { Download, RefreshCw } from 'lucide-react'

import { profileLabel, formatReportDate } from './reports-utils'

// ─────────────────────────────────────────────────────────────────────────
// SavedReportsList — the left-pane list of saved reports (legacy parity §5/§6):
// loading + empty states, per-row select (loads the report into the preview),
// per-row download, and a refresh control. Active row is highlighted with the
// orange accent. Reskinned to graphite/orange tokens.
// ─────────────────────────────────────────────────────────────────────────

export function SavedReportsList({
  reports,
  reportsLoading,
  activeReportId,
  draftReport,
  onSelect,
  onDownload,
  onRefresh,
}) {
  return (
    <div className="flex flex-1 flex-col overflow-hidden">
      <div className="flex items-center justify-between border-b border-border-faint bg-bg-base p-3">
        <span className="mono text-[11px] uppercase tracking-wider text-muted-foreground">Saved Reports</span>
        <button
          type="button"
          onClick={onRefresh}
          disabled={reportsLoading}
          title="Refresh Reports"
          aria-label="Refresh reports"
          className="text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50"
        >
          <RefreshCw className={`size-3.5 ${reportsLoading ? 'animate-spin' : ''}`} aria-hidden />
        </button>
      </div>

      <div className="flex flex-1 flex-col gap-1.5 overflow-y-auto p-2">
        {reportsLoading && reports.length === 0 ? (
          <div className="mono py-6 text-center text-xs text-muted-foreground">Loading reports…</div>
        ) : reports.length === 0 ? (
          <div className="mono py-8 text-center text-xs text-muted-foreground">No saved reports found</div>
        ) : (
          reports.map((r) => {
            const active = activeReportId === r.id && !draftReport
            return (
              <button
                key={r.id}
                type="button"
                onClick={() => onSelect(r.id)}
                className={`group flex flex-col gap-1 rounded-lg border p-3 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${
                  active
                    ? 'border-primary bg-bg-raised'
                    : 'border-border-faint bg-bg-raised hover:border-border-soft'
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold text-foreground">
                    {profileLabel(r.profile)} — {r.version || 'v1'} · {formatReportDate(r.created_at)}
                  </span>
                  <span
                    role="button"
                    tabIndex={0}
                    onClick={(e) => {
                      e.stopPropagation()
                      onDownload(r.id)
                    }}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.stopPropagation()
                        onDownload(r.id)
                      }
                    }}
                    title="Download Markdown"
                    aria-label={`Download report ${r.id.slice(0, 8)}`}
                    className="text-muted-foreground transition-colors hover:text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  >
                    <Download className="size-4" aria-hidden />
                  </span>
                </div>
                <div className="mono mt-1 flex items-center justify-between text-[10px] text-muted-foreground">
                  <span title={r.id}>ID: {r.id.slice(0, 8)}…</span>
                  <span>{r.examiner}</span>
                </div>
              </button>
            )
          })
        )}
      </div>
    </div>
  )
}
