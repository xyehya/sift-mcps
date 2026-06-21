import { useState } from 'react'
import { AlertTriangle, Download, FileText, Save } from 'lucide-react'

import { serializeToMarkdown } from './reports-utils'
import { ReportRenderedView } from './ReportRenderedView'

// ─────────────────────────────────────────────────────────────────────────
// ReportPreview — the right-hand preview pane (legacy parity §7-§11): the
// toolbar (draft/saved badge · id · Rendered/Raw toggle · Save draft · Download
// .md), inline integrity/chain warnings, and the rendered or raw-markdown body.
// Loading + "no report selected" states live here too.
//
// SECURITY: the Raw view binds the serialized markdown to a readonly <textarea>
// `value` (escaped) and the Rendered view delegates to ReportRenderedView which
// renders escaped React text nodes — never dangerouslySetInnerHTML.
// ─────────────────────────────────────────────────────────────────────────

function EmptyState() {
  return (
    <div className="mono flex flex-1 flex-col items-center justify-center bg-bg-base p-8 text-center text-muted-foreground">
      <FileText className="mb-3 size-10 text-border-soft" aria-hidden />
      <p className="text-sm font-semibold">No report selected</p>
      <p className="mt-1 max-w-xs text-xs text-muted-foreground">
        Select a saved report on the left or generate a new draft briefing.
      </p>
    </div>
  )
}

function Warning({ tone, label, message }) {
  const cls = tone === 'integrity' ? 'border-destructive/20 bg-destructive/5' : 'border-status-pending/20 bg-amber-dim'
  const text = tone === 'integrity' ? 'text-destructive' : 'text-status-pending'
  return (
    <div className={`flex flex-col gap-1 rounded-lg border p-4 text-left ${cls}`}>
      <span className={`mono flex items-center gap-1.5 text-xs font-bold uppercase tracking-wide ${text}`}>
        <AlertTriangle className="size-3.5" aria-hidden />
        {label}
      </span>
      <p className="mt-0.5 text-xs leading-relaxed text-foreground">{message}</p>
    </div>
  )
}

export function ReportPreview({ report, loading, draftReport, onSave, onDownload }) {
  const [previewMode, setPreviewMode] = useState('rendered')

  if (loading) {
    return (
      <div className="mono flex flex-1 items-center justify-center text-sm text-muted-foreground">
        Loading report content…
      </div>
    )
  }
  if (!report) return <EmptyState />

  return (
    <div className="flex flex-1 flex-col overflow-hidden bg-bg-base">
      <div className="flex h-12 shrink-0 items-center justify-between border-b border-border-faint bg-card px-4">
        <div className="flex items-center gap-3">
          <span
            className={`mono rounded px-2 py-0.5 text-[10px] font-bold uppercase ${
              draftReport
                ? 'border border-status-pending/20 bg-amber-dim text-status-pending'
                : 'border border-status-approved/20 bg-status-approved/10 text-status-approved'
            }`}
          >
            {draftReport ? 'Draft Briefing' : 'Saved Report'}
          </span>
          <span className="mono cursor-help text-xs text-muted-foreground" title={report.id}>
            ID: <span className="text-foreground">{report.id.slice(0, 8)}…</span>
          </span>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex rounded border border-border-soft bg-bg-base p-0.5 text-[10px]">
            <button
              type="button"
              onClick={() => setPreviewMode('rendered')}
              className={`rounded px-2 py-1 transition-colors ${
                previewMode === 'rendered'
                  ? 'bg-bg-raised font-bold text-primary'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              Rendered
            </button>
            <button
              type="button"
              onClick={() => setPreviewMode('raw')}
              className={`rounded px-2 py-1 transition-colors ${
                previewMode === 'raw'
                  ? 'bg-bg-raised font-bold text-primary'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              Raw Markdown
            </button>
          </div>

          {draftReport && (
            <button
              type="button"
              onClick={onSave}
              className="mono flex items-center gap-1 rounded-lg border border-primary bg-primary/10 px-3 py-1.5 text-xs font-bold text-primary transition-colors hover:bg-primary/20"
            >
              <Save className="size-3.5" aria-hidden />
              Save Report
            </button>
          )}

          <button
            type="button"
            onClick={() => onDownload(report.id)}
            className="mono flex items-center gap-1 rounded-lg border border-border-soft bg-bg-raised px-3 py-1.5 text-xs font-bold text-foreground transition-colors hover:bg-bg-overlay"
          >
            <Download className="size-3.5" aria-hidden />
            Download .md
          </button>
        </div>
      </div>

      <div className="flex flex-1 justify-center overflow-y-auto p-6">
        <div className="flex w-full max-w-3xl flex-col gap-6">
          {report.integrity_warning && (
            <Warning tone="integrity" label="Evidence Integrity Violation" message={report.integrity_warning} />
          )}
          {report.evidence_chain_warning && (
            <Warning tone="chain" label="Evidence Chain Notice" message={report.evidence_chain_warning} />
          )}

          {previewMode === 'raw' ? (
            <div className="flex min-h-[400px] flex-1 flex-col">
              <textarea
                readOnly
                aria-label="Raw report markdown"
                value={serializeToMarkdown(report)}
                className="mono flex-1 resize-none rounded-lg border border-border-soft bg-card p-4 text-xs leading-relaxed text-foreground focus:outline-none"
              />
            </div>
          ) : (
            <ReportRenderedView report={report} />
          )}
        </div>
      </div>
    </div>
  )
}
