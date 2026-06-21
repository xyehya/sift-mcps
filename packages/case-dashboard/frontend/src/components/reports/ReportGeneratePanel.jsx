import { Loader2, Plus } from 'lucide-react'

import { PROFILES } from './reports-utils'

// ─────────────────────────────────────────────────────────────────────────
// ReportGeneratePanel — the generate-control form (legacy parity §1/§2): the
// approved-only eligibility banner (DB authority), profile selector with a
// hover description, optional date + finding-id filters, and the challenge-gated
// Generate button. Submitting opens the password modal in the parent (never
// generates directly). Reskinned to orange/graphite tokens, lucide icons.
// ─────────────────────────────────────────────────────────────────────────

const FIELD_CLASS =
  'mono w-full rounded-lg border border-border-soft bg-bg-raised px-2 py-1.5 text-[11px] text-foreground focus:outline-none focus:ring-2 focus:ring-ring'

export function ReportGeneratePanel({
  form,
  onField,
  generating,
  eligibility,
  reportIneligible,
  onGenerate,
}) {
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault()
        onGenerate()
      }}
      className="flex flex-col gap-3 border-b border-border-faint p-4"
    >
      <h2 className="mono text-[10px] font-bold uppercase tracking-widest text-muted-foreground">
        Generate Report
      </h2>

      {eligibility != null && (
        <div
          className={`rounded-lg border px-2 py-1.5 text-[10px] ${
            reportIneligible ? 'border-status-pending text-status-pending' : 'border-border-soft text-muted-foreground'
          }`}
          data-testid="report-eligibility"
        >
          {reportIneligible
            ? `Not eligible: ${eligibility.reason || 'no approved findings'}. Approve at least one finding before generating a report.`
            : `Eligible — ${eligibility.approved_findings ?? 0} of ${eligibility.total_findings ?? 0} findings approved. Reports include approved data only.`}
        </div>
      )}

      <div className="group relative flex flex-col gap-1">
        <label htmlFor="report-profile" className="text-[11px] font-medium text-muted-foreground">
          Report Profile
        </label>
        <select
          id="report-profile"
          value={form.profile}
          onChange={(e) => onField('profile', e.target.value)}
          className="rounded-lg border border-border-soft bg-bg-raised px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
        >
          {Object.keys(PROFILES).map((key) => (
            <option key={key} value={key}>
              {PROFILES[key].label}
            </option>
          ))}
        </select>
        <div className="pointer-events-none absolute left-0 top-[52px] z-20 w-full rounded-lg border border-border-soft bg-bg-overlay p-2 text-[10px] leading-relaxed text-muted-foreground opacity-0 transition-opacity duration-150 group-hover:opacity-100">
          {PROFILES[form.profile].description}
        </div>
      </div>

      <div className="mt-1 flex flex-col gap-2">
        <div className="mono text-[10px] uppercase tracking-widest text-muted-foreground">
          Filters (Optional)
        </div>
        <div className="flex gap-2">
          <div className="flex flex-1 flex-col gap-0.5">
            <label htmlFor="report-start" className="text-[10px] text-muted-foreground">
              Start Date
            </label>
            <input
              id="report-start"
              type="text"
              placeholder="YYYY-MM-DD"
              value={form.startDate}
              onChange={(e) => onField('startDate', e.target.value)}
              className={FIELD_CLASS}
            />
          </div>
          <div className="flex flex-1 flex-col gap-0.5">
            <label htmlFor="report-end" className="text-[10px] text-muted-foreground">
              End Date
            </label>
            <input
              id="report-end"
              type="text"
              placeholder="YYYY-MM-DD"
              value={form.endDate}
              onChange={(e) => onField('endDate', e.target.value)}
              className={FIELD_CLASS}
            />
          </div>
        </div>
        <div className="flex flex-col gap-0.5">
          <label htmlFor="report-finding-ids" className="text-[10px] text-muted-foreground">
            Finding IDs (comma sep)
          </label>
          <input
            id="report-finding-ids"
            type="text"
            placeholder="F-001, F-002"
            value={form.findingIds}
            onChange={(e) => onField('findingIds', e.target.value)}
            className={FIELD_CLASS}
          />
        </div>
      </div>

      <button
        type="submit"
        disabled={generating || reportIneligible}
        title={reportIneligible ? 'Report generation requires at least one approved finding' : undefined}
        className="mono mt-2 flex w-full items-center justify-center gap-1.5 rounded-lg border border-primary bg-primary/10 py-2 text-xs font-semibold text-primary transition-colors hover:bg-primary/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
      >
        {generating ? (
          <>
            <Loader2 className="size-3.5 animate-spin" aria-hidden />
            Generating…
          </>
        ) : (
          <>
            <Plus className="size-3.5" aria-hidden />
            Generate Draft
          </>
        )}
      </button>
    </form>
  )
}
