import { Badge } from '@/components/ui/badge'

// ─────────────────────────────────────────────────────────────────────────
// Case context — a read-only summary of the active case brief (incident type,
// severity, TLP, scope, key dates). Ported display logic from the old
// CaseBriefCard; inline editing is deferred to a Settings/metadata surface in
// a later phase (tracked as a follow-up). All values are rendered as escaped
// React text — no HTML injection.
// ─────────────────────────────────────────────────────────────────────────

const DATE_FIELDS = [
  ['occurred_at', 'Occurred'],
  ['detected_at', 'Detected'],
  ['reported_at', 'Reported'],
  ['contained_at', 'Contained'],
]

function asList(val) {
  return Array.isArray(val) ? val : val ? [val] : []
}

function fmtDate(iso) {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleDateString()
}

function Field({ label, value }) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="truncate text-foreground">{value}</dd>
    </>
  )
}

export function CaseContextCard({ activeCase }) {
  if (!activeCase) return null
  const meta = activeCase

  const systems = asList(meta.affected_systems)
  const accounts = asList(meta.affected_accounts)
  const dates = DATE_FIELDS.filter(([k]) => meta[k])

  const hasBrief =
    meta.description ||
    meta.incident_type ||
    meta.severity ||
    meta.tlp ||
    meta.impact_summary ||
    systems.length ||
    accounts.length ||
    dates.length

  if (!hasBrief) {
    return (
      <p className="text-sm text-muted-foreground">
        No case brief recorded yet — capture incident type, severity, scope and key dates from the case metadata.
      </p>
    )
  }

  return (
    <div className="flex flex-col gap-3">
      {meta.description && <p className="text-sm leading-relaxed text-foreground">{meta.description}</p>}

      <div className="flex flex-wrap gap-1.5">
        {meta.incident_type && <Badge variant="secondary">{meta.incident_type}</Badge>}
        {meta.severity && <Badge variant="outline" className="text-status-pending">severity: {meta.severity}</Badge>}
        {meta.tlp && <Badge variant="outline" className="text-status-staged">TLP:{meta.tlp}</Badge>}
        {asList(meta.tags).map((t) => (
          <Badge key={t} variant="outline" className="mono">
            {t}
          </Badge>
        ))}
      </div>

      {(dates.length > 0 || systems.length > 0 || accounts.length > 0) && (
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
          {dates.map(([k, lbl]) => (
            <Field key={k} label={lbl} value={fmtDate(meta[k])} />
          ))}
          {systems.length > 0 && <Field label="Systems" value={systems.join(', ')} />}
          {accounts.length > 0 && <Field label="Accounts" value={accounts.join(', ')} />}
        </dl>
      )}

      {meta.impact_summary && (
        <div className="flex flex-col gap-1">
          <span className="text-[11px] uppercase tracking-wider text-muted-foreground">Impact</span>
          <p className="text-sm leading-relaxed text-foreground">{meta.impact_summary}</p>
        </div>
      )}
    </div>
  )
}
