import { formatDate } from './reports-utils'
import { ReportSection } from './ReportSection'

// ─────────────────────────────────────────────────────────────────────────
// ReportRenderedView — the high-fidelity formatted report (legacy parity §10):
// metadata header block, each ReportSection, and the custody/provenance
// appendix (F-MVP-4). All values render as escaped React text nodes.
// ─────────────────────────────────────────────────────────────────────────

const TH = 'mono px-2 py-1.5 text-left text-[10px] font-bold text-muted-foreground'
const TABLE = 'min-w-full overflow-hidden rounded-lg border border-border-soft bg-card text-[11px] font-mono'

function MetaCell({ label, value }) {
  return (
    <div>
      <span className="text-muted-foreground">{label}</span>{' '}
      <span className="font-bold text-foreground">{value}</span>
    </div>
  )
}

function CustodyAppendix({ appendix }) {
  const seal = appendix.evidence_seal || {}
  const fp = appendix.finding_provenance || []
  const sealRows = [
    ['Seal Status', seal.seal_status || 'N/A'],
    ['Manifest Version', seal.manifest_version ?? 0],
    ['Manifest Hash', seal.manifest_hash || 'N/A'],
    ['Chain Head Hash', seal.chain_head_hash || 'N/A'],
    ['Ledger Tip Hash', seal.ledger_tip_hash || 'N/A'],
    ['Active Evidence Count', seal.active_count ?? 0],
  ]
  return (
    <div className="mt-4 flex flex-col gap-3">
      <h2 className="mt-4 border-b border-border-faint pb-1.5 text-lg font-bold text-foreground">
        Appendix: Custody &amp; Provenance
      </h2>
      {appendix.verification_note && (
        <p className="text-xs italic text-muted-foreground">{appendix.verification_note}</p>
      )}
      {appendix.authorized_by_reauth_event && (
        <div className="mono text-[10px] text-muted-foreground">
          Authorized by re-auth event:{' '}
          <span className="break-all text-primary">{appendix.authorized_by_reauth_event}</span>
        </div>
      )}
      <div className="overflow-x-auto">
        <h3 className="mono mb-1 text-xs font-bold uppercase tracking-wider text-muted-foreground">
          Evidence Seal &amp; Hash-Chain Proof
        </h3>
        <table className={TABLE}>
          <tbody>
            {sealRows.map(([k, v]) => (
              <tr key={k} className="border-b border-border-faint last:border-0">
                <td className="w-1/3 px-3 py-1.5 font-bold text-muted-foreground">{k}</td>
                <td className="break-all px-3 py-1.5 text-foreground">{String(v)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="overflow-x-auto">
        <h3 className="mono mb-1 text-xs font-bold uppercase tracking-wider text-muted-foreground">
          Finding Provenance
        </h3>
        {fp.length === 0 ? (
          <span className="text-xs italic text-muted-foreground">No approved findings.</span>
        ) : (
          <table className={TABLE}>
            <thead>
              <tr className="border-b border-border-soft bg-bg-raised">
                <th className={TH}>Finding ID</th>
                <th className={`${TH} w-1/3`}>Approval Hash</th>
                <th className={TH}>Approved By</th>
                <th className={TH}>Provenance / Audit Refs</th>
              </tr>
            </thead>
            <tbody>
              {fp.map((entry, i) => (
                <tr key={i} className="border-b border-border-faint last:border-0 hover:bg-bg-raised/40">
                  <td className="px-2 py-1.5 font-bold text-primary">{entry.id}</td>
                  <td
                    className="max-w-[160px] truncate break-all px-2 py-1.5 text-muted-foreground"
                    title={entry.content_hash}
                  >
                    {entry.content_hash || 'N/A'}
                  </td>
                  <td className="px-2 py-1.5 text-foreground">{entry.approved_by || 'N/A'}</td>
                  <td className="break-all px-2 py-1.5 text-muted-foreground">
                    {(entry.provenance_refs || []).join(', ') || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

export function ReportRenderedView({ report }) {
  const meta = report.report_data?.metadata
  return (
    <div className="flex flex-col gap-6 pb-12 text-left leading-relaxed text-foreground">
      <div className="border-b border-border-faint pb-4">
        <h1 className="font-display text-2xl font-bold tracking-tight text-foreground">
          Forensic Incident Report: {meta?.name || 'Unknown Case'}
        </h1>
        <div className="mono mt-4 grid grid-cols-2 gap-4 rounded-lg border border-border-faint bg-card p-3 text-xs">
          <MetaCell label="Case ID:" value={meta?.case_id || 'N/A'} />
          <MetaCell label="Report Profile:" value={(report.profile || 'full').toUpperCase()} />
          <MetaCell label="Generated At:" value={formatDate(report.generated_at)} />
          <MetaCell label="Examiner:" value={report.examiner || 'Unknown'} />
        </div>
      </div>

      {(report.sections || []).map((sec, idx) => (
        <ReportSection
          key={idx}
          section={sec}
          reportData={report.report_data}
          zeltser={report.zeltser_guidance}
          humanReview={report.human_review_required}
        />
      ))}

      {report.custody_appendix && <CustodyAppendix appendix={report.custody_appendix} />}
    </div>
  )
}
