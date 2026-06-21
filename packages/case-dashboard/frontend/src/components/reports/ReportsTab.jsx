import { useStoreSlice } from '@/store/useStore'
import { useReports } from './useReports'
import { useChallenge } from './useChallenge'
import { ReportGeneratePanel } from './ReportGeneratePanel'
import { SavedReportsList } from './SavedReportsList'
import { ReportPreview } from './ReportPreview'
import { ReportChallengeModal } from './ReportChallengeModal'

// ─────────────────────────────────────────────────────────────────────────
// ReportsTab — report generation + render console (Mission-Control reskin of
// the legacy 1121-line view, full functional parity). Two-pane master-detail:
// LEFT = generate form + eligibility + saved-reports list; RIGHT = preview pane
// (rendered/raw markdown, save draft, download .md). Each pane scrolls
// independently (§8). Generation is challenge-gated — the examiner password is
// re-verified server-side against Supabase before inclusion (F-MVP-4 /
// B-MVP-017).
//
// Decomposed into ≤400-line files: useReports (list + actions) · useChallenge
// (re-auth state) · ReportGeneratePanel · SavedReportsList · ReportPreview →
// ReportRenderedView → ReportSection · reports-utils (markdown serializer +
// formatters) · ReportChallengeModal.
//
// SECURITY (AGENTS §11): all report/finding text renders as escaped React text
// nodes (ReportRenderedView/ReportSection) or readonly textarea value (raw
// markdown). NO dangerouslySetInnerHTML on report data. Mock/real split is at
// the API adapter layer — no isMock branching here (§3).
// ─────────────────────────────────────────────────────────────────────────

export function ReportsTab() {
  const { addToast, portalState } = useStoreSlice((state) => ({
    addToast: state.addToast,
    portalState: state.portalState,
  }))

  // Approved-only report eligibility (DB authority). When the portal-state
  // endpoint reports it ineligible, generation is blocked in the UI (the backend
  // also enforces with a 409). When unavailable, eligibility is unknown and
  // generation is allowed.
  const eligibility = portalState?.report_eligibility ?? null
  const reportIneligible = eligibility != null && eligibility.eligible === false

  const { modal, openChallenge, closeChallenge, setPassword, submit } = useChallenge()
  const r = useReports({ addToast, openChallenge })

  return (
    <div className="flex h-full overflow-hidden bg-bg-base text-text-primary">
      <aside className="flex w-[340px] shrink-0 flex-col overflow-hidden border-r border-border-faint bg-card">
        <ReportGeneratePanel
          form={r.form}
          onField={r.setField}
          generating={r.generating}
          eligibility={eligibility}
          reportIneligible={reportIneligible}
          onGenerate={r.handleGenerate}
        />
        <SavedReportsList
          reports={r.reports}
          reportsLoading={r.reportsLoading}
          activeReportId={r.activeReportId}
          draftReport={r.draftReport}
          onSelect={r.handleSelectSavedReport}
          onDownload={r.handleDownload}
          onRefresh={r.refreshReports}
        />
      </aside>

      <section className="flex flex-1 flex-col overflow-hidden" aria-label="Report preview">
        <ReportPreview
          report={r.currentReport}
          loading={r.selectedReportLoading}
          draftReport={r.draftReport}
          onSave={r.handleSave}
          onDownload={r.handleDownload}
        />
      </section>

      <ReportChallengeModal modal={modal} onChange={setPassword} onSubmit={submit} onClose={closeChallenge} />
    </div>
  )
}
