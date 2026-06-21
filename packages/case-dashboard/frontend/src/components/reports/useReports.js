import { useCallback, useEffect, useState } from 'react'

import { getReports, postReportGenerate, postReportSave, getReport } from '@/api/endpoints'
import { withVersions, triggerDownload } from './reports-utils'

// ─────────────────────────────────────────────────────────────────────────
// useReports — owns the saved-reports list, the active draft / selected report,
// the generate form fields, and every report action (refresh · generate · save
// · select · download). Keeps ReportsTab a thin orchestrator. The generate
// action is challenge-gated: handleGenerate(params) is the onConfirm body the
// password modal runs, so the operator password is re-verified server-side
// against Supabase (B-MVP-017 / F-MVP-4) before any inclusion. Mock/real split
// is at the API adapter layer — no isMock branching here (§3).
// ─────────────────────────────────────────────────────────────────────────

const EMPTY_FORM = { profile: 'full', findingIds: '', startDate: '', endDate: '' }

export function useReports({ addToast, openChallenge }) {
  const [reports, setReports] = useState([])
  const [reportsLoading, setReportsLoading] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [form, setForm] = useState(EMPTY_FORM)

  const [activeReportId, setActiveReportId] = useState(null)
  const [draftReport, setDraftReport] = useState(null)
  const [selectedReport, setSelectedReport] = useState(null)
  const [selectedReportLoading, setSelectedReportLoading] = useState(false)

  const setField = useCallback((field, value) => {
    setForm((prev) => ({ ...prev, [field]: value }))
  }, [])

  const refreshReports = useCallback(async () => {
    setReportsLoading(true)
    try {
      const list = await getReports()
      setReports(withVersions(list))
    } catch (err) {
      addToast('Failed to load reports: ' + (err.message || err), 'error')
    } finally {
      setReportsLoading(false)
    }
  }, [addToast])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    refreshReports()
  }, [refreshReports])

  // Open the password challenge before generating. The modal's onConfirm runs
  // the inclusion with the verified password (sensitive human action, F-MVP-4).
  function handleGenerate() {
    openChallenge('Confirm Report Generation', async ({ password }) => {
      setGenerating(true)
      setDraftReport(null)
      setSelectedReport(null)
      const payload = {
        profile: form.profile,
        finding_ids: form.findingIds ? form.findingIds.split(',').map((id) => id.trim()) : null,
        start_date: form.startDate || '',
        end_date: form.endDate || '',
      }
      if (password) payload.password = password
      try {
        const result = await postReportGenerate(payload)
        if (result) {
          setDraftReport(result)
          setActiveReportId(result.id)
          addToast('Report draft generated successfully', 'success')
        }
      } catch (err) {
        if (err.status === 429) {
          addToast('Too many attempts. A report generation is already in progress for this case.', 'error')
        } else if (err.status === 401 || err.status === 403) {
          addToast('Re-auth failed: incorrect password or expired challenge.', 'error')
        } else {
          addToast('Report generation failed. Check the case status.', 'error')
        }
        throw err
      } finally {
        setGenerating(false)
      }
    })
  }

  async function handleSave() {
    if (!draftReport || !draftReport.id) return
    try {
      const result = await postReportSave(draftReport.id)
      if (result && result.status === 'saved') {
        addToast('Report saved successfully', 'success')
        const saved = await getReport(draftReport.id)
        setSelectedReport(saved)
        setDraftReport(null)
        refreshReports()
      }
    } catch (err) {
      addToast('Failed to save report: ' + (err.message || err), 'error')
    }
  }

  async function handleSelectSavedReport(id) {
    setSelectedReportLoading(true)
    setDraftReport(null)
    setActiveReportId(id)
    try {
      const saved = await getReport(id)
      setSelectedReport(saved)
    } catch (err) {
      addToast('Failed to load report: ' + (err.message || err), 'error')
    } finally {
      setSelectedReportLoading(false)
    }
  }

  // Download the saved .md via the authenticated proxy. The blob is built from
  // the server-rendered markdown and triggered as a file download.
  async function handleDownload(id) {
    if (!id) return
    try {
      const res = await fetch(`/portal/api/reports/${id}/download`, { credentials: 'include' })
      if (!res.ok) throw new Error(`Download failed: HTTP ${res.status}`)
      triggerDownload(await res.blob(), `report_${id.slice(0, 8)}.md`)
    } catch (err) {
      addToast(err.message, 'error')
    }
  }

  const currentReport = draftReport || selectedReport

  return {
    reports,
    reportsLoading,
    generating,
    form,
    setField,
    activeReportId,
    draftReport,
    selectedReport,
    selectedReportLoading,
    currentReport,
    refreshReports,
    handleGenerate,
    handleSave,
    handleSelectSavedReport,
    handleDownload,
  }
}
