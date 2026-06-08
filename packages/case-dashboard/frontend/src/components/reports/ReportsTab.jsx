import { useState, useEffect } from 'react'
import { useStore } from '../../store/useStore'
import {
  getReports,
  getReportChallenge,
  postReportGenerate,
  postReportSave,
  getReport
} from '../../api/endpoints'
import { computeSimpleChallengeResponse } from '../../api/crypto'

const PROFILES = {
  full: {
    label: 'Full IR Report',
    description: 'Comprehensive incident response report containing all approved findings, timeline events, IOCs, MITRE ATT&CK mappings, evidence manifest, and open tasks.'
  },
  executive: {
    label: 'Executive Briefing',
    description: 'Non-technical management briefing (1-2 pages) summarizing the incident situation, business impact, current status, and high-priority action items.'
  },
  timeline: {
    label: 'Timeline Narrative',
    description: 'Event-focused chronological narrative report. Ideal for detailing the exact lifecycle and steps of the intrusion.'
  },
  ioc: {
    label: 'Indicators of Compromise (IOC)',
    description: 'Structured threat intelligence export mapping IOCs to categories, hosts, and source findings.'
  },
  findings: {
    label: 'Findings Detail',
    description: 'Deep-dive technical report containing full detailed write-ups, observations, and interpretations of every approved finding.'
  },
  status: {
    label: 'Status Summary',
    description: 'Quick snapshot for standups and daily status checks, containing KPI counts and lists of open tasks.'
  }
}

export function ReportsTab() {
  const { addToast, portalState } = useStore()
  // Approved-only report eligibility (DB authority). When the portal-state
  // endpoint is wired and reports it ineligible, generation is blocked in the UI
  // (the backend also enforces this with a 409). When unavailable (file-backed
  // deployments), eligibility is unknown and generation is allowed.
  const eligibility = portalState?.report_eligibility ?? null
  const reportIneligible = eligibility != null && eligibility.eligible === false
  const [reports, setReports] = useState([])
  const [reportsLoading, setReportsLoading] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [activeProfile, setActiveProfile] = useState('full')
  const [findingIds, setFindingIds] = useState('')
  const [startDate, setStartDate] = useState('')
  const [endDate, setEndDate] = useState('')

  const [activeReportId, setActiveReportId] = useState(null)
  const [draftReport, setDraftReport] = useState(null)
  const [selectedReport, setSelectedReport] = useState(null)
  const [selectedReportLoading, setSelectedReportLoading] = useState(false)
  const [previewMode, setPreviewMode] = useState('rendered')

  // Operator re-auth for report inclusion/export (F-MVP-4). The server enforces
  // re-auth when DB evidence authority is wired; the modal collects the password
  // to compute the HMAC challenge response.
  const [reauthOpen, setReauthOpen] = useState(false)
  const [reauthPassword, setReauthPassword] = useState('')

  // Load list of saved reports on mount
  const refreshReports = async () => {
    setReportsLoading(true)
    try {
      const list = await getReports()
      const sortedChronological = [...(list || [])].reverse()
      const profileCounts = {}
      const mappedList = sortedChronological.map(r => {
        profileCounts[r.profile] = (profileCounts[r.profile] || 0) + 1
        return {
          ...r,
          version: `v${profileCounts[r.profile]}`
        }
      })
      mappedList.reverse()
      setReports(mappedList || [])
    } catch (err) {
      addToast('Failed to load reports: ' + (err.message || err), 'error')
    } finally {
      setReportsLoading(false)
    }
  }

  useEffect(() => {
    refreshReports()
  }, [])

  // Open the re-auth modal before generating (report inclusion is a sensitive
  // human action and requires password confirmation; F-MVP-4 / AGENTS.md).
  const handleGenerate = (e) => {
    e.preventDefault()
    setReauthPassword('')
    setReauthOpen(true)
  }

  const handleConfirmGenerate = async (e) => {
    e.preventDefault()
    setReauthOpen(false)
    setGenerating(true)
    setDraftReport(null)
    setSelectedReport(null)

    const payload = {
      profile: activeProfile,
      finding_ids: findingIds ? findingIds.split(',').map(id => id.trim()) : null,
      start_date: startDate || '',
      end_date: endDate || ''
    }

    // Compute the HMAC challenge response so the server can record a re-auth
    // audit event for this inclusion. Best-effort: if the challenge endpoint is
    // unavailable, generation still proceeds (the server only enforces re-auth
    // when DB authority is wired and will reject without it).
    try {
      const challenge = await getReportChallenge()
      if (challenge && challenge.challenge_id) {
        payload.challenge_id = challenge.challenge_id
        payload.response = await computeSimpleChallengeResponse(reauthPassword, challenge)
      }
    } catch (err) {
      // No challenge available (file-backed) — proceed without re-auth material.
    } finally {
      setReauthPassword('')
    }

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
    } finally {
      setGenerating(false)
    }
  }

  const handleSave = async () => {
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

  const handleSelectSavedReport = async (id) => {
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

  const handleDownload = async (id) => {
    if (!id) return
    try {
      const url = `/portal/api/reports/${id}/download`
      const res = await fetch(url, { credentials: 'include' })
      if (!res.ok) {
        throw new Error(`Download failed: HTTP ${res.status}`)
      }
      const blob = await res.blob()
      const objectUrl = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = objectUrl
      link.download = `report_${id.slice(0, 8)}.md`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      URL.revokeObjectURL(objectUrl)
    } catch (err) {
      addToast(err.message, 'error')
    }
  }

  // Format date cleanly
  const formatDate = (isoStr) => {
    if (!isoStr) return ''
    try {
      return new Date(isoStr).toLocaleString()
    } catch (e) {
      return isoStr
    }
  }

  const formatReportDate = (isoStr) => {
    if (!isoStr) return ''
    try {
      const d = new Date(isoStr)
      const month = d.getMonth() + 1
      const day = d.getDate()
      const year = d.getFullYear()
      const hours = String(d.getHours()).padStart(2, '0')
      const minutes = String(d.getMinutes()).padStart(2, '0')
      return `${month}/${day}/${year} ${hours}:${minutes}`
    } catch (e) {
      return isoStr
    }
  }

  const currentReport = draftReport || selectedReport

  // Simple client-side markdown generator for preview
  const serializeToMarkdown = (report) => {
    if (!report) return ''
    const meta = report.report_data?.metadata || {}
    const profileName = (report.profile || 'full').toUpperCase()
    const generatedAt = report.generated_at || ''
    const examiner = report.examiner || 'Unknown'
    const caseName = meta.name || 'Unknown Case'
    const caseId = meta.case_id || 'Unknown ID'

    const md = []
    md.push(`# Forensic Incident Report: ${caseName}`)
    md.push('')
    md.push('## Report Metadata')
    md.push(`- **Case ID**: ${caseId}`)
    md.push(`- **Report Profile**: ${profileName}`)
    md.push(`- **Generated At**: ${formatDate(generatedAt)}`)
    md.push(`- **Examiner**: ${examiner}`)
    md.push('')

    if (report.integrity_warning) {
      md.push('> [!CAUTION]')
      md.push(`> **Evidence Integrity Warning**: ${report.integrity_warning}`)
      md.push('')
    } else if (report.evidence_chain_warning) {
      md.push('> [!WARNING]')
      md.push(`> **Evidence Chain Warning**: ${report.evidence_chain_warning}`)
      md.push('')
    }

    const sections = report.sections || []
    const reportData = report.report_data || {}
    const zg = report.zeltser_guidance || {}

    for (const sec of sections) {
      const name = sec.name || 'Section'
      const dataKey = sec.data_key

      md.push(`## ${name}`)
      md.push('')

      if (!dataKey) {
        const guidance = zg[name]
        if (guidance && Array.isArray(guidance.instructions)) {
          md.push('### Guidance & Instructions')
          for (const ins of guidance.instructions) {
            md.push(`- ${ins}`)
          }
          md.push('')
        }
        const matchingHr = (report.human_review_required || []).find(hr => hr.section === name)
        if (matchingHr) {
          md.push('> [!IMPORTANT]')
          md.push(`> **Human Curation Required**: ${matchingHr.reason}`)
          md.push(`> ${matchingHr.prompt}`)
          md.push('')
        } else {
          md.push(`[Draft Section: Write narrative for ${name} here]`)
          md.push('')
        }
      } else {
        const data = reportData[dataKey]
        if (data === undefined || data === null) {
          if (reportData[`${dataKey}_count`] !== undefined) {
            md.push(`Total count of ${dataKey}: **${reportData[`${dataKey}_count`]}**`)
            md.push('')
          } else {
            md.push('*No data available for this section.*')
            md.push('')
          }
          continue
        }

        if (dataKey === 'summary') {
          md.push('| Metric | Count |')
          md.push('|---|---|')
          for (const [k, v] of Object.entries(data)) {
            if (typeof v === 'number') {
              const namePretty = k.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
              md.push(`| ${namePretty} | ${v} |`)
            }
          }
          md.push('')
        } else if (dataKey === 'findings') {
          if (!Array.isArray(data) || data.length === 0) {
            md.push('*No approved findings in this report.*')
            md.push('')
          } else {
            for (const f of data) {
              md.push(`### Finding ${f.id || 'N/A'}: ${f.title || 'Untitled'}`)
              md.push(`- **Type**: ${f.type || 'N/A'}`)
              md.push(`- **Confidence**: ${f.confidence || 'N/A'}`)
              md.push(`- **Host**: ${f.host || 'N/A'}`)
              md.push(`- **Affected Account**: ${f.affected_account || 'N/A'}`)
              md.push(`- **Event Timestamp**: ${f.event_timestamp || f.timestamp || 'N/A'}`)
              if (f.tags && f.tags.length > 0) {
                md.push(`- **Tags**: ${f.tags.join(', ')}`)
              }
              md.push('')

              if (f.observation) {
                md.push('#### Observation')
                md.push(String(f.observation))
                md.push('')
              }
              if (f.interpretation) {
                md.push('#### Interpretation')
                md.push(String(f.interpretation))
                md.push('')
              }
            }
          }
        } else if (dataKey === 'timeline') {
          if (!Array.isArray(data) || data.length === 0) {
            md.push('*No timeline events included.*')
            md.push('')
          } else {
            md.push('| Timestamp | Host | Type | Description |')
            md.push('|---|---|---|---|')
            for (const t of data) {
              md.push(`| ${t.timestamp || 'N/A'} | ${t.host || 'N/A'} | ${t.type || 'N/A'} | ${t.description || 'No description'} |`)
            }
            md.push('')
          }
        } else if (dataKey === 'iocs') {
          const rows = []
          if (data && typeof data === 'object' && !Array.isArray(data)) {
            for (const [iocType, items] of Object.entries(data)) {
              if (!Array.isArray(items)) continue
              for (const it of items) {
                if (it && typeof it === 'object') rows.push({ ...it, type: it.type || iocType })
                else if (typeof it === 'string') rows.push({ value: it, type: iocType })
              }
            }
          } else if (Array.isArray(data)) {
            for (const it of data) {
              if (it && typeof it === 'object') rows.push(it)
              else if (typeof it === 'string') rows.push({ value: it })
            }
          }
          if (rows.length === 0) {
            md.push('*No indicators of compromise.*')
            md.push('')
          } else {
            md.push('| Value | Type | Category | Host | Source Findings |')
            md.push('|---|---|---|---|---|')
            for (const i of rows) {
              md.push(`| ${i.value || 'N/A'} | ${i.type || 'N/A'} | ${i.category || 'N/A'} | ${i.host || 'N/A'} | ${(i.source_findings || []).join(', ')} |`)
            }
            md.push('')
          }
        } else if (dataKey === 'mitre_mapping') {
          const keys = Object.keys(data)
          if (keys.length === 0) {
            md.push('*No MITRE ATT&CK mapping.*')
            md.push('')
          } else {
            md.push('| Technique ID | Technique Name | Findings |')
            md.push('|---|---|---|')
            for (const [techId, techInfo] of Object.entries(data)) {
              md.push(`| ${techId} | ${techInfo.name || 'Unknown Technique'} | ${(techInfo.findings || []).join(', ')} |`)
            }
            md.push('')
          }
        } else if (dataKey === 'evidence') {
          if (!Array.isArray(data) || data.length === 0) {
            md.push('*No evidence files registered.*')
            md.push('')
          } else {
            md.push('| Path | Size (Bytes) | Hash | Status |')
            md.push('|---|---|---|---|')
            for (const ev of data) {
              md.push(`| ${ev.path || 'N/A'} | ${ev.size_bytes || 0} | \`${ev.sha256 || 'N/A'}\` | ${ev.status || 'N/A'} |`)
            }
            md.push('')
          }
        } else if (dataKey === 'todos') {
          if (!Array.isArray(data) || data.length === 0) {
            md.push('*No open TODOs.*')
            md.push('')
          } else {
            for (const t of data) {
              md.push(`- **${t.title || 'Untitled'}** (Priority: ${t.priority || 'N/A'}, Assigned: ${t.examiner || 'N/A'})`)
              md.push(`  ${t.description || 'No description'}`)
            }
            md.push('')
          }
        } else {
          md.push('```json')
          md.push(JSON.stringify(data, null, 2))
          md.push('```')
          md.push('')
        }
      }
    }

    // Custody / provenance appendix (F-MVP-4)
    const appendix = report.custody_appendix
    if (appendix) {
      md.push('## Appendix: Custody & Provenance')
      md.push('')
      if (appendix.verification_note) {
        md.push(appendix.verification_note)
        md.push('')
      }
      if (appendix.authorized_by_reauth_event) {
        md.push(`- **Authorized by re-auth event**: \`${appendix.authorized_by_reauth_event}\``)
        md.push('')
      }
      const seal = appendix.evidence_seal || {}
      md.push('### Evidence Seal & Hash-Chain Proof')
      md.push('| Field | Value |')
      md.push('|---|---|')
      md.push(`| Seal Status | ${seal.seal_status || 'N/A'} |`)
      md.push(`| Manifest Version | ${seal.manifest_version || 0} |`)
      md.push(`| Manifest Hash | \`${seal.manifest_hash || 'N/A'}\` |`)
      md.push(`| Chain Head Hash | \`${seal.chain_head_hash || 'N/A'}\` |`)
      md.push(`| Ledger Tip Hash | \`${seal.ledger_tip_hash || 'N/A'}\` |`)
      md.push(`| Active Evidence Count | ${seal.active_count || 0} |`)
      md.push('')
      md.push('### Finding Provenance')
      const fp = appendix.finding_provenance || []
      if (fp.length === 0) {
        md.push('*No approved findings.*')
        md.push('')
      } else {
        md.push('| Finding ID | Approval Hash | Approved By | Provenance / Audit Refs |')
        md.push('|---|---|---|---|')
        for (const entry of fp) {
          const refs = (entry.provenance_refs || []).join(', ') || '—'
          md.push(`| ${entry.id || 'N/A'} | \`${entry.content_hash || 'N/A'}\` | ${entry.approved_by || 'N/A'} | ${refs} |`)
        }
        md.push('')
      }
    }

    return md.join('\n')
  }

  return (
    <div className="flex h-full overflow-hidden bg-bg-base text-text-primary">
      {/* Left Sidebar Panel */}
      <div className="w-[340px] shrink-0 border-r border-border-faint flex flex-col bg-bg-surface overflow-hidden">
        {/* Generate Control Form */}
        <form onSubmit={handleGenerate} className="p-4 border-b border-border-faint flex flex-col gap-3">
          <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-text-muted">Generate Report</h2>

          {/* Approved-only report eligibility (DB authority) */}
          {eligibility != null && (
            <div
              className={`text-[10px] rounded px-2 py-1.5 border ${reportIneligible ? 'border-amber text-amber' : 'border-border-soft text-text-muted'}`}
              data-testid="report-eligibility"
            >
              {reportIneligible
                ? `Not eligible: ${eligibility.reason || 'no approved findings'}. Approve at least one finding before generating a report.`
                : `Eligible — ${eligibility.approved_findings ?? 0} of ${eligibility.total_findings ?? 0} findings approved. Reports include approved data only.`}
            </div>
          )}

          <div className="flex flex-col gap-1 relative group">
            <label className="text-[11px] font-sans font-medium text-text-muted">Report Profile</label>
            <select
              value={activeProfile}
              onChange={(e) => setActiveProfile(e.target.value)}
              className="bg-bg-raised text-text-primary text-xs rounded border border-border-soft px-2 py-1.5 focus:outline-none focus:border-cyan"
            >
              {Object.keys(PROFILES).map((key) => (
                <option key={key} value={key}>{PROFILES[key].label}</option>
              ))}
            </select>
            {/* Tooltip Description */}
            <div className="pointer-events-none absolute left-0 top-[52px] w-full p-2 bg-bg-overlay border border-border-soft rounded text-[10px] text-text-muted leading-relaxed opacity-0 group-hover:opacity-100 transition-opacity duration-150 z-50">
              {PROFILES[activeProfile].description}
            </div>
          </div>

          {/* Optional Filter Accordion */}
          <div className="flex flex-col gap-2 mt-1">
            <div className="text-[10px] font-mono text-text-muted uppercase tracking-wider">Filters (Optional)</div>
            
            <div className="flex gap-2">
              <div className="flex-1 flex flex-col gap-0.5">
                <span className="text-[10px] text-text-muted">Start Date</span>
                <input
                  type="text"
                  placeholder="YYYY-MM-DD"
                  value={startDate}
                  onChange={(e) => setStartDate(e.target.value)}
                  className="bg-bg-raised text-text-primary text-[10px] font-mono rounded border border-border-soft px-1.5 py-1 focus:outline-none focus:border-cyan"
                />
              </div>
              <div className="flex-1 flex flex-col gap-0.5">
                <span className="text-[10px] text-text-muted">End Date</span>
                <input
                  type="text"
                  placeholder="YYYY-MM-DD"
                  value={endDate}
                  onChange={(e) => setEndDate(e.target.value)}
                  className="bg-bg-raised text-text-primary text-[10px] font-mono rounded border border-border-soft px-1.5 py-1 focus:outline-none focus:border-cyan"
                />
              </div>
            </div>

            <div className="flex flex-col gap-0.5">
              <span className="text-[10px] text-text-muted">Finding IDs (comma sep)</span>
              <input
                type="text"
                placeholder="F-001, F-002"
                value={findingIds}
                onChange={(e) => setFindingIds(e.target.value)}
                className="bg-bg-raised text-text-primary text-[10px] font-mono rounded border border-border-soft px-1.5 py-1 focus:outline-none focus:border-cyan"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={generating || reportIneligible}
            title={reportIneligible ? 'Report generation requires at least one approved finding' : undefined}
            className="w-full mt-2 bg-cyan text-bg-base font-bold text-xs py-2 rounded hover:bg-opacity-95 transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-1.5"
            style={{ backgroundColor: 'var(--cyan)' }}
          >
            {generating ? (
              <>
                <svg className="animate-spin h-3 w-3 text-bg-base" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Generating...
              </>
            ) : (
              <>
                <svg className="h-3 w-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5"><path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" /></svg>
                Generate Draft
              </>
            )}
          </button>
        </form>

        {/* Saved Reports List Pane */}
        <div className="flex-1 flex flex-col overflow-hidden">
          <div className="p-3 bg-bg-base border-b border-border-faint flex items-center justify-between">
            <span className="text-xs font-mono text-text-muted uppercase">Saved Reports</span>
            <button
              onClick={refreshReports}
              disabled={reportsLoading}
              title="Refresh Reports"
              className="text-text-muted hover:text-text-primary transition-colors disabled:opacity-50"
            >
              <svg className={`h-3.5 w-3.5 ${reportsLoading ? 'animate-spin' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 7.89H18" />
              </svg>
            </button>
          </div>

          <div className="flex-1 overflow-y-auto p-2 flex flex-col gap-1.5">
            {reportsLoading && reports.length === 0 ? (
              <div className="text-center py-6 text-xs text-text-muted font-mono">Loading reports...</div>
            ) : reports.length === 0 ? (
              <div className="text-center py-8 text-xs text-text-muted font-mono">No saved reports found</div>
            ) : (
              reports.map((r) => (
                <div
                  key={r.id}
                  onClick={() => handleSelectSavedReport(r.id)}
                  className={`p-3 rounded border text-left cursor-pointer transition-all flex flex-col gap-1 group relative ${
                    activeReportId === r.id && !draftReport
                      ? 'bg-bg-raised border-cyan'
                      : 'bg-bg-raised border-border-faint hover:border-border-soft'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-text-primary">
                      {PROFILES[r.profile]?.label || r.profile} — {r.version || 'v1'} · {formatReportDate(r.created_at)}
                    </span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        handleDownload(r.id)
                      }}
                      title="Download Markdown"
                      className="text-text-muted hover:text-cyan transition-colors"
                    >
                      <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                      </svg>
                    </button>
                  </div>
                  <div className="flex items-center justify-between text-[10px] text-text-muted font-mono mt-1">
                    <span title={r.id}>ID: {r.id.slice(0, 8)}...</span>
                    <span>{r.examiner}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Right Main Preview Pane */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {selectedReportLoading ? (
          <div className="flex-1 flex items-center justify-center font-mono text-sm text-text-muted">
            Loading report content...
          </div>
        ) : !currentReport ? (
          <div className="flex-1 flex flex-col items-center justify-center p-8 text-center text-text-muted bg-bg-base font-mono">
            <svg className="h-10 w-10 text-border-soft mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
              <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
            </svg>
            <p className="text-sm font-semibold">No report selected</p>
            <p className="text-xs text-text-muted mt-1 max-w-xs">Select a saved report on the left or generate a new draft briefing.</p>
          </div>
        ) : (
          <div className="flex-1 flex flex-col overflow-hidden bg-bg-base">
            {/* Top Toolbar */}
            <div className="h-12 border-b border-border-faint px-4 bg-bg-surface flex items-center justify-between shrink-0">
              <div className="flex items-center gap-3">
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                  draftReport ? 'bg-amber-dim text-amber border border-amber/20' : 'bg-green-dim text-green border border-green/20'
                }`}>
                  {draftReport ? 'Draft Briefing' : 'Saved Report'}
                </span>
                <span className="text-xs font-mono text-text-muted cursor-help" title={currentReport.id}>
                  ID: <span className="text-text-primary">{currentReport.id.slice(0, 8)}...</span>
                </span>
              </div>

              <div className="flex items-center gap-3">
                {/* Preview Mode Selector */}
                <div className="flex bg-bg-base border border-border-soft p-0.5 rounded text-[10px]">
                  <button
                    onClick={() => setPreviewMode('rendered')}
                    className={`px-2 py-1 rounded transition-colors ${
                      previewMode === 'rendered' ? 'bg-bg-raised text-cyan font-bold' : 'text-text-muted hover:text-text-primary'
                    }`}
                  >
                    Rendered
                  </button>
                  <button
                    onClick={() => setPreviewMode('raw')}
                    className={`px-2 py-1 rounded transition-colors ${
                      previewMode === 'raw' ? 'bg-bg-raised text-cyan font-bold' : 'text-text-muted hover:text-text-primary'
                    }`}
                  >
                    Raw Markdown
                  </button>
                </div>

                {draftReport && (
                  <button
                    onClick={handleSave}
                    className="bg-cyan text-bg-base text-xs font-bold px-3 py-1.5 rounded hover:bg-opacity-95 transition-colors flex items-center gap-1"
                    style={{ backgroundColor: 'var(--cyan)' }}
                  >
                    <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5"><path strokeLinecap="round" strokeLinejoin="round" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4" /></svg>
                    Save Report
                  </button>
                )}

                <button
                  onClick={() => handleDownload(currentReport.id)}
                  className="bg-bg-raised text-text-primary border border-border-soft text-xs font-bold px-3 py-1.5 rounded hover:bg-bg-overlay transition-colors flex items-center gap-1"
                >
                  <svg className="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2.5"><path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
                  Download .md
                </button>
              </div>
            </div>

            {/* Content Area */}
            <div className="flex-1 overflow-y-auto p-6 flex justify-center">
              <div className="w-full max-w-3xl flex flex-col gap-6">
                
                {/* Warnings inside preview if any */}
                {currentReport.integrity_warning && (
                  <div className="p-4 bg-crimson-dim border border-crimson/20 rounded flex flex-col gap-1 text-left">
                    <span className="text-xs font-mono font-bold text-crimson uppercase tracking-wide">⚠️ Evidence Integrity Violation</span>
                    <p className="text-xs text-text-primary leading-relaxed mt-0.5">{currentReport.integrity_warning}</p>
                  </div>
                )}
                {currentReport.evidence_chain_warning && (
                  <div className="p-4 bg-amber-dim border border-amber/20 rounded flex flex-col gap-1 text-left">
                    <span className="text-xs font-mono font-bold text-amber uppercase tracking-wide">⚠️ Evidence Chain Notice</span>
                    <p className="text-xs text-text-primary leading-relaxed mt-0.5">{currentReport.evidence_chain_warning}</p>
                  </div>
                )}

                {previewMode === 'raw' ? (
                  /* Raw Markdown Textarea View */
                  <div className="flex-1 flex flex-col min-h-[400px]">
                    <textarea
                      readOnly
                      value={serializeToMarkdown(currentReport)}
                      className="flex-1 w-full p-4 bg-bg-surface text-text-primary font-mono text-xs rounded border border-border-soft focus:outline-none resize-none leading-relaxed"
                    />
                  </div>
                ) : (
                  /* Rendered View (Custom High-Fidelity Formatted Layout) */
                  <div className="text-left font-sans text-text-primary leading-relaxed flex flex-col gap-6 pb-12">
                    
                    {/* Header Block */}
                    <div className="border-b border-border-faint pb-4">
                      <h1 className="text-2xl font-bold font-sans tracking-tight text-text-primary">
                        Forensic Incident Report: {currentReport.report_data?.metadata?.name || 'Unknown Case'}
                      </h1>
                      <div className="grid grid-cols-2 gap-4 mt-4 bg-bg-surface p-3 rounded border border-border-faint text-xs font-mono">
                        <div>
                          <span className="text-text-muted">Case ID:</span>{' '}
                          <span className="text-text-primary font-bold">{currentReport.report_data?.metadata?.case_id || 'N/A'}</span>
                        </div>
                        <div>
                          <span className="text-text-muted">Report Profile:</span>{' '}
                          <span className="text-text-primary font-bold">{(currentReport.profile || 'full').toUpperCase()}</span>
                        </div>
                        <div>
                          <span className="text-text-muted">Generated At:</span>{' '}
                          <span className="text-text-primary font-bold">{formatDate(currentReport.generated_at)}</span>
                        </div>
                        <div>
                          <span className="text-text-muted">Examiner:</span>{' '}
                          <span className="text-text-primary font-bold">{currentReport.examiner || 'Unknown'}</span>
                        </div>
                      </div>
                    </div>

                    {/* Section Renders */}
                    {(currentReport.sections || []).map((sec, idx) => {
                      const name = sec.name || 'Section'
                      const dataKey = sec.data_key
                      const data = currentReport.report_data?.[dataKey]
                      const zg = currentReport.zeltser_guidance?.[name]

                      return (
                        <div key={idx} className="flex flex-col gap-3">
                          <h2 className="text-lg font-bold border-b border-border-faint pb-1.5 mt-4 text-text-primary font-sans">
                            {name}
                          </h2>

                          {!dataKey ? (
                            /* Narrative/Guidance section placeholder */
                            <div className="p-4 bg-bg-surface border border-border-soft rounded flex flex-col gap-3">
                              {zg && Array.isArray(zg.instructions) && (
                                <div className="flex flex-col gap-1 text-[11px] text-text-muted border-b border-border-faint pb-2">
                                  <span className="font-mono font-bold uppercase tracking-wider text-text-muted">Zeltser IR Guidance:</span>
                                  <ul className="list-disc pl-4 mt-1 flex flex-col gap-1">
                                    {zg.instructions.map((ins, i) => <li key={i}>{ins}</li>)}
                                  </ul>
                                </div>
                              )}
                              
                              {(() => {
                                const hr = (currentReport.human_review_required || []).find(h => h.section === name)
                                if (hr) {
                                  return (
                                    <div className="p-3 bg-amber-dim/50 border border-amber/10 rounded flex flex-col gap-1">
                                      <span className="text-[11px] font-mono font-bold text-amber uppercase">✏️ Human Curation Required ({hr.reason})</span>
                                      <p className="text-xs text-text-primary italic mt-0.5">{hr.prompt}</p>
                                    </div>
                                  )
                                }
                                return (
                                  <p className="text-xs font-mono text-text-muted italic">
                                    [Narrative segment draft placeholder. examiner notes will append here.]
                                  </p>
                                )
                              })()}
                            </div>
                          ) : (
                            /* Data rendering */
                            <div className="overflow-x-auto">
                              {data === undefined || data === null ? (
                                currentReport.report_data?.[`${dataKey}_count`] !== undefined ? (
                                  <div className="text-xs font-mono text-text-primary">
                                    Total Count: <span className="font-bold text-cyan">{currentReport.report_data[`${dataKey}_count`]}</span>
                                  </div>
                                ) : (
                                  <span className="text-xs text-text-muted italic">No data available for this section.</span>
                                )
                              ) : dataKey === 'summary' ? (
                                <table className="min-w-full text-xs font-mono bg-bg-surface border border-border-soft rounded overflow-hidden">
                                  <thead>
                                    <tr className="bg-bg-raised border-b border-border-soft text-text-muted text-left font-bold">
                                      <th className="px-3 py-2">Metric Key</th>
                                      <th className="px-3 py-2">Count</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {Object.entries(data).map(([k, v]) => typeof v === 'number' && (
                                      <tr key={k} className="border-b border-border-faint last:border-0 hover:bg-bg-base/30">
                                        <td className="px-3 py-2 font-bold">{k.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}</td>
                                        <td className="px-3 py-2 text-cyan font-bold">{v}</td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              ) : dataKey === 'findings' ? (
                                !Array.isArray(data) || data.length === 0 ? (
                                  <span className="text-xs text-text-muted italic">No approved findings.</span>
                                ) : (
                                  <div className="flex flex-col gap-4">
                                    {data.map((f, i) => (
                                      <div key={i} className="p-4 bg-bg-surface border border-border-soft rounded flex flex-col gap-2">
                                        <div className="flex items-center justify-between border-b border-border-faint pb-1.5">
                                          <span className="font-bold text-sm text-text-primary">
                                            {f.id}: {f.title}
                                          </span>
                                          <span className="text-[10px] font-mono bg-bg-raised border border-border-soft px-1.5 py-0.5 rounded font-bold text-cyan">
                                            {f.confidence} Confidence
                                          </span>
                                        </div>
                                        <div className="grid grid-cols-3 gap-2 text-[10px] font-mono text-text-muted">
                                          <div><span className="text-text-muted">Host:</span> <span className="text-text-primary font-bold">{f.host || 'N/A'}</span></div>
                                          <div><span className="text-text-muted">Account:</span> <span className="text-text-primary font-bold">{f.affected_account || 'N/A'}</span></div>
                                          <div><span className="text-text-muted">Timestamp:</span> <span className="text-text-primary font-bold">{f.event_timestamp || f.timestamp || 'N/A'}</span></div>
                                        </div>
                                        {f.observation && (
                                          <div className="mt-2 text-xs text-left">
                                            <span className="font-bold text-text-muted text-[10px] uppercase font-mono block">Observation:</span>
                                            <p className="mt-0.5 text-text-primary">{f.observation}</p>
                                          </div>
                                        )}
                                        {f.interpretation && (
                                          <div className="mt-2 text-xs text-left">
                                            <span className="font-bold text-text-muted text-[10px] uppercase font-mono block">Interpretation:</span>
                                            <p className="mt-0.5 text-text-primary">{f.interpretation}</p>
                                          </div>
                                        )}
                                      </div>
                                    ))}
                                  </div>
                                )
                              ) : dataKey === 'timeline' ? (
                                !Array.isArray(data) || data.length === 0 ? (
                                  <span className="text-xs text-text-muted italic">No timeline data.</span>
                                ) : (
                                  <table className="min-w-full text-[11px] font-mono bg-bg-surface border border-border-soft rounded overflow-hidden">
                                    <thead>
                                      <tr className="bg-bg-raised border-b border-border-soft text-text-muted text-left font-bold">
                                        <th className="px-2 py-1.5 w-1/4">Timestamp</th>
                                        <th className="px-2 py-1.5 w-1/6">Host</th>
                                        <th className="px-2 py-1.5 w-1/6">Type</th>
                                        <th className="px-2 py-1.5">Description</th>
                                      </tr>
                                    </thead>
                                    <tbody>
                                      {data.map((t, i) => (
                                        <tr key={i} className="border-b border-border-faint last:border-0 hover:bg-bg-base/30">
                                          <td className="px-2 py-1.5 text-text-muted">{t.timestamp}</td>
                                          <td className="px-2 py-1.5">{t.host}</td>
                                          <td className="px-2 py-1.5"><span className="px-1 py-0.5 bg-bg-raised rounded text-[9px] border border-border-faint text-text-muted">{t.type}</span></td>
                                          <td className="px-2 py-1.5 text-text-primary">{t.description}</td>
                                        </tr>
                                      ))}
                                    </tbody>
                                  </table>
                                )
                              ) : dataKey === 'iocs' ? (
                                (() => {
                                  const rows = []
                                  if (data && typeof data === 'object' && !Array.isArray(data)) {
                                    for (const [iocType, items] of Object.entries(data)) {
                                      if (!Array.isArray(items)) continue
                                      for (const it of items) {
                                        if (it && typeof it === 'object') rows.push({ ...it, type: it.type || iocType })
                                        else if (typeof it === 'string') rows.push({ value: it, type: iocType })
                                      }
                                    }
                                  } else if (Array.isArray(data)) {
                                    for (const it of data) {
                                      if (it && typeof it === 'object') rows.push(it)
                                      else if (typeof it === 'string') rows.push({ value: it })
                                    }
                                  }
                                  if (rows.length === 0) {
                                    return <span className="text-xs text-text-muted italic">No IOCs.</span>
                                  }
                                  return (
                                    <table className="min-w-full text-[11px] font-mono bg-bg-surface border border-border-soft rounded overflow-hidden">
                                      <thead>
                                        <tr className="bg-bg-raised border-b border-border-soft text-text-muted text-left font-bold">
                                          <th className="px-2 py-1.5 w-1/3">Value</th>
                                          <th className="px-2 py-1.5">Type</th>
                                          <th className="px-2 py-1.5">Category</th>
                                          <th className="px-2 py-1.5">Host</th>
                                          <th className="px-2 py-1.5">Sources</th>
                                        </tr>
                                      </thead>
                                      <tbody>
                                        {rows.map((ioc, i) => (
                                          <tr key={i} className="border-b border-border-faint last:border-0 hover:bg-bg-base/30">
                                            <td className="px-2 py-1.5 text-cyan font-bold break-all">{ioc.value}</td>
                                            <td className="px-2 py-1.5">{ioc.type}</td>
                                            <td className="px-2 py-1.5">{ioc.category}</td>
                                            <td className="px-2 py-1.5 text-text-muted">{ioc.host}</td>
                                            <td className="px-2 py-1.5 text-text-muted">{(ioc.source_findings || []).join(', ')}</td>
                                          </tr>
                                        ))}
                                      </tbody>
                                    </table>
                                  )
                                })()
                              ) : dataKey === 'mitre_mapping' ? (
                                Object.keys(data).length === 0 ? (
                                  <span className="text-xs text-text-muted italic">No MITRE ATT&CK mapping.</span>
                                ) : (
                                  <table className="min-w-full text-[11px] font-mono bg-bg-surface border border-border-soft rounded overflow-hidden">
                                    <thead>
                                      <tr className="bg-bg-raised border-b border-border-soft text-text-muted text-left font-bold">
                                        <th className="px-2 py-1.5 w-1/4">Technique ID</th>
                                        <th className="px-2 py-1.5 w-1/2">Name</th>
                                        <th className="px-2 py-1.5">Findings</th>
                                      </tr>
                                    </thead>
                                    <tbody>
                                      {Object.entries(data).map(([techId, techInfo]) => (
                                        <tr key={techId} className="border-b border-border-faint last:border-0 hover:bg-bg-base/30">
                                          <td className="px-2 py-1.5 text-cyan font-bold">{techId}</td>
                                          <td className="px-2 py-1.5">{techInfo.name}</td>
                                          <td className="px-2 py-1.5 text-text-muted">{(techInfo.findings || []).join(', ')}</td>
                                        </tr>
                                      ))}
                                    </tbody>
                                  </table>
                                )
                              ) : dataKey === 'evidence' ? (
                                !Array.isArray(data) || data.length === 0 ? (
                                  <span className="text-xs text-text-muted italic">No evidence.</span>
                                ) : (
                                  <table className="min-w-full text-[11px] font-mono bg-bg-surface border border-border-soft rounded overflow-hidden">
                                    <thead>
                                      <tr className="bg-bg-raised border-b border-border-soft text-text-muted text-left font-bold">
                                        <th className="px-2 py-1.5 w-1/3">Path</th>
                                        <th className="px-2 py-1.5">Size</th>
                                        <th className="px-2 py-1.5 w-1/3">Hash (SHA-256)</th>
                                        <th className="px-2 py-1.5">Status</th>
                                      </tr>
                                    </thead>
                                    <tbody>
                                      {data.map((ev, i) => (
                                        <tr key={i} className="border-b border-border-faint last:border-0 hover:bg-bg-base/30">
                                          <td className="px-2 py-1.5 text-text-primary break-all">{ev.path}</td>
                                          <td className="px-2 py-1.5 text-text-muted">{ev.size_bytes}</td>
                                          <td className="px-2 py-1.5 text-text-muted select-all truncate max-w-[150px]" title={ev.sha256}>{ev.sha256}</td>
                                          <td className="px-2 py-1.5"><span className="text-[10px] px-1 py-0.5 rounded font-bold uppercase bg-bg-raised border border-border-faint">{ev.status}</span></td>
                                        </tr>
                                      ))}
                                    </tbody>
                                  </table>
                                )
                              ) : dataKey === 'todos' ? (
                                !Array.isArray(data) || data.length === 0 ? (
                                  <span className="text-xs text-text-muted italic">No open TODOs.</span>
                                ) : (
                                  <div className="flex flex-col gap-2">
                                    {data.map((todo, i) => (
                                      <div key={i} className="p-3 bg-bg-surface border border-border-soft rounded flex flex-col gap-1">
                                        <div className="flex items-center justify-between">
                                          <span className="text-xs font-bold text-text-primary">{todo.title}</span>
                                          <span className="text-[9px] uppercase font-mono px-1 border border-border-soft bg-bg-raised rounded text-cyan">{todo.priority} priority</span>
                                        </div>
                                        <p className="text-xs text-text-muted mt-0.5">{todo.description}</p>
                                        <div className="text-[9px] font-mono text-text-muted mt-1">Assigned: {todo.examiner}</div>
                                      </div>
                                    ))}
                                  </div>
                                )
                              ) : (
                                <pre className="text-left font-mono text-xs p-3 bg-bg-surface rounded border border-border-soft">
                                  {JSON.stringify(data, null, 2)}
                                </pre>
                              )}
                            </div>
                          )}
                        </div>
                      )
                    })}

                    {/* Custody / Provenance Appendix (F-MVP-4) */}
                    {currentReport.custody_appendix && (() => {
                      const appendix = currentReport.custody_appendix
                      const seal = appendix.evidence_seal || {}
                      const fp = appendix.finding_provenance || []
                      return (
                        <div className="flex flex-col gap-3 mt-4">
                          <h2 className="text-lg font-bold border-b border-border-faint pb-1.5 mt-4 text-text-primary font-sans">
                            Appendix: Custody &amp; Provenance
                          </h2>
                          {appendix.verification_note && (
                            <p className="text-xs text-text-muted italic">{appendix.verification_note}</p>
                          )}
                          {appendix.authorized_by_reauth_event && (
                            <div className="text-[10px] font-mono text-text-muted">
                              Authorized by re-auth event:{' '}
                              <span className="text-cyan break-all">{appendix.authorized_by_reauth_event}</span>
                            </div>
                          )}
                          <div className="overflow-x-auto">
                            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-text-muted mb-1">Evidence Seal &amp; Hash-Chain Proof</h3>
                            <table className="min-w-full text-[11px] font-mono bg-bg-surface border border-border-soft rounded overflow-hidden">
                              <tbody>
                                {[
                                  ['Seal Status', seal.seal_status || 'N/A'],
                                  ['Manifest Version', seal.manifest_version ?? 0],
                                  ['Manifest Hash', seal.manifest_hash || 'N/A'],
                                  ['Chain Head Hash', seal.chain_head_hash || 'N/A'],
                                  ['Ledger Tip Hash', seal.ledger_tip_hash || 'N/A'],
                                  ['Active Evidence Count', seal.active_count ?? 0],
                                ].map(([k, v]) => (
                                  <tr key={k} className="border-b border-border-faint last:border-0">
                                    <td className="px-3 py-1.5 font-bold text-text-muted w-1/3">{k}</td>
                                    <td className="px-3 py-1.5 text-text-primary break-all">{String(v)}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                          <div className="overflow-x-auto">
                            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-text-muted mb-1">Finding Provenance</h3>
                            {fp.length === 0 ? (
                              <span className="text-xs text-text-muted italic">No approved findings.</span>
                            ) : (
                              <table className="min-w-full text-[11px] font-mono bg-bg-surface border border-border-soft rounded overflow-hidden">
                                <thead>
                                  <tr className="bg-bg-raised border-b border-border-soft text-text-muted text-left font-bold">
                                    <th className="px-2 py-1.5">Finding ID</th>
                                    <th className="px-2 py-1.5 w-1/3">Approval Hash</th>
                                    <th className="px-2 py-1.5">Approved By</th>
                                    <th className="px-2 py-1.5">Provenance / Audit Refs</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {fp.map((entry, i) => (
                                    <tr key={i} className="border-b border-border-faint last:border-0 hover:bg-bg-base/30">
                                      <td className="px-2 py-1.5 text-cyan font-bold">{entry.id}</td>
                                      <td className="px-2 py-1.5 text-text-muted break-all truncate max-w-[160px]" title={entry.content_hash}>{entry.content_hash || 'N/A'}</td>
                                      <td className="px-2 py-1.5 text-text-primary">{entry.approved_by || 'N/A'}</td>
                                      <td className="px-2 py-1.5 text-text-muted break-all">{(entry.provenance_refs || []).join(', ') || '—'}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            )}
                          </div>
                        </div>
                      )
                    })()}
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Re-auth modal for report inclusion/export (F-MVP-4) */}
      {reauthOpen && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60">
          <form
            onSubmit={handleConfirmGenerate}
            className="w-[360px] bg-bg-surface border border-border-soft rounded-lg p-5 flex flex-col gap-3 shadow-xl"
          >
            <h3 className="text-sm font-bold text-text-primary">Confirm Report Generation</h3>
            <p className="text-xs text-text-muted leading-relaxed">
              Report inclusion and export are sensitive actions. Re-enter your password to
              authorize generating this report from approved data only.
            </p>
            <input
              type="password"
              autoFocus
              value={reauthPassword}
              onChange={(e) => setReauthPassword(e.target.value)}
              placeholder="Examiner password"
              className="bg-bg-raised text-text-primary text-xs rounded border border-border-soft px-2 py-2 focus:outline-none focus:border-cyan"
            />
            <div className="flex justify-end gap-2 mt-1">
              <button
                type="button"
                onClick={() => { setReauthOpen(false); setReauthPassword('') }}
                className="text-xs px-3 py-1.5 rounded border border-border-soft text-text-muted hover:text-text-primary transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="text-xs font-bold px-3 py-1.5 rounded text-bg-base"
                style={{ backgroundColor: 'var(--cyan)' }}
              >
                Authorize &amp; Generate
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  )
}
