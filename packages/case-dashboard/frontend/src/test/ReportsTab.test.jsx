import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'

import { useStore } from '@/store/useStore'
import * as endpoints from '@/api/endpoints'
import {
  serializeToMarkdown,
  withVersions,
  flattenIocs,
  profileLabel,
  formatReportDate,
} from '@/components/reports/reports-utils'
import { ReportsTab } from '@/components/reports/ReportsTab'

// ─────────────────────────────────────────────────────────────────────────
// ReportsTab.test.jsx — pure logic (markdown serializer · versioning · IOC
// flatten) PLUS interaction coverage of the challenge-gated generate flow, the
// saved-report select/render path, and the Rendered/Raw toggle.
//
// SECURITY ASSERTION: a <script>/HTML payload embedded in report data must
// render as ESCAPED TEXT and never execute/inject — verified in both the
// Rendered view (no live <script> node) and the Raw markdown serializer.
// ─────────────────────────────────────────────────────────────────────────

const XSS = '<script>window.__pwned__=1</script>'

const SAVED_REPORT = {
  id: 'rpt-abc12345',
  profile: 'executive',
  examiner: 'e.varga',
  generated_at: '2026-06-20T10:00:00Z',
  report_data: {
    metadata: { name: 'NORTHWIND', case_id: 'CASE-1' },
    summary: { total_findings: 6, approved_findings: 1 },
    findings: [
      {
        id: 'F-001',
        title: 'Lateral movement',
        confidence: 'HIGH',
        host: 'DC-01',
        observation: `EVTX logon ${XSS} payload`,
        interpretation: 'Hands-on-keyboard.',
      },
    ],
  },
  sections: [
    { name: 'Summary', data_key: 'summary' },
    { name: 'Findings', data_key: 'findings' },
  ],
}

// ── Pure logic ───────────────────────────────────────────────────────────
describe('reports-utils — pure logic', () => {
  it('withVersions: per-profile version counted oldest→newest (legacy parity)', () => {
    // Input is newest-first; the API list is reversed to chronological for
    // version counting, so the OLDEST item of a profile is v1. Here `b` is the
    // older "full" → v1, `a` the newer "full" → v2; `c` is the sole executive.
    const list = [
      { id: 'a', profile: 'full' },
      { id: 'b', profile: 'full' },
      { id: 'c', profile: 'executive' },
    ]
    const out = withVersions(list)
    const byId = Object.fromEntries(out.map((r) => [r.id, r.version]))
    expect(byId).toEqual({ a: 'v2', b: 'v1', c: 'v1' })
  })

  it('flattenIocs: record-of-arrays and array forms both flatten with type carried', () => {
    expect(flattenIocs({ ip: [{ value: '1.1.1.1' }], account: ['svc'] })).toEqual([
      { value: '1.1.1.1', type: 'ip' },
      { value: 'svc', type: 'account' },
    ])
    expect(flattenIocs([{ value: 'x', type: 'domain' }, 'raw'])).toEqual([
      { value: 'x', type: 'domain' },
      { value: 'raw' },
    ])
  })

  it('profileLabel + formatReportDate: known label, falls back to raw key', () => {
    expect(profileLabel('executive')).toMatch(/Executive Briefing/)
    expect(profileLabel('weird')).toBe('weird')
    expect(formatReportDate('')).toBe('')
  })

  it('serializeToMarkdown: keeps the XSS payload as an inert literal string', () => {
    const md = serializeToMarkdown(SAVED_REPORT)
    // The serializer emits the raw text — it is a STRING, never executed, and is
    // bound to a readonly <textarea> value downstream (no HTML injection).
    expect(md).toContain('# Forensic Incident Report: NORTHWIND')
    expect(md).toContain(XSS)
    expect(md).toContain('### Finding F-001: Lateral movement')
  })
})

// ── Interaction ──────────────────────────────────────────────────────────
vi.mock('@/api/endpoints', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    getReports: vi.fn(),
    getReport: vi.fn(),
    postReportGenerate: vi.fn(),
    postReportSave: vi.fn(),
  }
})

beforeEach(() => {
  vi.clearAllMocks()
  useStore.setState({
    toasts: [],
    user: { examiner: 'test', role: 'examiner' },
    activeTab: 'reports',
    portalState: { report_eligibility: { eligible: true, approved_findings: 1, total_findings: 6 } },
  })
  endpoints.getReports.mockResolvedValue([SAVED_REPORT])
  endpoints.getReport.mockResolvedValue(SAVED_REPORT)
})

describe('ReportsTab — interaction', () => {
  it('renders the saved-reports list + eligibility banner from loaded data', async () => {
    render(<ReportsTab />)
    await screen.findByText(/Executive Briefing — v1/)
    expect(screen.getByTestId('report-eligibility')).toHaveTextContent(/Eligible/)
  })

  it('selecting a saved report renders it and ESCAPES the XSS payload as text', async () => {
    render(<ReportsTab />)
    const row = await screen.findByText(/Executive Briefing — v1/)
    fireEvent.click(row)
    // Rendered header appears.
    expect(await screen.findByText(/Forensic Incident Report: NORTHWIND/)).toBeInTheDocument()
    // The payload text is present (escaped) but there is NO live injected script
    // node, and the global side-effect never fired.
    expect(document.querySelector('script')).toBeNull()
    expect(window.__pwned__).toBeUndefined()
    // The escaped observation text is a text node containing the literal payload.
    expect(screen.getByText(/window\.__pwned__=1/)).toBeInTheDocument()
  })

  it('generate is challenge-gated: postReportGenerate is NOT called until password confirmed', async () => {
    endpoints.postReportGenerate.mockResolvedValue({ ...SAVED_REPORT, id: 'rpt-draft', status: 'draft' })
    render(<ReportsTab />)
    await screen.findByText(/Executive Briefing — v1/)

    fireEvent.click(screen.getByRole('button', { name: /generate draft/i }))
    expect(endpoints.postReportGenerate).not.toHaveBeenCalled()
    // Confirm disabled until a password is entered.
    expect(screen.getByTestId('report-challenge-confirm')).toBeDisabled()

    fireEvent.change(screen.getByLabelText(/examiner password/i), { target: { value: 'pw' } })
    fireEvent.click(screen.getByTestId('report-challenge-confirm'))
    await waitFor(() =>
      expect(endpoints.postReportGenerate).toHaveBeenCalledWith(
        expect.objectContaining({ profile: 'full', password: 'pw' }),
      ),
    )
  })

  it('blocks generation when eligibility is ineligible', async () => {
    useStore.setState({
      portalState: { report_eligibility: { eligible: false, reason: 'no approved findings' } },
    })
    render(<ReportsTab />)
    await screen.findByText(/Executive Briefing — v1/)
    expect(screen.getByRole('button', { name: /generate draft/i })).toBeDisabled()
    expect(screen.getByTestId('report-eligibility')).toHaveTextContent(/Not eligible/)
  })
})
