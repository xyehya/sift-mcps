import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

import { ConfChip, MitreChips } from '../components/findings/FindingDetailChips'
import { Row } from '../components/findings/FindingRow'
import { FindingDetail } from '../components/findings/FindingDetail'
import { AuditTrailPanel } from '../components/findings/AuditTrailPanel'
import { confidenceLabel } from '../components/findings/findings-utils'
import * as endpoints from '../api/endpoints'

// P35-10/11/12 — Findings detail fixes found during LIVE ROCBA validation.

// ── P35-11: categorical confidence text, NO fabricated "%" ────────────────
describe('P35-11 confidence shows categorical text, never a fabricated %', () => {
  it('confidenceLabel maps the category to its display label (pure)', () => {
    expect(confidenceLabel('HIGH')).toBe('High')
    expect(confidenceLabel('medium')).toBe('Medium')
    expect(confidenceLabel('LOW')).toBe('Low')
    expect(confidenceLabel(null)).toBeNull()
    expect(confidenceLabel('???')).toBeNull()
  })

  it('ConfChip renders "Confidence: HIGH" text and no percentage', () => {
    const { container } = render(<ConfChip confidence="HIGH" />)
    expect(screen.getByText(/Confidence:\s*High/i)).toBeInTheDocument()
    expect(container.textContent).not.toMatch(/%/)
    expect(container.textContent).not.toMatch(/92/)
  })

  it('ConfChip renders nothing for an unknown confidence', () => {
    const { container } = render(<ConfChip confidence={undefined} />)
    expect(container.firstChild).toBeNull()
  })

  it('FindingRow subtitle shows the categorical label, not "92%"', () => {
    const finding = { id: 'F-001', host: 'DESKTOP- X', confidence: 'HIGH', confidence_score: null, title: 'brute force', status: 'draft' }
    const { container } = render(<Row finding={finding} onClick={() => {}} />)
    expect(container.textContent).toMatch(/DESKTOP-\s*X · High/)
    expect(container.textContent).not.toMatch(/%/)
    expect(container.textContent).not.toMatch(/92/)
  })
})

// ── P35-12: full MITRE technique set in the mounted detail ────────────────
describe('P35-12 mounted detail lists EVERY MITRE technique', () => {
  it('MitreChips renders all ids and nothing when empty', () => {
    const { container, rerender } = render(<MitreChips ids={['T1110.001', 'T1133', 'T1021.001']} />)
    // Each id sits in a chip whose text reads "ATT&CK <id>" — match by substring.
    expect(screen.getByText(/T1110\.001/)).toBeInTheDocument()
    expect(screen.getByText(/T1133/)).toBeInTheDocument()
    expect(screen.getByText(/T1021\.001/)).toBeInTheDocument()

    rerender(<MitreChips ids={[]} />)
    expect(container.firstChild).toBeNull()
  })

  it('FindingDetail body shows all three F-001 techniques (not just the first)', () => {
    const finding = {
      id: 'F-001', status: 'draft', type: 'finding', confidence: 'HIGH',
      title: 'RDP brute force', observation: 'obs', interpretation: 'interp',
      confidence_justification: 'just', mitre_ids: ['T1110.001', 'T1133', 'T1021.001'],
    }
    render(
      <FindingDetail
        finding={finding} stagedItem={null} canReview
        addToast={() => {}} onApprove={vi.fn()} onStage={vi.fn()}
        onReject={vi.fn()} onUnstage={vi.fn()} onEdit={vi.fn()}
      />,
    )
    // Second + third techniques live ONLY in the new body section.
    expect(screen.getByText(/T1133/)).toBeInTheDocument()
    expect(screen.getByText(/T1021\.001/)).toBeInTheDocument()
    // First id appears in both the header glance chip and the body list.
    expect(screen.getAllByText(/T1110\.001/).length).toBeGreaterThanOrEqual(2)
  })
})

// ── P35-10: audit entry with no provenance shows an empty-state line ──────
describe('P35-10 unresolved audit id shows an empty-state, not a blank box', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('renders the empty-state line when getAudit resolves nothing', async () => {
    vi.spyOn(endpoints, 'getAudit').mockResolvedValue([])
    const finding = { id: 'F-001', audit_ids: ['aud-unknown-1'] }
    render(<AuditTrailPanel finding={finding} />)
    // First entry is open by default; after the empty load it must explain
    // the absence rather than render an empty bordered box.
    expect(await screen.findByText(/No tool-call provenance recorded for this audit id\./i)).toBeInTheDocument()
  })

  it('still renders provenance when the entry carries tool-call data', async () => {
    vi.spyOn(endpoints, 'getAudit').mockResolvedValue([
      { audit_id: 'aud-1', tool: 'run_command', params: { command: 'whoami' }, _backend: 'exec' },
    ])
    const finding = { id: 'F-002', audit_ids: ['aud-1'] }
    render(<AuditTrailPanel finding={finding} />)
    expect(await screen.findByText('whoami')).toBeInTheDocument()
    expect(screen.queryByText(/No tool-call provenance recorded/i)).not.toBeInTheDocument()
  })
})
