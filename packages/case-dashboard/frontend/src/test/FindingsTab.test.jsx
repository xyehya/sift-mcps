import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'

import { useStore } from '../store/useStore'
import { TooltipProvider } from '../components/ui/tooltip'
import { FindingsTab } from '../components/findings/FindingsTab'
import { postDelta } from '../api/endpoints'

vi.mock('../api/endpoints', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    postDelta: vi.fn().mockResolvedValue({}),
    deleteDelta: vi.fn().mockResolvedValue({}),
    getAudit: vi.fn().mockResolvedValue([]),
  }
})

const FINDINGS = [
  {
    id: 'F-1', status: 'draft', confidence: 'HIGH', type: 'finding', content_hash: 'h1',
    title: 'RDP lateral movement', description: 'desc', observation: 'obs', interpretation: 'interp',
    mitre_ids: ['T1021'], iocs: [],
  },
  { id: 'F-2', status: 'approved', confidence: 'LOW', type: 'finding', title: 'bulk file access' },
]

beforeEach(() => {
  vi.clearAllMocks()
  window.matchMedia =
    window.matchMedia ||
    ((query) => ({ matches: false, media: query, onchange: null, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {}, dispatchEvent: () => false }))
  useStore.setState({
    findings: FINDINGS,
    delta: [],
    selectedFindingId: null,
    timeline: [],
    isLoading: false,
    findingsFilter: 'pending',
    findingsHostFilter: null,
    findingsAccountFilter: null,
    user: { examiner: 'tester', role: 'examiner' },
  })
})

function renderTab() {
  return render(
    <TooltipProvider>
      <FindingsTab />
    </TooltipProvider>,
  )
}

describe('FindingsTab', () => {
  it('lists pending findings and hides non-matching statuses', () => {
    renderTab()
    expect(screen.getByText('RDP lateral movement')).toBeInTheDocument()
    expect(screen.queryByText('bulk file access')).not.toBeInTheDocument() // approved, filtered out of pending
  })

  it('examiner can stage an approval (POST /api/delta with whole document)', async () => {
    useStore.setState({ selectedFindingId: 'F-1' })
    renderTab()
    fireEvent.click(screen.getByRole('button', { name: /^Approve$/ }))
    await waitFor(() => expect(postDelta).toHaveBeenCalledTimes(1))
    const sent = postDelta.mock.calls[0][0]
    expect(sent.items).toEqual([expect.objectContaining({ id: 'F-1', action: 'approve' })])
    await waitFor(() => expect(useStore.getState().delta).toHaveLength(1))
  })

  it('readonly users get a read-only view with review actions hidden', () => {
    useStore.setState({ user: { role: 'readonly' }, selectedFindingId: 'F-1' })
    renderTab()
    expect(screen.getByText(/Read-only — sign in as an examiner/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Approve$/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Reject$/ })).not.toBeInTheDocument()
  })

  it('shows the empty-detail prompt until a finding is selected', () => {
    renderTab()
    expect(screen.getByText('Select a finding to review')).toBeInTheDocument()
  })
})
