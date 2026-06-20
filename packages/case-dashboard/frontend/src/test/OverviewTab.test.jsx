import { describe, it, expect, beforeEach } from 'vitest'
import { render, screen, fireEvent, within } from '@testing-library/react'

import { useStore } from '../store/useStore'
import { TooltipProvider } from '../components/ui/tooltip'
import { OverviewTab } from '../components/overview/OverviewTab'

// matchMedia shim (jsdom lacks it) — framer-motion's useReducedMotion needs it.
beforeEach(() => {
  window.matchMedia =
    window.matchMedia ||
    ((query) => ({ matches: false, media: query, onchange: null, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {}, dispatchEvent: () => false }))
  window.location.hash = ''
  useStore.setState({
    activeTab: 'overview',
    activeCase: { case_id: 'CASE-X', name: 'Demo', incident_type: 'malware', severity: 'high' },
    findings: [
      { id: 'F-1', status: 'draft', confidence: 'HIGH', title: 'a', mitre_ids: ['T1059'], modified_at: new Date().toISOString() },
      { id: 'F-2', status: 'approved', confidence: 'LOW', title: 'b', mitre_ids: ['T1021'] },
    ],
    delta: [{ id: 'F-1', action: 'approve' }],
    summary: { findings: { total: 2, by_status: { approved: 1, draft: 1 } } },
    chainStatus: { status: 'ok', manifest_version: 2, write_protected: true },
    isLoading: false,
    findingsFilter: 'pending',
  })
})

function renderOverview() {
  return render(
    <TooltipProvider>
      <OverviewTab />
    </TooltipProvider>,
  )
}

describe('OverviewTab', () => {
  it('renders the four KPI cards with derived values', () => {
    renderOverview()
    const findingsCard = screen.getByRole('button', { name: 'View all findings' })
    expect(within(findingsCard).getByText('2')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'View approved findings' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Review pending findings' })).toBeInTheDocument()
  })

  it('KPI click-through deep-links to the filtered Findings tab', () => {
    renderOverview()
    fireEvent.click(screen.getByRole('button', { name: 'View approved findings' }))
    expect(useStore.getState().findingsFilter).toBe('approved')
    expect(useStore.getState().activeTab).toBe('findings')
    expect(window.location.hash).toBe('#/findings')
  })

  it('renders the severity distribution (High/Med/Low) and MITRE techniques', () => {
    // P0 model-shift: Speculative tier dropped — only High/Medium/Low shown.
    renderOverview()
    expect(screen.getByText('High')).toBeInTheDocument()
    expect(screen.queryByText('Speculative')).not.toBeInTheDocument()
    expect(screen.getByText('T1059')).toBeInTheDocument()
  })

  it('shows the no-case empty state when there is no active case', () => {
    useStore.setState({ activeCase: null, isLoading: false })
    renderOverview()
    expect(screen.getByText('No active case')).toBeInTheDocument()
  })
})
