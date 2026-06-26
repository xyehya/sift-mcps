import { describe, it, expect, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'

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
    agentActivity: [
      {
        id: 'evt-activity',
        ts: '2026-06-08T00:01:00+00:00',
        kind: 'discovery',
        text: 'Recorded finding - External RDP (HIGH)',
      },
    ],
    portalState: {
      agent: { state: 'working', metrics: { records_parsed: 412309, findings_proposed: 2, sources_fused: 1 } },
      evidence: { sealed: 12, total: 14 },
      backends: { up: 7, total: 8, degraded: [] },
      iocs: { total: 5, hosts: 2, accounts: 3 },
    },
  })
})

function renderOverview() {
  return render(
    <TooltipProvider>
      <OverviewTab />
    </TooltipProvider>,
  )
}

describe('OverviewTab (handoff layout rebuild)', () => {
  it('renders the Mission Control heading', () => {
    renderOverview()
    expect(screen.getByRole('heading', { name: 'Mission Control' })).toBeInTheDocument()
  })

  it('renders the session elapsed readout in the header', () => {
    renderOverview()
    // The live clock reads "SESSION hh:mm:ss ELAPSED" in mono text
    expect(screen.getByText(/elapsed/i)).toBeInTheDocument()
  })

  it('renders the Autonomous Investigator hero', () => {
    renderOverview()
    expect(screen.getAllByText('Autonomous Investigator').length).toBeGreaterThan(0)
  })

  it('renders the Case brief card', () => {
    renderOverview()
    expect(screen.getByText('Case brief')).toBeInTheDocument()
  })

  it('renders the Blocked actions read-only pane with no approve/deny buttons', () => {
    renderOverview()
    expect(screen.getByText('Blocked actions')).toBeInTheDocument()
    expect(screen.getByText('Policy guards · Read-only')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Review & authorize/i })).not.toBeInTheDocument()
  })

  it('renders the MissionStats KPI tiles (Evidence / High confidence / IOCs / MCP backends)', () => {
    renderOverview()
    expect(screen.getByText('Evidence')).toBeInTheDocument()
    expect(screen.getByText('High confidence')).toBeInTheDocument()
    expect(screen.getByText('MCP backends')).toBeInTheDocument()
  })

  it('renders the confidence distribution rows (High/Med/Low)', () => {
    renderOverview()
    // SeverityDistribution renders High / Medium / Low rows
    expect(screen.getByText('High')).toBeInTheDocument()
    expect(screen.queryByText('Speculative')).not.toBeInTheDocument()
  })

  it('does NOT render MitreMatrix or EvidenceChainSummary on the Overview screen', () => {
    renderOverview()
    // Neither MITRE chips (T1059) nor Evidence chain summary appear on Overview
    expect(screen.queryByText('T1059')).not.toBeInTheDocument()
    expect(screen.queryByText(/evidence chain/i)).not.toBeInTheDocument()
  })

  it('renders the Recent findings panel', () => {
    renderOverview()
    expect(screen.getByText('Recent findings')).toBeInTheDocument()
    expect(screen.getByText('Review all →')).toBeInTheDocument()
  })

  it('renders the Agent activity feed panel', () => {
    renderOverview()
    expect(screen.getByText('Agent activity')).toBeInTheDocument()
    expect(screen.getByText('Recorded finding - External RDP (HIGH)')).toBeInTheDocument()
    expect(screen.queryByText(/185\.66\.0\.12/)).not.toBeInTheDocument()
    expect(screen.queryByText(/records parsed/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/sources fused/i)).not.toBeInTheDocument()
  })

  it('shows the no-case empty state when there is no active case', () => {
    useStore.setState({ activeCase: null, isLoading: false })
    renderOverview()
    expect(screen.getByText('No active case')).toBeInTheDocument()
  })

  it('Recent findings "Review all →" navigates to Findings tab', () => {
    renderOverview()
    fireEvent.click(screen.getByText('Review all →'))
    expect(useStore.getState().activeTab).toBe('findings')
    expect(window.location.hash).toBe('#/findings')
  })
})
