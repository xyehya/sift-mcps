import { describe, it, expect, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

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
    activeCase: { case_id: 'CASE-2026-0410', name: 'NORTHWIND', status: 'active' },
    user: { examiner: 'e.varga', role: 'examiner' },
    findings: [{ id: 'F-1', status: 'draft', confidence: 'HIGH', title: 'a', mitre_ids: ['T1059'] }],
    delta: [],
    summary: { findings: { total: 1, by_status: { draft: 1 } } },
    chainStatus: { status: 'ok', manifest_version: 3, write_protected: true },
    portalState: {
      agent: { state: 'awaiting-authorization', metrics: { records_parsed: 1284402, findings_proposed: 47, sources_fused: 3 } },
      gated_actions: [
        { id: 'ga-1', title: 'Acquire volatile memory — WS-FINANCE-03', tool: 'mcp:acquire.memory', icon: 'cpu', risk: 'irreversible' },
      ],
      backends: { up: 7, total: 8, degraded: ['yara'] },
      evidence: { sealed: 12, total: 14 },
      iocs: { total: 23, hosts: 9, accounts: 31 },
      severity: { open: 6, awaiting: 3 },
    },
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

describe('Mission Control overview', () => {
  it('renders the Mission Control hero with the agent state', () => {
    renderOverview()
    expect(screen.getByRole('heading', { name: 'Mission Control' })).toBeInTheDocument()
    expect(screen.getByText('Autonomous Investigator')).toBeInTheDocument()
    expect(screen.getAllByText('Awaiting authorization').length).toBeGreaterThan(0)
  })

  it('renders the Authorization Required queue (agent cannot self-approve)', () => {
    renderOverview()
    expect(screen.getByText('Authorization required')).toBeInTheDocument()
    expect(screen.getByText('Agent cannot self-approve')).toBeInTheDocument()
    expect(screen.getByText('mcp:acquire.memory')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Review & authorize/i })).toBeInTheDocument()
  })

  it('renders the mission KPI tiles (Evidence · High severity · IOCs · MCP backends)', () => {
    renderOverview()
    expect(screen.getByText('Evidence')).toBeInTheDocument()
    expect(screen.getByText('High severity')).toBeInTheDocument()
    expect(screen.getByText('MCP backends')).toBeInTheDocument()
    expect(screen.getByText(/degraded · yara/)).toBeInTheDocument()
  })
})
