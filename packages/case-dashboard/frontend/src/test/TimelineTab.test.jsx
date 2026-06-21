import { describe, it, expect, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'

import { useStore } from '@/store/useStore'
import { TimelineTab } from '@/components/timeline/TimelineTab'

// matchMedia shim (framer-motion useReducedMotion needs it under jsdom).
beforeEach(() => {
  window.matchMedia =
    window.matchMedia ||
    ((q) => ({ matches: false, media: q, onchange: null, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {}, dispatchEvent: () => false }))
  useStore.setState({
    activeTab: 'timeline',
    isLoading: false,
    selectedFindingId: null,
    timeline: [
      { id: 'E-1', timestamp: '2026-01-02T05:00:00Z', event_type: 'auth', host: 'DC-01', description: 'svc-backup authenticated', finding_refs: ['F-001'] },
      { id: 'E-2', timestamp: '2026-01-02T03:00:00Z', event_type: 'network', host: 'WS-FIN', description: 'beacon to 185.99.12.44' },
      { id: 'E-3', timestamp: '2026-01-02T04:00:00Z', event_type: 'auth', host: 'WS-FIN', description: 'interactive logon m.reyes', status: 'approved' },
    ],
  })
})

describe('TimelineTab — render + filters', () => {
  it('renders events chronologically with the result count', () => {
    render(<TimelineTab />)
    expect(screen.getByText('beacon to 185.99.12.44')).toBeInTheDocument()
    expect(screen.getByText('3 events')).toBeInTheDocument()
  })

  it('type chip filters to matching events', () => {
    render(<TimelineTab />)
    // Activate the "network" chip → only the network event remains.
    fireEvent.click(screen.getByRole('button', { name: 'network' }))
    expect(screen.getByText('1 events')).toBeInTheDocument()
    expect(screen.getByText('beacon to 185.99.12.44')).toBeInTheDocument()
    expect(screen.queryByText('svc-backup authenticated')).not.toBeInTheDocument()
  })

  it('search narrows by description', () => {
    render(<TimelineTab />)
    fireEvent.change(screen.getByLabelText(/search timeline events/i), { target: { value: 'logon' } })
    expect(screen.getByText('1 events')).toBeInTheDocument()
    expect(screen.getByText('interactive logon m.reyes')).toBeInTheDocument()
  })

  it('host select filters to one host', () => {
    render(<TimelineTab />)
    fireEvent.change(screen.getByLabelText(/filter by host/i), { target: { value: 'DC-01' } })
    expect(screen.getByText('1 events')).toBeInTheDocument()
  })

  it('finding cross-link navigates to Findings with the finding selected', () => {
    render(<TimelineTab />)
    fireEvent.click(screen.getByRole('button', { name: '[F-001]' }))
    expect(useStore.getState().activeTab).toBe('findings')
    expect(useStore.getState().selectedFindingId).toBe('F-001')
  })

  it('shows an empty state when no events match', () => {
    render(<TimelineTab />)
    fireEvent.change(screen.getByLabelText(/search timeline events/i), { target: { value: 'zzz-no-match' } })
    expect(screen.getByText(/no events match filters/i)).toBeInTheDocument()
  })
})
