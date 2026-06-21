import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'

import { useStore } from '@/store/useStore'
import { iocCategories, filterIocs, iocHosts, iocStatusTone } from '@/components/iocs/iocs-utils'
import { IocsTab } from '@/components/iocs/IocsTab'

// ── Pure logic ───────────────────────────────────────────────────────────
const IOCS = [
  { id: 'ioc-1', type: 'ip', value: '185.99.12.44', category: 'network', confidence: 'LOW', status: 'DRAFT', source_findings: ['F-004'], sightings: [{ host: 'ws-fin' }], mitre_techniques: ['T1071.001'], tags: ['c2'] },
  { id: 'ioc-2', type: 'account', value: 'svc-backup', category: 'identity', confidence: 'HIGH', status: 'APPROVED', source_findings: ['F-001'], sightings: [{ host: 'dc-01' }, { host: 'ws-fin' }], mitre_techniques: ['T1078.002'], tags: [] },
  { id: 'ioc-3', type: 'hash', value: 'deadbeef', category: 'host', confidence: 'MEDIUM', status: 'REJECTED', source_findings: [], sightings: [] },
]

describe('iocs-utils — pure logic', () => {
  it('iocCategories returns distinct sorted non-empty categories', () => {
    expect(iocCategories(IOCS)).toEqual(['host', 'identity', 'network'])
  })

  it('filterIocs filters by category, status, and value/id/type search', () => {
    expect(filterIocs(IOCS, { category: 'network' }).map((i) => i.id)).toEqual(['ioc-1'])
    expect(filterIocs(IOCS, { status: 'APPROVED' }).map((i) => i.id)).toEqual(['ioc-2'])
    expect(filterIocs(IOCS, { search: 'SVC' }).map((i) => i.id)).toEqual(['ioc-2'])
    expect(filterIocs(IOCS, { search: 'hash' }).map((i) => i.id)).toEqual(['ioc-3'])
  })

  it('iocHosts dedupes + uppercases sighting hosts', () => {
    expect(iocHosts(IOCS[1])).toEqual(['DC-01', 'WS-FIN'])
    expect(iocHosts(IOCS[2])).toEqual([])
  })

  it('iocStatusTone maps status → badge tone', () => {
    expect(iocStatusTone('APPROVED')).toBe('approved')
    expect(iocStatusTone('REJECTED')).toBe('rejected')
    expect(iocStatusTone('DRAFT')).toBe('pending')
    expect(iocStatusTone('???')).toBe('muted')
  })
})

// ── Render + interaction ───────────────────────────────────────────────────
beforeEach(() => {
  window.matchMedia =
    window.matchMedia ||
    ((q) => ({ matches: false, media: q, onchange: null, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {}, dispatchEvent: () => false }))
  useStore.setState({
    activeTab: 'iocs',
    isLoading: false,
    selectedFindingId: null,
    iocs: IOCS,
    // Multiple hosts in findings → Hosts column shown (isSingleHost false).
    findings: [{ id: 'F-001', host: 'DC-01' }, { id: 'F-004', host: 'WS-FIN' }],
  })
})

describe('IocsTab — render + filters + expand', () => {
  it('renders the IOC values and the of-total count', () => {
    render(<IocsTab />)
    expect(screen.getByText('185.99.12.44')).toBeInTheDocument()
    expect(screen.getByText('svc-backup')).toBeInTheDocument()
    expect(screen.getByText('(3 of 3)')).toBeInTheDocument()
  })

  it('status filter narrows the table', () => {
    render(<IocsTab />)
    fireEvent.change(screen.getByLabelText(/filter by status/i), { target: { value: 'APPROVED' } })
    expect(screen.getByText('(1 of 3)')).toBeInTheDocument()
    expect(screen.getByText('svc-backup')).toBeInTheDocument()
    expect(screen.queryByText('185.99.12.44')).not.toBeInTheDocument()
  })

  it('search matches value/id/type', () => {
    render(<IocsTab />)
    fireEvent.change(screen.getByLabelText(/search indicators/i), { target: { value: 'deadbeef' } })
    expect(screen.getByText('(1 of 3)')).toBeInTheDocument()
  })

  it('expanding a row reveals MITRE techniques + tags', () => {
    render(<IocsTab />)
    fireEvent.click(screen.getAllByRole('button', { name: /expand ioc detail/i })[0])
    expect(screen.getByText('T1071.001')).toBeInTheDocument()
    expect(screen.getByText('c2')).toBeInTheDocument()
  })

  it('source-finding link navigates to Findings', () => {
    render(<IocsTab />)
    fireEvent.click(screen.getByRole('button', { name: 'F-001' }))
    expect(useStore.getState().activeTab).toBe('findings')
    expect(useStore.getState().selectedFindingId).toBe('F-001')
  })

  it('copy button writes the value to the clipboard', () => {
    const writeText = vi.fn().mockResolvedValue()
    Object.assign(navigator, { clipboard: { writeText } })
    render(<IocsTab />)
    fireEvent.click(screen.getAllByRole('button', { name: /copy ioc value/i })[0])
    expect(writeText).toHaveBeenCalledWith('185.99.12.44')
  })

  it('shows an empty state when no IOC matches', () => {
    render(<IocsTab />)
    fireEvent.change(screen.getByLabelText(/search indicators/i), { target: { value: 'zzz' } })
    expect(screen.getByText(/no iocs match the current filters/i)).toBeInTheDocument()
  })
})
