import { describe, it, expect, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'

import { useStore } from '@/store/useStore'
import { AccountsTab } from '@/components/accounts/AccountsTab'

beforeEach(() => {
  window.matchMedia =
    window.matchMedia ||
    ((q) => ({ matches: false, media: q, onchange: null, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {}, dispatchEvent: () => false }))
})

function seed(findings) {
  useStore.setState({ activeTab: 'accounts', isLoading: false, findings, findingsAccountFilter: null })
}

const MULTI_HOST = [
  { id: 'F-1', host: 'dc-01', confidence: 'HIGH', status: 'approved', affected_account: 'svc-backup', event_timestamp: '2026-01-02T03:00:00Z' },
  { id: 'F-2', host: 'ws-01', confidence: 'MEDIUM', status: 'draft', affected_account: 'svc-backup' },
  { id: 'F-3', host: 'fs-01', confidence: 'LOW', status: 'draft' }, // no account → Unattributed
]

describe('AccountsTab — render + grouping + navigation', () => {
  it('groups findings by account and shows an Unattributed bucket', () => {
    seed(MULTI_HOST)
    render(<AccountsTab />)
    expect(screen.getByText('svc-backup')).toBeInTheDocument()
    expect(screen.getByText(/unattributed account/i)).toBeInTheDocument()
  })

  it('multi-host: Host List column is shown; row click sets account filter', () => {
    seed(MULTI_HOST)
    render(<AccountsTab />)
    expect(screen.getByText('Host List')).toBeInTheDocument()
    fireEvent.click(screen.getByText('svc-backup'))
    expect(useStore.getState().findingsAccountFilter).toBe('svc-backup')
    expect(useStore.getState().activeTab).toBe('findings')
  })

  it('single-host: collapses Host columns and annotates the title', () => {
    seed([
      { id: 'F-1', host: 'dc-01', confidence: 'HIGH', status: 'approved', affected_account: 'svc-backup' },
      { id: 'F-2', host: 'dc-01', confidence: 'LOW', status: 'draft', affected_account: 'admin' },
    ])
    render(<AccountsTab />)
    expect(screen.getByText(/host: dc-01/i)).toBeInTheDocument()
    expect(screen.queryByText('Host List')).not.toBeInTheDocument()
  })

  it('Unattributed row click sets the empty-string (no-account) filter', () => {
    seed(MULTI_HOST)
    render(<AccountsTab />)
    fireEvent.click(screen.getByText(/unattributed account/i))
    expect(useStore.getState().findingsAccountFilter).toBe('')
  })

  it('shows an empty state when there are no findings', () => {
    seed([])
    render(<AccountsTab />)
    expect(screen.getByText(/no accounts in scope yet/i)).toBeInTheDocument()
  })
})
