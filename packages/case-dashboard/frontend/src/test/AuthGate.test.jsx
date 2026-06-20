import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'

import { useStore } from '../store/useStore'
import { ThemeProvider } from '../lib/theme'
import { TooltipProvider } from '../components/ui/tooltip'
import * as endpoints from '../api/endpoints'
import App from '../App'

// Stub the auth probe + the shell's poll. getMe drives the gate; the poll
// endpoints just need to resolve so the authed branch doesn't throw.
vi.mock('../api/endpoints', async (importOriginal) => {
  const actual = await importOriginal()
  const empty = vi.fn().mockResolvedValue(null)
  return {
    ...actual,
    getMe: vi.fn(),
    getCase: empty,
    getCases: vi.fn().mockResolvedValue({ cases: [] }),
    getSummary: empty,
    getFindings: vi.fn().mockResolvedValue([]),
    getDelta: vi.fn().mockResolvedValue({ items: [] }),
    getTimeline: vi.fn().mockResolvedValue([]),
    getChainStatus: empty,
    getIocs: vi.fn().mockResolvedValue([]),
    getTodos: vi.fn().mockResolvedValue([]),
    getReports: vi.fn().mockResolvedValue([]),
    getPortalState: empty,
  }
})

beforeEach(() => {
  vi.clearAllMocks()
  window.matchMedia = window.matchMedia || ((query) => ({
    matches: false,
    media: query,
    onchange: null,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => false,
  }))
  window.location.hash = ''
  useStore.setState({ activeTab: 'overview', user: null, findings: [], summary: null })
})

function renderApp() {
  return render(
    <ThemeProvider>
      <TooltipProvider>
        <App />
      </TooltipProvider>
    </ThemeProvider>,
  )
}

describe('auth gating', () => {
  it('renders the login screen when getMe returns no session (401 → null)', async () => {
    endpoints.getMe.mockResolvedValue(null)
    renderApp()
    expect(await screen.findByText('Examiner Portal')).toBeInTheDocument()
    expect(screen.getByLabelText('Email')).toBeInTheDocument()
  })

  it('renders the authenticated shell when getMe returns a principal', async () => {
    endpoints.getMe.mockResolvedValue({ examiner: 'alice', role: 'examiner' })
    renderApp()
    // SideNav brand + grouped destinations only exist in the authed shell.
    expect(await screen.findByText('Protocol SIFT Gateway')).toBeInTheDocument()
    expect(screen.getByRole('navigation', { name: /primary/i })).toBeInTheDocument()
    // The principal is mirrored into the store for RBAC consumers.
    await waitFor(() => expect(useStore.getState().user?.role).toBe('examiner'))
  })
})
