import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'

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
    postSupabaseLogin: vi.fn(),
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

  it('mirrors the PRINCIPAL (not the login envelope) into the store after a fresh login', async () => {
    // Regression: /api/auth/login returns {ok, principal, must_reset} while
    // getMe() returns the bare principal. RBAC reads user.role, so storing the
    // envelope leaves role undefined → a freshly-logged-in examiner is stuck in
    // VIEW ONLY until a page reload re-probes getMe.
    endpoints.getMe.mockResolvedValue(null) // start unauthed → login screen
    endpoints.postSupabaseLogin.mockResolvedValue({
      ok: true,
      principal: { examiner: 'alice', role: 'examiner' },
      must_reset: false,
    })
    renderApp()
    fireEvent.change(await screen.findByLabelText('Email'), { target: { value: 'a@b.c' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'pw' } })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))
    // Must be the principal's role, not undefined (envelope).
    await waitFor(() => expect(useStore.getState().user?.role).toBe('examiner'))
  })
})
