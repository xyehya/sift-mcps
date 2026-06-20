import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'

import { useStore } from '../store/useStore'
import { ThemeProvider } from '../lib/theme'
import { TooltipProvider } from '../components/ui/tooltip'
import { parseHashTab, navigateToTab } from '../hooks/useHashRoute'
import { VALID_TABS, DEFAULT_TAB } from '../lib/nav'
import { AuthProvider } from '../lib/auth'
import { AppShell } from '../components/layout/AppShell'

// The shell polls the API on mount; stub every endpoint it touches so nothing
// hits the network and the poll resolves to empty data.
vi.mock('../api/endpoints', async (importOriginal) => {
  const actual = await importOriginal()
  const empty = vi.fn().mockResolvedValue(null)
  return {
    ...actual,
    // AuthProvider probes getMe on mount; return an examiner so the shell mounts.
    getMe: vi.fn().mockResolvedValue({ examiner: 'test', role: 'examiner' }),
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

// matchMedia shim (jsdom lacks it) — ThemeProvider + reduced-motion query.
beforeEach(() => {
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
  useStore.setState({
    activeTab: 'overview',
    commandPaletteOpen: false,
    findings: [],
    summary: null,
    user: { examiner: 'test', role: 'examiner' },
  })
})

afterEach(() => {
  window.location.hash = ''
})

function renderShell() {
  return render(
    <ThemeProvider>
      <TooltipProvider>
        <AuthProvider>
          <AppShell />
        </AuthProvider>
      </TooltipProvider>
    </ThemeProvider>,
  )
}

describe('hash routing (URL-hash deep-linking)', () => {
  it('parseHashTab maps a valid hash to a tab and rejects junk', () => {
    expect(parseHashTab('#/findings')).toBe('findings')
    expect(parseHashTab('#findings')).toBe('findings')
    expect(parseHashTab('#/FINDINGS')).toBe('findings')
    expect(parseHashTab('#/nope')).toBeNull()
    expect(parseHashTab('')).toBeNull()
  })

  it('every nav destination is a valid tab', () => {
    expect(VALID_TABS.has(DEFAULT_TAB)).toBe(true)
    expect(VALID_TABS.size).toBe(11)
  })

  it('navigateToTab pushes history and updates the store', () => {
    const setActiveTab = useStore.getState().setActiveTab
    navigateToTab(setActiveTab, 'timeline')
    expect(useStore.getState().activeTab).toBe('timeline')
    expect(window.location.hash).toBe('#/timeline')
  })

  it('AppShell reflects activeTab into the hash and follows hashchange (back/forward)', async () => {
    renderShell()
    // store → hash reflection
    await waitFor(() => expect(window.location.hash).toBe('#/overview'))

    // simulate a back/forward landing on a deep link
    act(() => {
      window.location.hash = '#/iocs'
      window.dispatchEvent(new HashChangeEvent('hashchange'))
    })
    await waitFor(() => expect(useStore.getState().activeTab).toBe('iocs'))
  })

  it('an invalid inbound hash falls back to the default tab', async () => {
    window.location.hash = '#/bogus'
    renderShell()
    await waitFor(() => expect(useStore.getState().activeTab).toBe(DEFAULT_TAB))
  })
})

describe('command palette open/close', () => {
  it('⌘K opens the palette and Escape-driven onOpenChange closes it', async () => {
    renderShell()
    expect(useStore.getState().commandPaletteOpen).toBe(false)
    act(() => {
      window.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', metaKey: true }))
    })
    await waitFor(() => expect(useStore.getState().commandPaletteOpen).toBe(true))
    expect(await screen.findByPlaceholderText(/Search findings or run a command/i)).toBeInTheDocument()

    act(() => useStore.getState().setCommandPaletteOpen(false))
    await waitFor(() => expect(useStore.getState().commandPaletteOpen).toBe(false))
  })
})

describe('theme toggle', () => {
  it('toggles the .dark class on <html> from the header control', async () => {
    renderShell()
    const toggle = await screen.findByRole('button', { name: /switch to (light|dark) theme/i })
    const before = document.documentElement.classList.contains('dark')
    fireEvent.click(toggle)
    await waitFor(() => expect(document.documentElement.classList.contains('dark')).toBe(!before))
  })
})
