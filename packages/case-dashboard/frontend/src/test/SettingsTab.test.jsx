import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'

import { useStore } from '@/store/useStore'
import * as endpoints from '@/api/endpoints'
import { ThemeProvider } from '@/lib/theme'
import {
  formatTtl,
  principalStatus,
  tokenTypeLabel,
  isRevoked,
  dateMs,
} from '@/components/settings/settings-utils'
import { SettingsTab } from '@/components/settings/SettingsTab'

// ─────────────────────────────────────────────────────────────────────────
// SettingsTab.test.jsx — pure logic (TTL/status derivation) PLUS interaction
// coverage of the credential console (issue principal · revoke with confirm),
// the theme toggle (uses the existing lib/theme provider), and the RBAC gate
// (analyst hides the issue form + revoke). Endpoints are mocked; the store is
// seeded so the tab renders populated.
// ─────────────────────────────────────────────────────────────────────────

const NOW = Date.parse('2026-06-21T00:00:00Z')
const PRINCIPALS = [
  { principal_type: 'agent', principal_id: 'agt-1', display_name: 'Hermes', token_type: 'supabase_jwt', status: 'active', tool_scopes: ['mcp:*'], last_issued_expires_at: '2026-06-22T12:00:00Z' },
  { principal_type: 'agent', principal_id: 'agt-2', display_name: 'Old', token_type: 'supabase_jwt', status: 'revoked', tool_scopes: [], last_issued_expires_at: '2026-06-20T00:00:00Z' },
]

const renderWithTheme = (ui) => render(<ThemeProvider>{ui}</ThemeProvider>)

describe('settings-utils — pure logic', () => {
  it('dateMs: accepts epoch-seconds number and ISO string', () => {
    expect(dateMs(1000)).toBe(1000000)
    expect(dateMs('2026-06-21T00:00:00Z')).toBe(NOW)
    expect(dateMs(null)).toBeNull()
    expect(dateMs('nonsense')).toBeNull()
  })

  it('formatTtl: days/hours/minutes/expired/not-recorded', () => {
    expect(formatTtl('2026-06-22T12:00:00Z', NOW)).toBe('1d 12h')
    expect(formatTtl('2026-06-21T05:30:00Z', NOW)).toBe('5h 30m')
    expect(formatTtl('2026-06-20T00:00:00Z', NOW)).toBe('Expired')
    expect(formatTtl(null, NOW)).toBe('Not recorded')
  })

  it('principalStatus: revoked stays revoked; expired derived from TTL', () => {
    expect(principalStatus({ status: 'revoked' }, NOW)).toBe('revoked')
    expect(principalStatus({ status: 'active', last_issued_expires_at: '2026-06-20T00:00:00Z' }, NOW)).toBe('expired')
    expect(principalStatus({ status: 'active', last_issued_expires_at: '2026-06-22T00:00:00Z' }, NOW)).toBe('active')
  })

  it('tokenTypeLabel + isRevoked', () => {
    expect(tokenTypeLabel({ token_type: 'supabase_jwt' })).toBe('Supabase JWT')
    expect(isRevoked({ status: 'revoked' })).toBe(true)
    expect(isRevoked({ status: 'active' })).toBe(false)
  })
})

vi.mock('@/api/endpoints', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    getPrincipals: vi.fn(),
    postPrincipal: vi.fn(),
    deletePrincipal: vi.fn(),
  }
})

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
  useStore.setState({
    toasts: [],
    user: { examiner: 'E. Varga', role: 'examiner' },
    activeTab: 'settings',
  })
  endpoints.getPrincipals.mockResolvedValue({ principals: PRINCIPALS })
})

describe('SettingsTab — interaction', () => {
  it('renders the principals table populated', async () => {
    renderWithTheme(<SettingsTab />)
    await screen.findByText('Hermes')
    expect(screen.getByText('agt-1')).toBeInTheDocument()
    expect(screen.getByText('E. Varga')).toBeInTheDocument()
  })

  it('issue principal calls postPrincipal with form fields + password', async () => {
    endpoints.postPrincipal.mockResolvedValue({
      principal_type: 'agent', principal_id: 'new', access_token: 'A', refresh_token: 'R', token_fingerprint: 'fp', expires_at: '2026-06-23T00:00:00Z',
    })
    renderWithTheme(<SettingsTab />)
    await screen.findByText('Hermes')

    fireEvent.change(screen.getByLabelText(/display name/i), { target: { value: 'New agent' } })
    fireEvent.change(screen.getByLabelText(/operator password/i), { target: { value: 'pw' } })
    fireEvent.click(screen.getByRole('button', { name: /issue session/i }))

    await waitFor(() =>
      expect(endpoints.postPrincipal).toHaveBeenCalledWith(
        expect.objectContaining({ kind: 'agent', display_name: 'New agent', password: 'pw' }),
      ),
    )
    // Issued-once banner shows the token material (title is uppercased via CSS;
    // DOM text is Title-case).
    expect(await screen.findByText(/New JWT Session Issued/i)).toBeInTheDocument()
  })

  it('revoke confirms then calls deletePrincipal', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    endpoints.deletePrincipal.mockResolvedValue({})
    renderWithTheme(<SettingsTab />)
    await screen.findByText('Hermes')

    // Only the active principal (agt-1) has an enabled Revoke button.
    fireEvent.click(screen.getByRole('button', { name: /^revoke$/i }))
    await waitFor(() => expect(endpoints.deletePrincipal).toHaveBeenCalledWith('agent', 'agt-1'))
    window.confirm.mockRestore()
  })

  it('theme toggle uses the lib/theme provider (sets dark)', async () => {
    renderWithTheme(<SettingsTab />)
    await screen.findByText('Hermes')
    fireEvent.click(screen.getByRole('radio', { name: /dark/i }))
    expect(document.documentElement.classList.contains('dark')).toBe(true)
    expect(localStorage.getItem('sift-theme')).toBe('dark')
  })

  it('RBAC: analyst hides the issue form + revoke', async () => {
    useStore.setState({ user: { examiner: 'a', role: 'analyst' } })
    renderWithTheme(<SettingsTab />)
    await screen.findByText('Hermes')
    expect(screen.queryByRole('button', { name: /issue session/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /^revoke$/i })).toBeNull()
  })
})
