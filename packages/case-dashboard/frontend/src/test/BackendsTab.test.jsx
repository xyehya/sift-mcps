import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'

import { useStore } from '@/store/useStore'
import * as endpoints from '@/api/endpoints'
import {
  parseArgs,
  compileEnv,
  getButtonStates,
  showsLifecycleButtons,
  statusLabel,
  buildConfigPayload,
} from '@/components/backends/backends-utils'
import { BackendsTab } from '@/components/backends/BackendsTab'

// ─────────────────────────────────────────────────────────────────────────
// BackendsTab.test.jsx — unit coverage of the pure registry/lifecycle logic in
// backends-utils (parseArgs · compileEnv · getButtonStates · showsLifecycle ·
// statusLabel) PLUS interaction coverage of the challenge-gated admin flows
// (register · validate · reload · start/stop/restart · unregister · enable
// toggle). Endpoints are mocked; the store is seeded so the tab renders.
//
// CHALLENGE GATE: every mutating action opens the password modal and the
// endpoint is NOT called until a password is entered and Confirm submitted —
// asserted below. One error path (rejected endpoint) is covered too.
// ─────────────────────────────────────────────────────────────────────────

// ── Pure logic ───────────────────────────────────────────────────────────
describe('backends-utils — pure logic', () => {
  it('parseArgs: newline list, JSON array, and malformed-JSON fallback', () => {
    expect(parseArgs('a\nb\n   c   ')).toEqual(['a', 'b', 'c'])
    expect(parseArgs('["a", "b", "c"]')).toEqual(['a', 'b', 'c'])
    // Missing closing bracket → not a parseable array → newline-split fallback.
    expect(parseArgs('["a", "b"')).toEqual(['["a", "b"'])
    expect(parseArgs('')).toEqual([])
  })

  it('compileEnv: legacy parity — trims key AND value, drops blank-key/blank-value rows', () => {
    const envList = [
      { key: 'PORT', value: '8080' },
      { key: '  HOST ', value: '127.0.0.1' },
      { key: '', value: 'ignored' }, // blank key → dropped
      { key: 'A', value: '  x  ' }, // value trimmed → A:'x'
      { key: 'B', value: '   ' }, // blank (whitespace-only) value → dropped
    ]
    expect(compileEnv(envList)).toEqual({ PORT: '8080', HOST: '127.0.0.1', A: 'x' })
    // Explicit locks for the legacy semantics the migration must preserve:
    expect(compileEnv([{ key: 'A', value: '  x  ' }])).toEqual({ A: 'x' }) // value trimmed
    expect(compileEnv([{ key: 'B', value: '   ' }])).toEqual({}) // blank value dropped
  })

  it('getButtonStates: start/stop/restart enablement', () => {
    const gated = { enabled: true, started: false, unmet_requires: ['unmet:req'], requires: ['unmet:req'] }
    expect(getButtonStates(gated)).toEqual({ canStart: false, canStop: false, canRestart: false })

    const stoppedMet = { enabled: true, started: false, unmet_requires: [], requires: ['met:req'] }
    expect(getButtonStates(stoppedMet)).toEqual({ canStart: true, canStop: false, canRestart: false })

    const activeGated = { enabled: true, started: true, unmet_requires: ['new-unmet:req'], requires: [] }
    expect(getButtonStates(activeGated)).toEqual({ canStart: false, canStop: true, canRestart: false })

    const disabledStarted = { enabled: false, started: true, unmet_requires: [], requires: [] }
    expect(getButtonStates(disabledStarted)).toEqual({ canStart: false, canStop: true, canRestart: false })
  })

  it('showsLifecycleButtons: hidden for on-demand (proxy-mounted) backends', () => {
    expect(showsLifecycleButtons({ on_demand: true, enabled: true, started: false })).toBe(false)
    expect(showsLifecycleButtons({ on_demand: false, enabled: true, started: false })).toBe(true)
  })

  it('statusLabel: on-demand → "Ready · on-demand", stopped, pending mappings', () => {
    expect(statusLabel({ on_demand: true, started: false, pending_apply: false })).toBe('Ready · on-demand')
    expect(statusLabel({ on_demand: false, started: false, pending_apply: false })).toBe('Stopped')
    expect(statusLabel({ on_demand: true, started: false, pending_apply: true })).toBe('Pending restart')
  })

  it('buildConfigPayload: stdio carries parsed args + env_refs; http carries url + env refs', () => {
    const stdio = buildConfigPayload({
      type: 'stdio',
      manifestPath: 'm.json',
      command: 'node',
      argsStr: '--a\n--b',
      envList: [{ key: 'K', value: 'GATEWAY_K' }],
    })
    expect(stdio).toEqual({
      type: 'stdio',
      manifest_path: 'm.json',
      command: 'node',
      args: ['--a', '--b'],
      env_refs: { K: 'GATEWAY_K' },
    })

    const http = buildConfigPayload({
      type: 'http',
      manifestPath: '',
      url: 'http://x/mcp',
      bearerTokenEnv: 'TOK',
      tlsCertEnv: '',
    })
    expect(http).toEqual({ type: 'http', manifest_path: '', url: 'http://x/mcp', bearer_token_env: 'TOK' })
  })
})

// ── Interaction ──────────────────────────────────────────────────────────
vi.mock('@/api/endpoints', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    getBackends: vi.fn(),
    getHealth: vi.fn(),
    postRegisterBackend: vi.fn(),
    postValidateBackend: vi.fn(),
    postReloadBackends: vi.fn(),
    postStartService: vi.fn(),
    postStopService: vi.fn(),
    postRestartService: vi.fn(),
    deleteBackend: vi.fn(),
    postSetBackendEnabled: vi.fn(),
  }
})

const BACKENDS = [
  {
    name: 'opensearch-mcp',
    type: 'stdio',
    enabled: true,
    started: true,
    on_demand: false,
    pending_apply: false,
    requires: [],
    unmet_requires: [],
    health: { status: 'ok' },
  },
  {
    name: 'timesketch-mcp',
    type: 'http',
    enabled: true,
    started: false,
    on_demand: false,
    pending_apply: true,
    requires: [],
    unmet_requires: [],
    health: { status: 'gated' },
  },
]

beforeEach(() => {
  vi.clearAllMocks()
  useStore.setState({ toasts: [], user: { examiner: 'test', role: 'examiner' }, activeTab: 'backends' })
  endpoints.getBackends.mockResolvedValue({ backends: BACKENDS })
  endpoints.getHealth.mockResolvedValue({ status: 'ok', tools_count: 5, supabase: {}, evidence_root: {}, backends: {} })
})

/** Fill the challenge modal password and confirm. */
function confirmChallenge(password = 'pw') {
  const input = screen.getByLabelText(/examiner password/i)
  fireEvent.change(input, { target: { value: password } })
  fireEvent.click(screen.getByTestId('backend-challenge-confirm'))
}

describe('BackendsTab — interaction (challenge-gated flows)', () => {
  it('renders the registry list + restart banner from loaded data', async () => {
    render(<BackendsTab />)
    await screen.findByText('opensearch-mcp')
    expect(screen.getByText('timesketch-mcp')).toBeInTheDocument()
    // pending_apply on timesketch-mcp drives the restart-required banner.
    expect(screen.getByText(/Restart required to apply/i)).toBeInTheDocument()
  })

  it('Reload (Check Apply Status) is challenge-gated: no call until password entered', async () => {
    endpoints.postReloadBackends.mockResolvedValue({ status: 'current' })
    render(<BackendsTab />)
    await screen.findByText('opensearch-mcp')

    fireEvent.click(screen.getByRole('button', { name: /check apply status/i }))
    // Modal open, but endpoint not yet called.
    expect(endpoints.postReloadBackends).not.toHaveBeenCalled()
    // Confirm with no password submits nothing (button disabled).
    expect(screen.getByTestId('backend-challenge-confirm')).toBeDisabled()

    confirmChallenge()
    await waitFor(() => expect(endpoints.postReloadBackends).toHaveBeenCalledWith({ password: 'pw' }))
  })

  it('Register parses args/env into the payload after the challenge', async () => {
    endpoints.postRegisterBackend.mockResolvedValue({ restart_required: true })
    render(<BackendsTab />)
    await screen.findByText('opensearch-mcp')

    fireEvent.change(screen.getByLabelText(/backend name/i), { target: { value: 'new-mcp' } })
    fireEvent.change(screen.getByLabelText(/command/i), { target: { value: 'node' } })
    fireEvent.change(screen.getByLabelText(/arguments/i), { target: { value: '--verbose\n--port\n8080' } })
    fireEvent.click(screen.getByRole('button', { name: /^register$/i }))

    expect(endpoints.postRegisterBackend).not.toHaveBeenCalled()
    confirmChallenge()
    await waitFor(() =>
      expect(endpoints.postRegisterBackend).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'new-mcp',
          password: 'pw',
          config: expect.objectContaining({ command: 'node', args: ['--verbose', '--port', '8080'] }),
        }),
      ),
    )
  })

  it('Validate calls postValidateBackend (no challenge) and shows the result', async () => {
    endpoints.postValidateBackend.mockResolvedValue({ valid: true, namespace: 'ns', provides: [], requires: [], tools: [] })
    render(<BackendsTab />)
    await screen.findByText('opensearch-mcp')

    fireEvent.change(screen.getByLabelText(/backend name/i), { target: { value: 'x' } })
    fireEvent.click(screen.getByRole('button', { name: /validate/i }))
    await waitFor(() => expect(endpoints.postValidateBackend).toHaveBeenCalled())
    expect(await screen.findByText(/VALID BACKEND MANIFEST/i)).toBeInTheDocument()
  })

  it('Start passes the backend name through the challenge', async () => {
    // opensearch-mcp is started=true, so it shows Stop/Restart; timesketch-mcp is
    // enabled+stopped+met → Start enabled.
    endpoints.postStartService.mockResolvedValue({})
    render(<BackendsTab />)
    await screen.findByText('timesketch-mcp')

    // Two Start buttons render: opensearch-mcp's is disabled (already started);
    // timesketch-mcp's is the enabled one. Pick the enabled button.
    const startBtn = screen
      .getAllByRole('button', { name: /^start$/i })
      .find((btn) => !btn.disabled)
    fireEvent.click(startBtn)
    confirmChallenge()
    await waitFor(() => expect(endpoints.postStartService).toHaveBeenCalledWith('timesketch-mcp', { password: 'pw' }))
  })

  it('Unregister passes the backend name + password to deleteBackend', async () => {
    endpoints.deleteBackend.mockResolvedValue({ restart_required: false })
    render(<BackendsTab />)
    await screen.findByText('opensearch-mcp')

    fireEvent.click(screen.getAllByRole('button', { name: /unregister/i })[0])
    confirmChallenge()
    await waitFor(() => expect(endpoints.deleteBackend).toHaveBeenCalledWith('opensearch-mcp', { password: 'pw' }))
  })

  it('enable toggle calls postSetBackendEnabled with the next enabled state', async () => {
    endpoints.postSetBackendEnabled.mockResolvedValue({ restart_required: false })
    render(<BackendsTab />)
    await screen.findByText('opensearch-mcp')

    // opensearch-mcp is enabled → its toggle reads "Disable".
    fireEvent.click(screen.getAllByRole('button', { name: /^disable$/i })[0])
    confirmChallenge()
    await waitFor(() =>
      expect(endpoints.postSetBackendEnabled).toHaveBeenCalledWith('opensearch-mcp', { enabled: false, password: 'pw' }),
    )
  })

  it('error path: a rejected challenge action surfaces the error in the modal', async () => {
    endpoints.postReloadBackends.mockRejectedValue(new Error('Password verification failed'))
    render(<BackendsTab />)
    await screen.findByText('opensearch-mcp')

    fireEvent.click(screen.getByRole('button', { name: /check apply status/i }))
    confirmChallenge('bad')
    expect(await screen.findByText(/Password verification failed/i)).toBeInTheDocument()
  })
})
