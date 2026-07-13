import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { useStore } from '../store/useStore'
import * as endpoints from '../api/endpoints'
import { EvidenceTab } from '../components/evidence/EvidenceTab'

vi.mock('../api/endpoints', async (importOriginal) => ({
  ...(await importOriginal()),
  getEvidence: vi.fn(),
  getChainStatus: vi.fn(),
  postChainRescan: vi.fn(),
  postReplaceBegin: vi.fn(),
  postRestoreBegin: vi.fn(),
  postRecoveryComplete: vi.fn(),
  getEvidenceHistory: vi.fn(),
}))

const STATUS = { seal_status: 'sealed', ok: ['evidence/disk.img'], authority: 'db', manifest_version: 3 }
const EVIDENCE = [{ evidence_id: '22222222-2222-4222-8222-222222222222', path: 'evidence/disk.img', sha256: 'abc123def456', description: 'disk' }]

beforeEach(() => {
  vi.clearAllMocks()
  useStore.setState({ chainStatus: STATUS, user: { examiner: 'test', role: 'examiner' }, toasts: [] })
  endpoints.getEvidence.mockResolvedValue(EVIDENCE)
  endpoints.getChainStatus.mockResolvedValue(STATUS)
})

describe('P4.23.3 durable evidence recovery', () => {
  it('replaces standalone Unseal with a per-object Replace/Reacquire action', async () => {
    render(<EvidenceTab />)
    expect(await screen.findByTestId('replace-btn-evidence/disk.img')).toBeInTheDocument()
    expect(screen.queryByText(/^Unseal$/)).not.toBeInTheDocument()
  })

  it('begins Replace/Reacquire with a stable operation intent', async () => {
    endpoints.postReplaceBegin.mockResolvedValue({
      ready_for_replacement: true,
      operation_id: '33333333-3333-4333-8333-333333333333',
    })
    render(<EvidenceTab />)
    fireEvent.click(await screen.findByTestId('replace-btn-evidence/disk.img'))
    fireEvent.change(await screen.findByPlaceholderText(/Original acquisition corrupted/i), { target: { value: 'same source re-image' } })
    fireEvent.change(screen.getByPlaceholderText('Enter password...'), { target: { value: 'pw' } })
    fireEvent.click(screen.getByRole('button', { name: 'Begin Replace/Reacquire' }))
    await waitFor(() => expect(endpoints.postReplaceBegin).toHaveBeenCalledTimes(1))
    const body = endpoints.postReplaceBegin.mock.calls[0][0]
    expect(body).toMatchObject({ password: 'pw', path: 'evidence/disk.img', reason: 'same source re-image' })
    expect(body.idempotency_key).toMatch(/^[0-9a-f-]{36}$/)
  })

  it('completes the server-stored operation using only password and operation ID', async () => {
    const operationId = '33333333-3333-4333-8333-333333333333'
    const incomplete = { ...STATUS, incomplete_operation: { operation_id: operationId, action: 'RESTORE_EXACT', phase: 'FILESYSTEM_APPLYING', recoverable: true } }
    useStore.setState({ chainStatus: incomplete })
    endpoints.getChainStatus.mockResolvedValue(incomplete)
    endpoints.postRecoveryComplete.mockResolvedValue({ completed: true, restored_exact: true })
    render(<EvidenceTab />)
    fireEvent.click(await screen.findByRole('button', { name: 'Complete Recovery' }))
    fireEvent.change(screen.getByPlaceholderText('Enter password...'), { target: { value: 'fresh-pw' } })
    fireEvent.click(screen.getByTestId('recovery-complete-submit'))
    await waitFor(() => expect(endpoints.postRecoveryComplete).toHaveBeenCalledWith({
      password: 'fresh-pw', operation_id: operationId,
    }))
  })

  it('shows append-only Evidence Version and custody-event history by object ID', async () => {
    endpoints.getEvidenceHistory.mockResolvedValue({
      versions: [{ evidence_version_id: 'v1', manifest_version: 3, sha256: 'sha256:abcdef', bytes: 10 }],
      events: [{ event_id: 'e1', seq: 7, event_type: 'MANIFEST_SEALED' }],
    })
    render(<EvidenceTab />)
    fireEvent.click(await screen.findByRole('button', { name: 'Version history' }))
    expect(await screen.findByText(/v3 ·/)).toBeInTheDocument()
    expect(screen.getByText(/#7 · MANIFEST_SEALED/)).toBeInTheDocument()
    expect(endpoints.getEvidenceHistory).toHaveBeenCalledWith(EVIDENCE[0].evidence_id)
  })
})
