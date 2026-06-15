import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { useStore } from '../store/useStore'
import * as endpoints from '../api/endpoints'
import { EvidenceTab } from '../components/evidence/EvidenceTab'

// Mock the API layer so the component never hits the network.
vi.mock('../api/endpoints', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    getEvidence: vi.fn(),
    getChainStatus: vi.fn(),
    postChainRescan: vi.fn(),
    unsealEvidence: vi.fn(),
    postChainUnseal: vi.fn(),
  }
})

// chainStatus.ok is the list of per-item SEALED display_paths; the Unseal button
// keys off per-item membership in `ok`, not the case aggregate seal_status.
const SEALED_STATUS = { seal_status: 'sealed', ok: ['evidence/disk.img'], authority: 'db', manifest_version: 3 }
const EVIDENCE = [{ path: 'evidence/disk.img', sha256: 'abc123def456', description: 'disk', registered_at: null, registered_by: 'examiner' }]

function seedStore() {
  useStore.setState({
    chainStatus: SEALED_STATUS,
    user: { examiner: 'test-examiner', role: 'examiner' },
    toasts: [],
    activeTab: 'evidence',
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  seedStore()
  endpoints.getEvidence.mockResolvedValue(EVIDENCE)
  endpoints.getChainStatus.mockResolvedValue(SEALED_STATUS)
})

describe('B-MVP-048: evidence Unseal operator action', () => {
  it('renders an Unseal button for sealed evidence items', async () => {
    render(<EvidenceTab />)
    expect(await screen.findByTestId('unseal-btn-evidence/disk.img')).toBeInTheDocument()
  })

  it('does NOT render the Unseal button when the item is not sealed', async () => {
    const unsealedStatus = { seal_status: 'unsealed', ok: [], authority: 'db' }
    useStore.setState({ chainStatus: unsealedStatus })
    endpoints.getChainStatus.mockResolvedValue(unsealedStatus)
    render(<EvidenceTab />)
    // Wait for the row to render, then assert the unseal control is absent.
    await screen.findByText('evidence/disk.img')
    expect(screen.queryByTestId('unseal-btn-evidence/disk.img')).not.toBeInTheDocument()
  })

  it('renders the Unseal button PER-ITEM even when the case aggregate is not sealed', async () => {
    // Regression: unsealing one item drops the case aggregate to non-sealed; a
    // still-sealed sibling item must KEEP its Unseal button (gated on ok[], not
    // the aggregate seal_status).
    const mixed = { seal_status: 'unsealed', ok: ['evidence/disk.img'], authority: 'db' }
    useStore.setState({ chainStatus: mixed })
    endpoints.getChainStatus.mockResolvedValue(mixed)
    render(<EvidenceTab />)
    expect(await screen.findByTestId('unseal-btn-evidence/disk.img')).toBeInTheDocument()
  })

  it('opens the re-auth modal and calls unsealEvidence with (path, reason, password)', async () => {
    endpoints.unsealEvidence.mockResolvedValue({ unsealed: true, seal_status: 'unsealed' })
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByTestId('unseal-btn-evidence/disk.img'))

    const reason = await screen.findByPlaceholderText(/Replacing corrupted image/i)
    fireEvent.change(reason, { target: { value: 'adding new evidence' } })
    fireEvent.change(screen.getByPlaceholderText('Enter password...'), { target: { value: 'hunter2' } })

    fireEvent.click(screen.getByTestId('unseal-submit'))

    await waitFor(() => {
      expect(endpoints.unsealEvidence).toHaveBeenCalledWith('evidence/disk.img', 'adding new evidence', 'hunter2')
    })
  })

  it('surfaces a 401 wrong-password error from the API in the modal', async () => {
    endpoints.unsealEvidence.mockRejectedValue(new Error('Re-authentication failed'))
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByTestId('unseal-btn-evidence/disk.img'))
    fireEvent.change(await screen.findByPlaceholderText(/Replacing corrupted image/i), { target: { value: 'r' } })
    fireEvent.change(screen.getByPlaceholderText('Enter password...'), { target: { value: 'wrong' } })
    fireEvent.click(screen.getByTestId('unseal-submit'))

    expect(await screen.findByText('Re-authentication failed')).toBeInTheDocument()
  })
})
