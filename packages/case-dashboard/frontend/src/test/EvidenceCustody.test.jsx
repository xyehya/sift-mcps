import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'

import { useStore } from '@/store/useStore'
import * as endpoints from '@/api/endpoints'
import { EvidenceTab } from '@/components/evidence/EvidenceTab'

// ─────────────────────────────────────────────────────────────────────────
// EvidenceCustody.test.jsx — interaction coverage for the custody flows that
// the frozen EvidenceUnseal.test.jsx does NOT cover (seal · ignore · delete ·
// retire · reacquire · verify-hmac · per-item verify · anchor · proof-export).
// Locks functionality without a backend.
//
// Mocking mirrors EvidenceUnseal.test.jsx: mock @/api/endpoints, seed the store
// so panels render.
//
// SUBMIT GATING: every required field carries the HTML `required` attribute, so
// the form will not submit (and the endpoint is never called) until the
// required fields are filled — the "submit stays disabled until required fields
// are filled" contract. Each flow asserts: empty submit → endpoint NOT called;
// then the filled-in happy path (correct endpoint + args + success state). Plus
// error-path coverage (rejected endpoint → modal error banner), the path users
// hit in ?mock=1 with no backend.
// ─────────────────────────────────────────────────────────────────────────

vi.mock('@/api/endpoints', async (importOriginal) => {
  const actual = await importOriginal()
  return {
    ...actual,
    getEvidence: vi.fn(),
    getChainStatus: vi.fn(),
    postChainRescan: vi.fn(),
    postChainSeal: vi.fn(),
    postChainIgnore: vi.fn(),
    postChainDelete: vi.fn(),
    postChainRetire: vi.fn(),
    postChainReacquire: vi.fn(),
    postChainVerifyHmac: vi.fn(),
    postVerifyEvidence: vi.fn(),
    postChainAnchor: vi.fn(),
    postChainProofExport: vi.fn(),
  }
})

const EVIDENCE = [
  {
    path: 'evidence/disk.img',
    sha256: 'abc123def4567890',
    description: 'disk',
    registered_at: null,
    registered_by: 'examiner',
  },
]

/** Seed the store with a chainStatus + minimal user/toast surface. */
function seed(chainStatus) {
  useStore.setState({
    chainStatus,
    user: { examiner: 'test-examiner', role: 'examiner' },
    toasts: [],
    activeTab: 'evidence',
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  endpoints.getEvidence.mockResolvedValue(EVIDENCE)
  // Default: refreshData's getChainStatus should not clobber the seeded status.
  endpoints.getChainStatus.mockImplementation(async () => useStore.getState().chainStatus)
})

/** Fill the password field (and optionally the reason field) inside an open modal. */
function fillModal({ password, reason } = {}) {
  if (reason != null) {
    fireEvent.change(screen.getByLabelText(/Justification Reason/i), { target: { value: reason } })
  }
  if (password != null) {
    fireEvent.change(screen.getByPlaceholderText('Enter password...'), { target: { value: password } })
  }
}

// ── 1. Seal ────────────────────────────────────────────────────────────────
describe('Seal manifest flow', () => {
  beforeEach(() => seed({ status: 'ok', unregistered: ['evidence/pcap.raw'], write_protected: true }))

  it('opens the seal modal from "Seal Manifest", gates submit on password, and seals with file specs', async () => {
    endpoints.postChainSeal.mockResolvedValue({ sealed: true, manifest_version: 4 })
    render(<EvidenceTab />)

    // Trigger renders + per-row inputs visible.
    const sealBtn = await screen.findByRole('button', { name: /Seal Manifest \(1 file\)/i })
    // Set source/description on the unregistered row (must reach the payload).
    fireEvent.change(screen.getByPlaceholderText('e.g. USB drive #1'), { target: { value: 'USB drive #1' } })
    fireEvent.change(screen.getByPlaceholderText('e.g. Acquired disk image'), { target: { value: 'PCAP capture' } })

    fireEvent.click(sealBtn)
    const modal = await screen.findByRole('dialog')

    // Gate: required password is empty → form will not submit, endpoint NOT called.
    fireEvent.click(within(modal).getByRole('button', { name: 'Confirm' }))
    expect(endpoints.postChainSeal).not.toHaveBeenCalled()

    // Happy path: fill password → seals with file specs derived from the row inputs.
    fillModal({ password: 'hunter2' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Confirm' }))

    await waitFor(() => {
      expect(endpoints.postChainSeal).toHaveBeenCalledWith({
        password: 'hunter2',
        file_specs: [{ path: 'evidence/pcap.raw', source: 'USB drive #1', description: 'PCAP capture' }],
      })
    })
    expect(await within(modal).findByText(/Manifest version 4 sealed successfully/i)).toBeInTheDocument()
  })

  it('renders the modal error banner when postChainSeal rejects (the ?mock=1 no-backend path)', async () => {
    endpoints.postChainSeal.mockRejectedValue(new Error('Seal endpoint unavailable'))
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByRole('button', { name: /Seal Manifest/i }))
    const modal = await screen.findByRole('dialog')
    fillModal({ password: 'hunter2' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Confirm' }))

    expect(await within(modal).findByText('Seal endpoint unavailable')).toBeInTheDocument()
  })
})

// ── 2. Ignore ────────────────────────────────────────────────────────────────
describe('Ignore unregistered file flow', () => {
  beforeEach(() => seed({ status: 'ok', unregistered: ['evidence/temp.log'], write_protected: true }))

  it('opens ignore modal, requires reason + password, then calls postChainIgnore', async () => {
    endpoints.postChainIgnore.mockResolvedValue({ ignored: true })
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByRole('button', { name: 'Ignore' }))
    const modal = await screen.findByRole('dialog')
    expect(within(modal).getByText('Ignore Unregistered File')).toBeInTheDocument()

    // Gate 1: all fields empty → endpoint NOT called (required attrs block submit).
    fireEvent.click(within(modal).getByRole('button', { name: 'Ignore File' }))
    expect(endpoints.postChainIgnore).not.toHaveBeenCalled()

    // Gate 2: reason filled but password still empty → still NOT called.
    fillModal({ reason: 'temp scan file' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Ignore File' }))
    expect(endpoints.postChainIgnore).not.toHaveBeenCalled()

    // Happy path.
    fillModal({ password: 'pw' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Ignore File' }))
    await waitFor(() => {
      expect(endpoints.postChainIgnore).toHaveBeenCalledWith({
        password: 'pw',
        path: 'evidence/temp.log',
        reason: 'temp scan file',
      })
    })
    expect(await within(modal).findByText(/marked as ignored successfully/i)).toBeInTheDocument()
  })
})

// ── 3. Delete ────────────────────────────────────────────────────────────────
describe('Delete stray file flow', () => {
  beforeEach(() => seed({ status: 'ok', unregistered: ['evidence/stray.bin'], write_protected: true }))

  it('opens delete modal, requires reason + password, then calls postChainDelete', async () => {
    endpoints.postChainDelete.mockResolvedValue({ deleted: true, file_removed: true })
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByRole('button', { name: 'Delete' }))
    const modal = await screen.findByRole('dialog')
    expect(within(modal).getByText('Delete Stray File')).toBeInTheDocument()

    // Gate: empty required fields → endpoint NOT called.
    fireEvent.click(within(modal).getByRole('button', { name: 'Delete File' }))
    expect(endpoints.postChainDelete).not.toHaveBeenCalled()

    fillModal({ reason: 'unauthorized file', password: 'pw' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Delete File' }))
    await waitFor(() => {
      expect(endpoints.postChainDelete).toHaveBeenCalledWith({
        password: 'pw',
        path: 'evidence/stray.bin',
        reason: 'unauthorized file',
      })
    })
    expect(await within(modal).findByText(/File deleted from evidence/i)).toBeInTheDocument()
  })
})

// ── 4. Retire (custody violation: missing) ───────────────────────────────────
describe('Retire missing file flow', () => {
  beforeEach(() => seed({ status: 'violated', missing: ['evidence/lost.img'], write_protected: true }))

  it('opens retire modal from a missing-file violation and calls postChainRetire', async () => {
    endpoints.postChainRetire.mockResolvedValue({ retired: true, manifest_version: 5 })
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByRole('button', { name: 'Retire File' }))
    const modal = await screen.findByRole('dialog')
    expect(within(modal).getByText('Retire Missing File')).toBeInTheDocument()

    // Gate: empty required fields → endpoint NOT called.
    fireEvent.click(within(modal).getByRole('button', { name: 'Retire File' }))
    expect(endpoints.postChainRetire).not.toHaveBeenCalled()

    fillModal({ reason: 'removed from scope', password: 'pw' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Retire File' }))
    await waitFor(() => {
      expect(endpoints.postChainRetire).toHaveBeenCalledWith({
        password: 'pw',
        path: 'evidence/lost.img',
        reason: 'removed from scope',
      })
    })
    expect(await within(modal).findByText(/File retired successfully/i)).toBeInTheDocument()
  })

  it('renders the modal error banner when postChainRetire rejects', async () => {
    endpoints.postChainRetire.mockRejectedValue(new Error('Retire endpoint unavailable'))
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByRole('button', { name: 'Retire File' }))
    const modal = await screen.findByRole('dialog')
    fillModal({ reason: 'x', password: 'pw' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Retire File' }))

    expect(await within(modal).findByText('Retire endpoint unavailable')).toBeInTheDocument()
  })
})

// ── 5. Reacquire / Re-seal (custody violation: modified) ─────────────────────
describe('Reacquire (re-seal) modified file flow', () => {
  beforeEach(() => seed({ status: 'violated', modified: ['evidence/changed.img'], write_protected: true }))

  it('opens reacquire modal from a modified-file violation and calls postChainReacquire', async () => {
    endpoints.postChainReacquire.mockResolvedValue({ reacquired: true, manifest_version: 6 })
    render(<EvidenceTab />)

    // "Re-seal" appears as a violation action and as the modal confirm button.
    fireEvent.click(await screen.findByRole('button', { name: 'Re-seal' }))
    const modal = await screen.findByRole('dialog')
    expect(within(modal).getByText('Re-acquire & Re-seal Evidence')).toBeInTheDocument()

    // Gate: empty required fields → endpoint NOT called.
    fireEvent.click(within(modal).getByRole('button', { name: 'Re-seal' }))
    expect(endpoints.postChainReacquire).not.toHaveBeenCalled()

    fillModal({ reason: 'corrupted; re-imaged', password: 'pw' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Re-seal' }))
    await waitFor(() => {
      expect(endpoints.postChainReacquire).toHaveBeenCalledWith({
        password: 'pw',
        path: 'evidence/changed.img',
        reason: 'corrupted; re-imaged',
      })
    })
    expect(await within(modal).findByText(/re-acquired and re-sealed/i)).toBeInTheDocument()
  })
})

// ── 6. Verify HMAC (both result branches) ────────────────────────────────────
describe('Verify HMAC flow', () => {
  beforeEach(() => seed({ status: 'ok', hmac_verify_needed: true, write_protected: true }))

  it('verifies HMAC and renders the intact branch on { ok:true }', async () => {
    endpoints.postChainVerifyHmac.mockResolvedValue({ ok: true, verified: 12 })
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByRole('button', { name: 'Verify Now' }))
    const modal = await screen.findByRole('dialog')

    // Gate: required password empty → endpoint NOT called.
    fireEvent.click(within(modal).getByRole('button', { name: 'Verify' }))
    expect(endpoints.postChainVerifyHmac).not.toHaveBeenCalled()

    fillModal({ password: 'pw' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Verify' }))
    await waitFor(() => {
      expect(endpoints.postChainVerifyHmac).toHaveBeenCalledWith({ password: 'pw' })
    })
    expect(await within(modal).findByText(/Verified 12 event\(s\)\. Chain is intact\./i)).toBeInTheDocument()
  })

  it('renders the failed branch with failed_indices on { ok:false }', async () => {
    endpoints.postChainVerifyHmac.mockResolvedValue({ ok: false, failed: 3, failed_indices: [1, 4, 7] })
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByRole('button', { name: 'Verify Now' }))
    const modal = await screen.findByRole('dialog')
    fillModal({ password: 'pw' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Verify' }))

    expect(await within(modal).findByText(/3 event\(s\) FAILED/i)).toBeInTheDocument()
    expect(within(modal).getByText(/\[1,4,7\]/)).toBeInTheDocument()
  })
})

// ── 7. Per-item Verify (registered table) ────────────────────────────────────
describe('Per-item evidence verify flow', () => {
  beforeEach(() => seed({ status: 'sealed', ok: [], write_protected: true }))

  it('transitions checking → verified when postVerifyEvidence reports verified', async () => {
    let resolveVerify
    endpoints.postVerifyEvidence.mockReturnValue(new Promise((res) => { resolveVerify = res }))
    render(<EvidenceTab />)

    const row = (await screen.findByText('evidence/disk.img')).closest('tr')
    fireEvent.click(within(row).getByRole('button', { name: 'Verify' }))

    // checking state while the promise is pending
    expect(await within(row).findByText(/Checking/i)).toBeInTheDocument()
    expect(endpoints.postVerifyEvidence).toHaveBeenCalledWith('evidence/disk.img')

    resolveVerify({ status: 'verified' })
    expect(await within(row).findByText(/Verified/i)).toBeInTheDocument()
  })

  it('shows the FAILED state when postVerifyEvidence reports failed', async () => {
    endpoints.postVerifyEvidence.mockResolvedValue({ status: 'failed' })
    render(<EvidenceTab />)

    const row = (await screen.findByText('evidence/disk.img')).closest('tr')
    fireEvent.click(within(row).getByRole('button', { name: 'Verify' }))
    expect(await within(row).findByText(/FAILED/i)).toBeInTheDocument()
  })

  it('shows the error state when postVerifyEvidence rejects', async () => {
    endpoints.postVerifyEvidence.mockRejectedValue(new Error('boom'))
    render(<EvidenceTab />)

    const row = (await screen.findByText('evidence/disk.img')).closest('tr')
    fireEvent.click(within(row).getByRole('button', { name: 'Verify' }))
    expect(await within(row).findByText('Error')).toBeInTheDocument()
  })
})

// ── 8. Anchor ────────────────────────────────────────────────────────────────
describe('Solana anchor flow', () => {
  beforeEach(() =>
    seed({
      status: 'sealed',
      write_protected: true,
      anchor: { anchoring_enabled: true, manifest_version: 3, solana_tx: null },
    }),
  )

  it('triggers postChainAnchor from "Anchor Now"', async () => {
    endpoints.postChainAnchor.mockResolvedValue({ anchored: true })
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByRole('button', { name: 'Anchor Now' }))
    await waitFor(() => expect(endpoints.postChainAnchor).toHaveBeenCalledTimes(1))
  })
})

// ── 9. Proof export (DB authority only) ──────────────────────────────────────
describe('Custody proof export flow', () => {
  it('renders the proof-export panel under authority:db and triggers postChainProofExport', async () => {
    seed({ status: 'sealed', authority: 'db', write_protected: true })
    endpoints.postChainProofExport.mockResolvedValue({ proof_export: { verified: true } })
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByRole('button', { name: /Generate Proof Export/i }))
    await waitFor(() => expect(endpoints.postChainProofExport).toHaveBeenCalledTimes(1))
  })

  it('does NOT render the proof-export panel when authority is not db', async () => {
    seed({ status: 'sealed', write_protected: true })
    render(<EvidenceTab />)
    await screen.findByText('Evidence Chain')
    expect(screen.queryByRole('button', { name: /Generate Proof Export/i })).not.toBeInTheDocument()
  })
})
