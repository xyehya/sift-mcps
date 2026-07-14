import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'

import { useStore } from '@/store/useStore'
import * as endpoints from '@/api/endpoints'
import { EvidenceTab } from '@/components/evidence/EvidenceTab'

// ─────────────────────────────────────────────────────────────────────────
// EvidenceCustody.test.jsx — interaction coverage for custody flows outside
// EvidenceRecovery.test.jsx (seal · ignore · delete · retire · Full Verify Evidence ·
// per-item verify · anchor · proof-export).
// Locks functionality without a backend.
//
// Mocking mirrors EvidenceRecovery.test.jsx: mock @/api/endpoints, seed the store
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
    postChainSealResume: vi.fn(),
    postChainIgnore: vi.fn(),
    postChainDelete: vi.fn(),
    postChainRetire: vi.fn(),
    postReplaceBegin: vi.fn(),
    postRestoreBegin: vi.fn(),
    postRecoveryComplete: vi.fn(),
    getEvidenceHistory: vi.fn(),
    postFullVerifyEvidence: vi.fn(),
    postEvidenceStorageProfile: vi.fn(),
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
    fillModal({ password: 'hunter2', reason: 'Initial evidence intake' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Confirm' }))

    await waitFor(() => {
      expect(endpoints.postChainSeal).toHaveBeenCalledWith({
        password: 'hunter2',
        reason: 'Initial evidence intake',
        storage_profile: 'LOCAL_IMMUTABLE',
        idempotency_key: expect.any(String),
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
    fillModal({ password: 'hunter2', reason: 'Retry initial evidence intake' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Confirm' }))

    expect(await within(modal).findByText('Seal endpoint unavailable')).toBeInTheDocument()
  })

  it('retains one idempotency key across retry and rotates it for a new modal intent', async () => {
    endpoints.postChainSeal.mockRejectedValue(new Error('temporary network loss'))
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByRole('button', { name: /Seal Manifest/i }))
    let modal = await screen.findByRole('dialog')
    fillModal({ password: 'hunter2', reason: 'Initial intake' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Confirm' }))
    await within(modal).findByText('temporary network loss')
    const firstKey = endpoints.postChainSeal.mock.calls[0][0].idempotency_key

    fireEvent.click(within(modal).getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(endpoints.postChainSeal).toHaveBeenCalledTimes(2))
    expect(endpoints.postChainSeal.mock.calls[1][0].idempotency_key).toBe(firstKey)

    fireEvent.click(within(modal).getByRole('button', { name: 'Cancel' }))
    fireEvent.click(await screen.findByRole('button', { name: /Seal Manifest/i }))
    modal = await screen.findByRole('dialog')
    fillModal({ password: 'hunter2', reason: 'Initial intake' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(endpoints.postChainSeal).toHaveBeenCalledTimes(3))
    expect(endpoints.postChainSeal.mock.calls[2][0].idempotency_key).not.toBe(firstKey)
  })

  it('renders a path-free recoverable operation state and exact next action', async () => {
    seed({
      status: 'unsealed',
      unregistered: [],
      incomplete_operation: {
        operation_id: 'op-1',
        action: 'ADD_SEAL',
        phase: 'FAILED_RECOVERABLE',
        failed_from_phase: 'FILESYSTEM_APPLYING',
        recoverable: true,
      },
    })
    render(<EvidenceTab />)

    const notice = await screen.findByRole('region', { name: 'Incomplete custody operation' })
    expect(within(notice).getByText('State: FAILED_RECOVERABLE')).toBeInTheDocument()
    expect(within(notice).getByText('Interrupted from: FILESYSTEM_APPLYING')).toBeInTheDocument()
    expect(within(notice).getByText(/Retry Add & Seal with the same intent/i)).toBeInTheDocument()
    expect(notice).not.toHaveTextContent('evidence/')
  })

  it('labels interrupted Restore completion without teaching Add & Seal retry', async () => {
    seed({
      status: 'violated', unregistered: [],
      incomplete_operation: {
        operation_id: 'op-restore', action: 'RESTORE_EXACT',
        phase: 'FAILED_RECOVERABLE', failed_from_phase: 'FILESYSTEM_VERIFIED',
        recoverable: true,
      },
    })
    render(<EvidenceTab />)

    const notice = await screen.findByRole('region', { name: 'Incomplete custody operation' })
    expect(within(notice).getByText('Exact Restore is incomplete')).toBeInTheDocument()
    expect(within(notice).getByText(/Retry Exact Restore completion with fresh re-authentication/i)).toBeInTheDocument()
    expect(notice).not.toHaveTextContent('Retry Add & Seal')
  })

  it.each(['GATE_BLOCKED', 'FILESYSTEM_APPLYING', 'FILESYSTEM_VERIFIED', 'FAILED_RECOVERABLE'])(
  'resumes the same server operation after a fresh component state in %s', async (phase) => {
    const operation = { operation_id: '33333333-3333-3333-3333-333333333333', action: 'ADD_SEAL', phase, recoverable: true }
    seed({ status: 'unsealed', unregistered: [], incomplete_operation: operation })
    const first = render(<EvidenceTab />)
    await screen.findByText(`State: ${phase}`)
    first.unmount()
    endpoints.postChainSealResume.mockResolvedValue({ sealed: true, manifest_version: 8, operation_id: operation.operation_id })
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByRole('button', { name: 'Resume Add & Seal' }))
    const modal = await screen.findByRole('dialog')
    fireEvent.change(within(modal).getByPlaceholderText('Enter password...'), { target: { value: 'fresh-password' } })
    fireEvent.click(within(modal).getByRole('button', { name: 'Resume' }))
    await waitFor(() => expect(endpoints.postChainSealResume).toHaveBeenCalledWith({
      password: 'fresh-password', operation_id: operation.operation_id,
    }))
    expect(endpoints.postChainSealResume).toHaveBeenCalledTimes(1)
    expect(endpoints.postChainSeal).not.toHaveBeenCalled()
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
      expect(endpoints.postChainIgnore).toHaveBeenCalledWith(expect.objectContaining({
        password: 'pw',
        path: 'evidence/temp.log',
        reason: 'temp scan file',
        idempotency_key: expect.any(String),
      }))
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
      expect(endpoints.postChainDelete).toHaveBeenCalledWith(expect.objectContaining({
        password: 'pw',
        path: 'evidence/stray.bin',
        reason: 'unauthorized file',
        idempotency_key: expect.any(String),
      }))
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
      expect(endpoints.postChainRetire).toHaveBeenCalledWith(expect.objectContaining({
        password: 'pw',
        path: 'evidence/lost.img',
        reason: 'removed from scope',
        idempotency_key: expect.any(String),
      }))
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

  it('rejects ambiguous retire responses without retired true', async () => {
    endpoints.postChainRetire.mockResolvedValue({ ignored: true, manifest_version: 5 })
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByRole('button', { name: 'Retire File' }))
    const modal = await screen.findByRole('dialog')
    fillModal({ reason: 'removed from scope', password: 'pw' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Retire File' }))

    expect(await within(modal).findByText('Retire failed')).toBeInTheDocument()
    expect(within(modal).queryByText(/File retired successfully/i)).not.toBeInTheDocument()
  })
})

// ── 5. Exact Restore (custody violation: modified) ────────────────────────────
describe('Exact Restore modified file flow', () => {
  beforeEach(() => seed({ status: 'violated', modified: ['evidence/changed.img'], write_protected: true }))

  it('opens exact Restore and records a durable begin intent', async () => {
    endpoints.postRestoreBegin.mockResolvedValue({ ready_for_replacement: true, operation_id: 'op-1' })
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByRole('button', { name: 'Exact Restore' }))
    const modal = await screen.findByRole('dialog')
    expect(within(modal).getByRole('heading', { name: 'Begin Exact Restore' })).toBeInTheDocument()

    // Gate: empty required fields → endpoint NOT called.
    fireEvent.click(within(modal).getByRole('button', { name: 'Begin Exact Restore' }))
    expect(endpoints.postRestoreBegin).not.toHaveBeenCalled()

    fillModal({ reason: 'corrupted; re-imaged', password: 'pw' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Begin Exact Restore' }))
    await waitFor(() => {
      expect(endpoints.postRestoreBegin).toHaveBeenCalledWith(expect.objectContaining({
        password: 'pw',
        path: 'evidence/changed.img',
        reason: 'corrupted; re-imaged',
      }))
    })
  })
})

// ── 6. Full database-custody verification (both result branches) ─────────────
describe('Full Verify Evidence flow', () => {
  beforeEach(() => seed({
    status: 'ok',
    seal_status: 'sealed',
    manifest_version: 1,
    active_count: 1,
    hmac_verify_needed: true,
    write_protected: true,
  }))

  it('full-verifies mounted evidence and renders the intact branch on { ok:true }', async () => {
    endpoints.postFullVerifyEvidence.mockResolvedValue({ ok: true, verified: true, issues: [] })
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByRole('button', { name: 'Full Verify Evidence' }))
    const modal = await screen.findByRole('dialog')
    expect(within(modal).getByRole('heading', { name: 'Full Verify Evidence' })).toBeInTheDocument()
    expect(within(modal).getByText(/Postgres custody authority/i)).toBeInTheDocument()

    // Full Verify is an integrity read and intentionally has no re-auth ceremony.
    fireEvent.click(within(modal).getByRole('button', { name: 'Full Verify' }))
    await waitFor(() => {
      expect(endpoints.postFullVerifyEvidence).toHaveBeenCalledWith({})
    })
    expect(await within(modal).findByText(/Mounted evidence matches database custody authority/i)).toBeInTheDocument()
  })

  it('renders database verification issues on { ok:false }', async () => {
    endpoints.postFullVerifyEvidence.mockResolvedValue({ ok: false, verified: false, issues: ['digest mismatch'] })
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByRole('button', { name: 'Full Verify Evidence' }))
    const modal = await screen.findByRole('dialog')
    fireEvent.click(within(modal).getByRole('button', { name: 'Full Verify' }))

    expect(await within(modal).findByText(/Full verification failed with 1 issue/i)).toBeInTheDocument()
    expect(within(modal).getByText('digest mismatch')).toBeInTheDocument()
  })

  it('guides virgin external intake and disables Full Verify until a manifest exists', async () => {
    seed({
      status: 'unsealed',
      seal_status: 'unsealed',
      storage_profile: 'EXTERNALLY_READ_ONLY',
      storage_availability: 'FULL_VERIFY_REQUIRED',
      storage_remediation: 'FULL_VERIFY',
      manifest_version: 0,
      active_count: 0,
      hmac_verify_needed: true,
      unregistered: ['evidence/external.raw'],
      write_protected: true,
    })

    render(<EvidenceTab />)

    expect(await screen.findByText(/Add & Seal establishes the first full-hash source and mount receipt/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Full Verify Evidence' })).toBeDisabled()
    expect(screen.getByRole('button', { name: /Seal Manifest \(1 file\)/i })).toBeEnabled()
    expect(endpoints.postFullVerifyEvidence).not.toHaveBeenCalled()
  })

  it('does not label a nonvirgin zero-active manifest as first external intake', async () => {
    seed({
      status: 'violated',
      seal_status: 'violated',
      storage_profile: 'EXTERNALLY_READ_ONLY',
      storage_source_identity: 'already-established-source',
      storage_verified_mount_instance: 'prior-mount',
      storage_verified_generation: 1,
      manifest_version: 2,
      active_count: 0,
      hmac_verify_needed: true,
      unregistered: [],
    })

    render(<EvidenceTab />)

    expect(await screen.findByText(/Evidence has not yet been fully verified/i)).toBeInTheDocument()
    expect(screen.queryByText(/Add & Seal establishes the first full-hash source and mount receipt/i)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Full Verify Evidence' })).toBeDisabled()
  })
})

describe('Evidence storage profile flow', () => {
  beforeEach(() => seed({
    status: 'sealed',
    storage_profile: 'LOCAL_IMMUTABLE',
    storage_availability: 'AVAILABLE',
    storage_remediation: 'NONE',
    write_protected: true,
  }))

  it('shows only safe posture state and requires scoped re-auth to change profile', async () => {
    endpoints.postEvidenceStorageProfile.mockResolvedValue({
      storage_profile: 'EXTERNALLY_READ_ONLY',
      storage_availability: 'FULL_VERIFY_REQUIRED',
      storage_remediation: 'FULL_VERIFY',
    })
    render(<EvidenceTab />)

    expect(await screen.findByText('Local immutable')).toBeInTheDocument()
    expect(screen.getByText(/State: AVAILABLE/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Change profile' }))
    const modal = await screen.findByRole('dialog')
    expect(within(modal).getByText(/Change to Externally Read-Only/)).toBeInTheDocument()

    fillModal({ reason: 'Move to hardware read-only evidence', password: 'pw' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Change Profile' }))
    await waitFor(() => {
      expect(endpoints.postEvidenceStorageProfile).toHaveBeenCalledWith({
        password: 'pw',
        profile: 'EXTERNALLY_READ_ONLY',
        reason: 'Move to hardware read-only evidence',
        idempotency_key: expect.any(String),
      })
    })
    expect(await within(modal).findByText(/Storage profile changed\. Full Verify Evidence is required/)).toBeInTheDocument()
  })

  it('renders current database storage values after the status refresh', async () => {
    endpoints.getChainStatus.mockResolvedValue({
      status: 'sealed',
      storage_profile: 'EXTERNALLY_READ_ONLY',
      storage_availability: 'AVAILABLE',
      storage_remediation: 'NONE',
      storage_last_full_verified_at: '2026-07-14T12:34:56+00:00',
      write_protected: true,
    })

    render(<EvidenceTab />)

    expect(await screen.findByText('Externally read-only')).toBeInTheDocument()
    expect(screen.getByText(/State: AVAILABLE · Remediation: NONE/)).toBeInTheDocument()
    expect(screen.getByText(/Last full verify: 2026-07-14T12:34:56\+00:00/)).toBeInTheDocument()
    expect(screen.queryByText(/State: UNAVAILABLE/)).not.toBeInTheDocument()
    expect(screen.queryByText(/Last full verify: never/)).not.toBeInTheDocument()
  })

  it('shows unavailable authority truth without profile mutation controls', async () => {
    endpoints.getChainStatus.mockResolvedValue({
      authority: 'db',
      status: 'no_case',
      storage_profile: 'UNKNOWN',
      storage_availability: 'UNAVAILABLE',
      storage_remediation: 'FULL_VERIFY',
      storage_last_full_verified_at: null,
    })

    render(<EvidenceTab />)

    expect(await screen.findByText('Storage profile unavailable')).toBeInTheDocument()
    expect(screen.getByText(/State: UNAVAILABLE · Remediation: FULL_VERIFY/)).toBeInTheDocument()
    expect(screen.getByText(/Last full verify: never/)).toBeInTheDocument()
    expect(screen.queryByText('Local immutable')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Change profile' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Authorize current source' })).not.toBeInTheDocument()
  })

  it('offers explicit source authorization without conflating it with a profile toggle', async () => {
    seed({
      status: 'violated',
      storage_profile: 'EXTERNALLY_READ_ONLY',
      storage_availability: 'IDENTITY_DRIFT',
      storage_remediation: 'AUTHORIZE_SOURCE_CHANGE',
      write_protected: true,
    })
    endpoints.postEvidenceStorageProfile.mockResolvedValue({
      storage_profile: 'EXTERNALLY_READ_ONLY',
      storage_availability: 'FULL_VERIFY_REQUIRED',
      storage_remediation: 'FULL_VERIFY',
    })
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByRole('button', { name: 'Authorize current source' }))
    const modal = await screen.findByRole('dialog')
    fillModal({ reason: 'Examiner authorizes this replacement source', password: 'pw' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Change Profile' }))
    await waitFor(() => expect(endpoints.postEvidenceStorageProfile).toHaveBeenCalledWith({
      password: 'pw',
      profile: 'EXTERNALLY_READ_ONLY',
      reason: 'Examiner authorizes this replacement source',
      idempotency_key: expect.any(String),
    }))
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
