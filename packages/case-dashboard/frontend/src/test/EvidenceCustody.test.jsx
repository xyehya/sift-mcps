import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'

import { useStore } from '@/store/useStore'
import * as endpoints from '@/api/endpoints'
import { EvidenceTab } from '@/components/evidence/EvidenceTab'

// ─────────────────────────────────────────────────────────────────────────
// EvidenceCustody.test.jsx — interaction coverage for custody flows outside
// EvidenceHistory.test.jsx (seal · the unified D4 Resolve batch · Full Verify
// Evidence · per-item verify · anchor · proof-export).
// Locks functionality without a backend.
//
// Replace/Reacquire, exact Restore, Delete Stray, storage-profile change, and
// signing-key rotation are permanently out of scope (SPEC "Out of Scope") and
// have no coverage here — see EVIDENCE-CUSTODY-SPEC.md.
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
    getCustodyStatus: vi.fn(),
    postCustodySeal: vi.fn(),
    postChainSeal: vi.fn(),
    postChainSealResume: vi.fn(),
    postCustodyResolve: vi.fn(),
    getEvidenceHistory: vi.fn(),
    postFullVerifyEvidence: vi.fn(),
    postVerifyEvidence: vi.fn(),
    postChainAnchor: vi.fn(),
    postChainProofExport: vi.fn(),
  }
})

// EC-4: `status: 'sealed'` is required for this row to render in the Sealed
// Evidence table at all — a detected-only/digestless object never does.
const EVIDENCE = [
  {
    evidence_id: 'obj-1',
    path: 'evidence/disk.img',
    sha256: 'abc123def4567890',
    description: 'disk',
    status: 'sealed',
    seal_status: 'sealed',
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
  endpoints.getCustodyStatus.mockResolvedValue({})
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
// PF-009: Add & Seal posts to the canonical two-phase /custody/seal (begin then
// commit), NOT the dead legacy /api/evidence/chain/seal (production
// EvidenceAuthorityService has no .seal). Targets carry the real
// snapshot_observation_id from the latest Refresh; only a COMMITTED result seals.
describe('Seal manifest flow', () => {
  beforeEach(() =>
    seed({ status: 'ok', unregistered: ['evidence/pcap.raw'], snapshot_observation_id: 42, write_protected: true }),
  )

  it('posts begin then commit to /custody/seal with the same key and snapshot targets', async () => {
    endpoints.postCustodySeal
      .mockResolvedValueOnce({ operation_id: 'op-1', phase: 'REQUESTED' })
      .mockResolvedValueOnce({ operation_id: 'op-1', phase: 'COMMITTED', manifest_version: 4, gate_state: 'OPEN' })
    render(<EvidenceTab />)

    const sealBtn = await screen.findByRole('button', { name: /Seal Manifest \(1 file\)/i })
    fireEvent.change(screen.getByPlaceholderText('e.g. USB drive #1'), { target: { value: 'USB drive #1' } })
    // PF-009 (B): the orphaned per-row Description INPUT is removed — the canonical
    // SealTarget has no description, so it can't be silently discarded. (The sealed-
    // evidence table's read-only Description column is a separate committed-object
    // display and is intentionally kept.)
    expect(screen.queryByPlaceholderText('e.g. Acquired disk image')).not.toBeInTheDocument()
    fireEvent.click(sealBtn)
    const modal = await screen.findByRole('dialog')

    // Gate: required password empty → form will not submit, endpoint NOT called.
    fireEvent.click(within(modal).getByRole('button', { name: 'Confirm' }))
    expect(endpoints.postCustodySeal).not.toHaveBeenCalled()
    expect(endpoints.postChainSeal).not.toHaveBeenCalled()

    fillModal({ password: 'hunter2', reason: 'Initial evidence intake' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Confirm' }))

    const target = { display_path: 'evidence/pcap.raw', snapshot_observation_id: 42, source: 'USB drive #1' }
    await waitFor(() => expect(endpoints.postCustodySeal).toHaveBeenCalledTimes(2))
    // Phase 1: begin — fresh password/reason + selected snapshot targets.
    expect(endpoints.postCustodySeal).toHaveBeenNthCalledWith(1, {
      phase: 'begin',
      password: 'hunter2',
      reason: 'Initial evidence intake',
      idempotency_key: expect.any(String),
      targets: [target],
    })
    // Phase 2: commit — same idempotency key + same targets, no reauth on the
    // happy single-shot path.
    expect(endpoints.postCustodySeal).toHaveBeenNthCalledWith(2, {
      phase: 'commit',
      idempotency_key: expect.any(String),
      targets: [target],
    })
    const beginBody = endpoints.postCustodySeal.mock.calls[0][0]
    const commitBody = endpoints.postCustodySeal.mock.calls[1][0]
    expect(commitBody.idempotency_key).toBe(beginBody.idempotency_key)
    // The dead legacy route is never used, and no client storage_profile is ever sent.
    expect(endpoints.postChainSeal).not.toHaveBeenCalled()
    expect(beginBody).not.toHaveProperty('storage_profile')
    expect(commitBody).not.toHaveProperty('storage_profile')
    expect(await within(modal).findByText(/Manifest version 4 sealed successfully/i)).toBeInTheDocument()
  })

  it('all targets carry the real snapshot_observation_id and never a synthesized/UNKNOWN one', async () => {
    seed({
      status: 'ok',
      storage_profile: 'UNKNOWN',
      unregistered: ['evidence/a.raw', 'evidence/b.raw'],
      snapshot_observation_id: 77,
    })
    endpoints.postCustodySeal
      .mockResolvedValueOnce({ phase: 'REQUESTED' })
      .mockResolvedValueOnce({ phase: 'COMMITTED', manifest_version: 1 })
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByRole('button', { name: /Seal Manifest \(2 files\)/i }))
    const modal = await screen.findByRole('dialog')
    fillModal({ password: 'hunter2', reason: 'intake' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Confirm' }))

    await waitFor(() => expect(endpoints.postCustodySeal).toHaveBeenCalledTimes(2))
    for (const call of endpoints.postCustodySeal.mock.calls) {
      const { targets } = call[0]
      expect(targets.map((t) => t.snapshot_observation_id)).toEqual([77, 77])
      expect(JSON.stringify(call[0])).not.toContain('UNKNOWN')
      expect(call[0]).not.toHaveProperty('storage_profile')
    }
  })

  it('refuses to seal without a real Refresh snapshot id and posts nothing', async () => {
    seed({ status: 'ok', unregistered: ['evidence/pcap.raw'] }) // no snapshot_observation_id
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByRole('button', { name: /Seal Manifest/i }))
    const modal = await screen.findByRole('dialog')
    fillModal({ password: 'hunter2', reason: 'intake' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Confirm' }))

    expect(await within(modal).findByText(/Refresh custody status/i)).toBeInTheDocument()
    expect(endpoints.postCustodySeal).not.toHaveBeenCalled()
  })

  it('renders the modal error banner when the seal begin is rejected (shaped failure stays visible)', async () => {
    endpoints.postCustodySeal.mockRejectedValue(new Error('Seal endpoint unavailable'))
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByRole('button', { name: /Seal Manifest/i }))
    const modal = await screen.findByRole('dialog')
    fillModal({ password: 'hunter2', reason: 'Retry initial evidence intake' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Confirm' }))

    expect(await within(modal).findByText('Seal endpoint unavailable')).toBeInTheDocument()
  })

  it('a non-COMMITTED commit result is a failure, not a success', async () => {
    endpoints.postCustodySeal
      .mockResolvedValueOnce({ phase: 'REQUESTED' })
      .mockResolvedValueOnce({ phase: 'PROTECTED' }) // never COMMITTED
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByRole('button', { name: /Seal Manifest/i }))
    const modal = await screen.findByRole('dialog')
    fillModal({ password: 'hunter2', reason: 'intake' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Confirm' }))

    await waitFor(() => expect(endpoints.postCustodySeal).toHaveBeenCalledTimes(2))
    expect(within(modal).queryByText(/sealed successfully/i)).not.toBeInTheDocument()
  })

  it('retains one idempotency key across retry and rotates it for a new modal intent', async () => {
    endpoints.postCustodySeal.mockRejectedValue(new Error('temporary network loss'))
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByRole('button', { name: /Seal Manifest/i }))
    let modal = await screen.findByRole('dialog')
    fillModal({ password: 'hunter2', reason: 'Initial intake' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Confirm' }))
    await within(modal).findByText('temporary network loss')
    const firstKey = endpoints.postCustodySeal.mock.calls[0][0].idempotency_key

    fireEvent.click(within(modal).getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(endpoints.postCustodySeal).toHaveBeenCalledTimes(2))
    expect(endpoints.postCustodySeal.mock.calls[1][0].idempotency_key).toBe(firstKey)

    fireEvent.click(within(modal).getByRole('button', { name: 'Cancel' }))
    fireEvent.click(await screen.findByRole('button', { name: /Seal Manifest/i }))
    modal = await screen.findByRole('dialog')
    fillModal({ password: 'hunter2', reason: 'Initial intake' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(endpoints.postCustodySeal).toHaveBeenCalledTimes(3))
    expect(endpoints.postCustodySeal.mock.calls[2][0].idempotency_key).not.toBe(firstKey)
  })

  it('renders a path-free recoverable operation state and exact next action', async () => {
    seed({
      status: 'unsealed',
      unregistered: [],
      incomplete_operation: {
        operation_id: 'op-1',
        action: 'ADD_SEAL',
        phase: 'REQUESTED',
      },
    })
    render(<EvidenceTab />)

    const notice = await screen.findByRole('region', { name: 'Incomplete custody operation' })
    expect(within(notice).getByText('State: REQUESTED')).toBeInTheDocument()
    expect(within(notice).getByText(/Retry Add & Seal to continue/i)).toBeInTheDocument()
    expect(notice).not.toHaveTextContent('evidence/')
  })

  it.each(['REQUESTED', 'PROTECTED'])(
    'resumes the same server operation after a fresh component state in %s',
    async (phase) => {
      const operation = { operation_id: '33333333-3333-3333-3333-333333333333', action: 'ADD_SEAL', phase }
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
    },
  )
})

// ── 2. Resolve findings (D4 — unified batch, heterogeneous verbs) ───────────
describe('Resolve findings flow', () => {
  beforeEach(() =>
    seed({
      status: 'violated',
      missing: ['evidence/lost.img'],
      unregistered: ['evidence/temp.log'],
      write_protected: true,
    }),
  )

  it('selects a missing file and a pending file into one batch and resolves both under one password', async () => {
    endpoints.postCustodyResolve.mockResolvedValue({
      receipts: [
        { action: 'RETIRE', receipt_id: 'r1', audit_id: 'a1', gate_state: 'OPEN' },
        { action: 'IGNORE', receipt_id: 'r2', audit_id: 'a2', gate_state: 'OPEN' },
      ],
    })
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select evidence/lost.img to retire' }))
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select evidence/temp.log to ignore' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Resolve Selected' }))

    const modal = await screen.findByRole('dialog')
    // Honest verbs surfaced per target — not a generic bulk action.
    expect(within(modal).getByText('evidence/lost.img')).toBeInTheDocument()
    expect(within(modal).getByText('RETIRE')).toBeInTheDocument()
    expect(within(modal).getByText('evidence/temp.log')).toBeInTheDocument()
    expect(within(modal).getByText('IGNORE')).toBeInTheDocument()

    // Gate: empty required fields → endpoint NOT called.
    fireEvent.click(within(modal).getByRole('button', { name: 'Resolve' }))
    expect(endpoints.postCustodyResolve).not.toHaveBeenCalled()

    fillModal({ reason: 'Post-triage disposition', password: 'pw' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Resolve' }))

    await waitFor(() => {
      expect(endpoints.postCustodyResolve).toHaveBeenCalledWith({
        password: 'pw',
        reason: 'Post-triage disposition',
        batch_key: expect.any(String),
        dispositions: expect.arrayContaining([
          { verb: 'RETIRE', target: 'evidence/lost.img' },
          { verb: 'IGNORE', target: 'evidence/temp.log' },
        ]),
      })
    })
    expect(await within(modal).findByText(/Resolved 2 finding/i)).toBeInTheDocument()
  })

  it('renders the modal error banner when postCustodyResolve rejects (the ?mock=1 no-backend path)', async () => {
    endpoints.postCustodyResolve.mockRejectedValue(new Error('Resolve endpoint unavailable'))
    render(<EvidenceTab />)

    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select evidence/lost.img to retire' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Resolve Selected' }))
    const modal = await screen.findByRole('dialog')
    fillModal({ reason: 'x', password: 'pw' })
    fireEvent.click(within(modal).getByRole('button', { name: 'Resolve' }))

    expect(await within(modal).findByText('Resolve endpoint unavailable')).toBeInTheDocument()
  })

  it('deselecting a checkbox drops it from the next batch', async () => {
    render(<EvidenceTab />)

    const checkbox = await screen.findByRole('checkbox', { name: 'Select evidence/lost.img to retire' })
    fireEvent.click(checkbox)
    expect(await screen.findByRole('button', { name: 'Resolve Selected' })).toBeInTheDocument()

    fireEvent.click(checkbox)
    expect(screen.queryByRole('button', { name: 'Resolve Selected' })).not.toBeInTheDocument()
  })
})

// ── 3. Full database-custody verification ─────────────────────────────────
describe('Full Verify Evidence flow', () => {
  beforeEach(() => seed({
    status: 'ok',
    seal_status: 'sealed',
    manifest_version: 1,
    active_count: 1,
    verification_needed: true,
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
})

// ── Evidence version history (append-only, path-free) ───────────────────────
describe('Evidence version history flow', () => {
  beforeEach(() => seed({ status: 'sealed', ok: [], write_protected: true }))

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

// ── 4. Per-item Verify (registered table) ────────────────────────────────────
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

// ── 5. Anchor ────────────────────────────────────────────────────────────────
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

// ── 6. Proof export (DB authority only) ──────────────────────────────────────
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

// ── 7. Refresh custody status (CP3 — single reconcile trigger) ───────────────
describe('Refresh custody status', () => {
  it('reconciles via ONE target custody-status call, then reads legacy passively', async () => {
    seed({ status: 'ok', authority: 'db', unregistered: [] })
    render(<EvidenceTab />)
    // Let mount-time passive refreshData settle, then isolate the Refresh click.
    await waitFor(() => expect(endpoints.getEvidence).toHaveBeenCalled())
    endpoints.getCustodyStatus.mockClear()
    endpoints.getChainStatus.mockClear()
    endpoints.getEvidence.mockClear()

    fireEvent.click(screen.getAllByRole('button', { name: /Refresh custody status/i })[0])

    // Exactly one reconciliation trigger — the target custody-status route.
    await waitFor(() => expect(endpoints.getCustodyStatus).toHaveBeenCalledTimes(1))
    // The legacy reads run passively (no args) — they never reconcile.
    await waitFor(() => expect(endpoints.getChainStatus).toHaveBeenCalled())
    expect(endpoints.getEvidence).toHaveBeenCalled()
    expect(endpoints.getChainStatus.mock.calls.every((c) => c.length === 0)).toBe(true)
    expect(endpoints.getEvidence.mock.calls.every((c) => c.length === 0)).toBe(true)
  })
})
