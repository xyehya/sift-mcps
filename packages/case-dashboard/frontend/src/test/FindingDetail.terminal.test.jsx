import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import { FindingDetail } from '../components/findings/FindingDetail'

// P35-1: a committed/terminal finding (no stagedItem, canReview true) must not
// offer Stage/Reject/Approve — it falls into the action-cluster branch because
// it has left the delta, so it must lock read-only instead.

const APPROVED = {
  id: 'F-9',
  status: 'approved',
  confidence: 'HIGH',
  type: 'finding',
  title: 'committed finding',
  observation: 'obs',
  interpretation: 'interp',
  confidence_justification: 'just',
}

const DRAFT = { ...APPROVED, id: 'F-10', status: 'draft', title: 'draft finding' }

function noop() {}

const handlers = {
  addToast: noop,
  onApprove: vi.fn(),
  onStage: vi.fn(),
  onReject: vi.fn(),
  onUnstage: vi.fn(),
  onEdit: vi.fn(),
}

describe('FindingDetail terminal/committed state', () => {
  it('renders read-only lock and NO Stage/Reject/Approve for an approved finding', () => {
    render(<FindingDetail finding={APPROVED} stagedItem={null} canReview {...handlers} />)

    expect(screen.getByText(/committed to record/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^stage$/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^reject$/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^approve$/i })).not.toBeInTheDocument()
  })

  it('still offers Approve/Stage/Reject for a draft finding', () => {
    render(<FindingDetail finding={DRAFT} stagedItem={null} canReview {...handlers} />)

    expect(screen.queryByText(/committed to record/i)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^approve$/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^stage$/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^reject$/i })).toBeInTheDocument()
  })
})
