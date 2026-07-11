import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { postCommit } from '@/api/endpoints'
import { CommitDrawer } from '@/components/layout/CommitDrawer'
import { useStore } from '@/store/useStore'

vi.mock('@/api/endpoints', () => ({
  deleteDelta: vi.fn(),
  postCommit: vi.fn(),
}))

vi.mock('@/hooks/useDeltaRefetch', () => ({
  useDeltaRefetch: () => vi.fn(),
}))

const STAGED_DELTA = [{ id: 'F-001', action: 'approve' }]

beforeEach(() => {
  vi.useFakeTimers()
  vi.spyOn(console, 'error').mockImplementation(() => {})
  useStore.setState({
    commitDrawerOpen: true,
    delta: STAGED_DELTA,
    findings: [{ id: 'F-001', title: 'Review finding' }],
  })
})

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('CommitDrawer failure feedback', () => {
  it.each([
    [403, 'Commit authorization was denied. Confirm your account can commit and complete any required password reset.'],
    [429, 'Too many commit attempts. Wait before trying again; your staged changes remain available.'],
    [503, 'Commit authorization is temporarily unavailable. Your staged changes remain available; try again shortly.'],
    [500, 'Commit could not be completed. Your staged changes remain available; retry or contact an administrator.'],
  ])('shows sanitized, actionable feedback for HTTP %i', async (status, expected) => {
    postCommit.mockRejectedValueOnce({ status, message: 'internal implementation detail' })
    render(<CommitDrawer />)

    fireEvent.change(screen.getByLabelText('Examiner password'), { target: { value: 'password' } })
    fireEvent.mouseDown(screen.getByRole('button', { name: 'Hold to commit' }))
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3000)
    })

    expect(screen.getByRole('alert')).toHaveTextContent(expected)
    expect(screen.getByRole('alert')).not.toHaveTextContent('internal implementation detail')
  })
})
