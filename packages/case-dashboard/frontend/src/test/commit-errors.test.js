import { describe, expect, it } from 'vitest'

import { commitFailureMessage } from '@/lib/commit-errors'

describe('commitFailureMessage', () => {
  it.each([
    [403, 'Commit authorization was denied. Confirm your account can commit and complete any required password reset.'],
    [429, 'Too many commit attempts. Wait before trying again; your staged changes remain available.'],
    [503, 'Commit authorization is temporarily unavailable. Your staged changes remain available; try again shortly.'],
  ])('returns safe, actionable copy for HTTP %i', (status, expected) => {
    expect(commitFailureMessage({ status, message: 'internal implementation detail' })).toBe(expected)
  })

  it('uses a safe generic message for unknown failures without displaying server text', () => {
    const error = { status: 500, message: 'database password at /private/path' }

    expect(commitFailureMessage(error)).toBe(
      'Commit could not be completed. Your staged changes remain available; retry or contact an administrator.',
    )
  })
})
