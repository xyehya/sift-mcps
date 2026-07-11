// Commit failures can include server-side implementation detail. Keep the
// operator-facing copy status-specific, actionable, and safe to render.
const COMMIT_FAILURES = {
  400: 'Commit request was invalid. Reopen the drawer and try again.',
  401: 'Password confirmation failed. Check your password and try again.',
  403: 'Commit authorization was denied. Confirm your account can commit and complete any required password reset.',
  429: 'Too many commit attempts. Wait before trying again; your staged changes remain available.',
  503: 'Commit authorization is temporarily unavailable. Your staged changes remain available; try again shortly.',
}

const DEFAULT_FAILURE = 'Commit could not be completed. Your staged changes remain available; retry or contact an administrator.'

export function commitFailureMessage(error) {
  return COMMIT_FAILURES[error?.status] ?? DEFAULT_FAILURE
}
