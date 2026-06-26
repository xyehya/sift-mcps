// ─────────────────────────────────────────────────────────────────────────
// custody-guard — the shared re-auth guard for ledgered custody mutations.
// Pure (no hooks, no React): given the modal field values + setters, validate
// that a password (and, for ledgered actions, a reason) is present, then prime
// the modal into its loading state. Returns false (and surfaces the error) when
// the gate is not satisfied. Used by every guarded handler in
// useCustodyGuardedActions so the re-auth contract lives in exactly one place.
// ─────────────────────────────────────────────────────────────────────────

export function runGuard({ needReason, modalPassword, modalReason, setModalLoading, setModalError, setModalResult }) {
  if (needReason && !modalReason) {
    setModalError('Reason is required.')
    return false
  }
  if (!modalPassword) {
    setModalError('Password required.')
    return false
  }
  setModalLoading(true)
  setModalError('')
  setModalResult(null)
  return true
}
