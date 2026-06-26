import { useCallback, useState } from 'react'

// ─────────────────────────────────────────────────────────────────────────
// useChallenge — the examiner-password re-auth state machine (legacy IA parity
// §6). openChallenge(title, onConfirm) opens the modal; submit() runs onConfirm
// with { password }, which the endpoint re-verifies server-side against
// Supabase (B-MVP-017). On success the modal closes; on failure the error is
// surfaced in-modal. Confirm stays disabled until a password is entered.
// ─────────────────────────────────────────────────────────────────────────

const CLOSED = { isOpen: false, title: '', error: '', loading: false, password: '', onConfirm: null }

export function useChallenge() {
  const [modal, setModal] = useState(CLOSED)

  const openChallenge = useCallback((title, onConfirm) => {
    setModal({ ...CLOSED, isOpen: true, title, onConfirm })
  }, [])

  const closeChallenge = useCallback(() => setModal(CLOSED), [])

  const setPassword = useCallback((password) => setModal((prev) => ({ ...prev, password })), [])

  async function submit(e) {
    if (e) e.preventDefault()
    const { password, onConfirm } = modal
    if (!password || !onConfirm) return
    setModal((prev) => ({ ...prev, loading: true, error: '' }))
    try {
      await onConfirm({ password })
      setModal(CLOSED)
    } catch (err) {
      setModal((prev) => ({ ...prev, loading: false, error: err.message || 'Password verification failed' }))
    }
  }

  return { modal, openChallenge, closeChallenge, setPassword, submit }
}
