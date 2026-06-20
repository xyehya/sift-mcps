import { useCallback, useEffect, useState } from 'react'

import { onUnauthorized } from '@/api/client'
import { getMe, postLogout } from '@/api/endpoints'
import { useStore } from '@/store/useStore'
import { AuthContext } from '@/lib/auth-context'

// ─────────────────────────────────────────────────────────────────────────
// Behavior-preserving port of the old App.jsx auth gate (spec §6 contract):
//   • On mount, call getMe(). A session envelope cookie (HttpOnly, server-set)
//     authenticates the request — no token ever lives in JS. getMe() returns
//     the principal on success, or null on 401 (apiFetch emits the unauthorized
//     event and resolves null when not suppressed).
//   • Any later 401 from any request fires the 'sift:unauthorized' window event;
//     we listen and drop back to the login screen (session-expiry redirect).
//   • login(result): a successful Supabase login/forced-reset hands us the
//     principal; we cache it and flip to 'authed'.
//   • logout(): best-effort server logout, then clear local state.
// The user principal is mirrored into the zustand store (store.user) because
// feature components + RBAC checks read it from there.
// ─────────────────────────────────────────────────────────────────────────

export function AuthProvider({ children }) {
  const setStoreUser = useStore((state) => state.setUser)
  const [user, setUser] = useState(null)
  // 'checking' until the initial getMe() resolves, then 'authed' | 'unauthed'.
  const [status, setStatus] = useState('checking')

  const applyUser = useCallback(
    (principal) => {
      setUser(principal)
      setStoreUser(principal)
    },
    [setStoreUser],
  )

  // Initial session probe.
  useEffect(() => {
    let active = true
    getMe()
      .then((data) => {
        if (!active) return
        if (data) {
          applyUser(data)
          setStatus('authed')
        } else {
          setStatus('unauthed')
        }
      })
      .catch(() => {
        if (active) setStatus('unauthed')
      })
    return () => {
      active = false
    }
  }, [applyUser])

  // Session-expiry redirect: any 401 anywhere drops us to the login screen.
  useEffect(() => {
    return onUnauthorized(() => {
      applyUser(null)
      setStatus('unauthed')
    })
  }, [applyUser])

  const login = useCallback(
    (result) => {
      applyUser(result)
      setStatus('authed')
    },
    [applyUser],
  )

  const logout = useCallback(() => {
    // Best-effort server logout; clear local state regardless of network result.
    postLogout().catch(() => {})
    applyUser(null)
    setStatus('unauthed')
  }, [applyUser])

  const value = { status, user, login, logout }
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
