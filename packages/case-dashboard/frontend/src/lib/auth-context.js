import { createContext, useContext } from 'react'

// Separated from auth.jsx so that auth.jsx only exports components/providers
// (keeps react-refresh fast-refresh happy, mirroring lib/theme-context.js).
// Holds the auth context + hook only.
export const AuthContext = createContext(null)

/**
 * useAuth — read the auth session state.
 *   status:  'checking' | 'authed' | 'unauthed'
 *   user:    the principal record from getMe()/login (role drives RBAC)
 *   login(result):  mark authed after a successful login/reset
 *   logout():       clear the server session + local state
 * Must be used within <AuthProvider>.
 */
export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within an AuthProvider')
  return ctx
}
