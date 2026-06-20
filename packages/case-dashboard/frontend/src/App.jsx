import { AuthProvider } from '@/lib/auth'
import { useAuth } from '@/lib/auth-context'
import { LoginCard } from '@/components/auth/LoginCard'
import { AppShell } from '@/components/layout/AppShell'

// ─────────────────────────────────────────────────────────────────────────
// App — auth gate (spec §6). AuthProvider owns the session lifecycle (getMe
// probe, 401 → login redirect, login/logout). While the initial probe is in
// flight we render nothing (no flash of either screen); then either the login
// screen or the authenticated AppShell.
// ─────────────────────────────────────────────────────────────────────────

function Gate() {
  const { status, login } = useAuth()
  if (status === 'checking') return null
  if (status !== 'authed') return <LoginCard onLogin={login} />
  return <AppShell />
}

export default function App() {
  return (
    <AuthProvider>
      <Gate />
    </AuthProvider>
  )
}
