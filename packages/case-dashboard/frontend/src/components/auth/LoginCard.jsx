import { useState } from 'react'

import { getMe, postForcedReset, postSupabaseLogin } from '@/api/endpoints'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'

// ─────────────────────────────────────────────────────────────────────────
// LoginCard — behavior-preserving port (spec §6). Supabase email/password is
// the only login path (B-MVP-011): the server validates against Supabase Auth
// and sets a signed HttpOnly session cookie; the browser never receives,
// stores, or displays any JWT/refresh token. WI6 forced first-login reset is
// preserved. onLogin(principal) hands the session up to AuthProvider.
// ─────────────────────────────────────────────────────────────────────────

// WI6 — forced first-login reset (temporary installer password → permanent).
function ResetPasswordForm({ onSession, onNeedLogin }) {
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)

  async function submit(e) {
    e.preventDefault()
    if (password !== confirm) {
      setErr('Passwords do not match.')
      return
    }
    if (password.length < 8) {
      setErr('Password must be at least 8 characters.')
      return
    }
    setLoading(true)
    setErr('')
    try {
      await postForcedReset({ new_password: password })
      // Changing the password usually invalidates the temporary session; try to
      // reuse the cookie, otherwise route back to sign-in with the new password.
      let session = null
      try {
        session = await getMe()
      } catch {
        session = null
      }
      if (session) {
        onSession(session)
        return
      }
      onNeedLogin('Password set. Sign in with your new password.')
    } catch (ex) {
      console.error('Password reset failed:', ex)
      setErr('Password reset failed. The temporary session may have expired — sign in again with the installer password.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={submit} className="flex flex-col gap-4">
      <div className="flex flex-col gap-1">
        <p className="mono text-xs uppercase tracking-widest text-primary">protocol sift gateway</p>
        <h1 className="text-xl font-semibold text-foreground">Set your password</h1>
        <p className="text-sm text-muted-foreground">
          First sign-in detected. Choose a permanent password to activate the account.
        </p>
      </div>
      <Alert>
        <AlertTitle>Where did the temporary password come from?</AlertTitle>
        <AlertDescription>
          The installer stored it in <span className="mono">/var/lib/sift/tokens/installer-handoff.txt</span> on the
          SIFT VM. Once you set a new password it is no longer recoverable from that file.
        </AlertDescription>
      </Alert>
      {err && (
        <p role="alert" aria-live="assertive" className="text-sm text-destructive">
          {err}
        </p>
      )}
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="reset-new">New password</Label>
        <Input id="reset-new" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="reset-confirm">Confirm password</Label>
        <Input id="reset-confirm" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
      </div>
      <Button type="submit" disabled={loading} className="w-full">
        {loading ? 'Updating…' : 'Set password and continue'}
      </Button>
    </form>
  )
}

export function LoginCard({ onLogin }) {
  const [phase, setPhase] = useState('login') // 'login' | 'reset'
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [err, setErr] = useState('')
  const [notice, setNotice] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleLogin(e) {
    e.preventDefault()
    setLoading(true)
    setErr('')
    try {
      const result = await postSupabaseLogin({ email, password })
      if (!result) {
        setErr('Authentication failed. Check your email and password.')
        return
      }
      if (result?.error) {
        setErr(result.error)
        return
      }
      if (result?.must_reset) {
        setPhase('reset')
        return
      }
      onLogin(result)
    } catch (ex) {
      console.error('Login failed:', ex)
      // 503 → the control plane (Supabase) is unreachable.
      const msg =
        ex?.status === 503
          ? ex?.message || 'Control plane unavailable — the gateway cannot reach Supabase Auth. Check the control plane and retry.'
          : 'Authentication failed. Check your email and password.'
      setErr(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-4">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle className="sr-only">Examiner Portal sign in</CardTitle>
        </CardHeader>
        <CardContent>
          {phase === 'reset' ? (
            <ResetPasswordForm
              onSession={onLogin}
              onNeedLogin={(msg) => {
                setPhase('login')
                setNotice(msg)
                setPassword('')
              }}
            />
          ) : (
            <form onSubmit={handleLogin} className="flex flex-col gap-4">
              <div className="flex flex-col gap-1">
                <p className="mono text-xs uppercase tracking-widest text-primary">protocol sift gateway</p>
                <h1 className="text-2xl font-semibold text-foreground">Examiner Portal</h1>
                <p className="text-sm text-muted-foreground">Sign in with your Supabase operator email and password.</p>
              </div>
              {notice && (
                <p aria-live="polite" className="text-sm text-status-approved">
                  {notice}
                </p>
              )}
              {err && (
                <p role="alert" aria-live="assertive" className="text-sm text-destructive">
                  {err}
                </p>
              )}
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="login-email">Email</Label>
                <Input id="login-email" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="login-password">Password</Label>
                <Input id="login-password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
              </div>
              <Button type="submit" disabled={loading} className="w-full">
                {loading ? 'Authenticating…' : 'Sign in'}
              </Button>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
