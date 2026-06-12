import { useState } from 'react'
import {
  getMe,
  postSupabaseLogin,
  postForcedReset,
} from '../../api/endpoints'

function Input({ label, value, onChange, type = 'text', autoComplete }) {
  return (
    <label className="block">
      <span className="block text-text-muted text-xs font-sans font-medium uppercase tracking-wider mb-1">{label}</span>
      <input
        type={type}
        value={value}
        autoComplete={autoComplete}
        onChange={(e) => onChange(e.target.value)}
        className="w-full px-3 py-2 rounded bg-bg-raised border border-border-soft text-text-bright text-sm font-sans focus:border-cyan focus:outline-none transition-colors"
        required
      />
    </label>
  )
}

// WI6 — forced first-login reset. Explains where the temporary password came
// from (installer handoff file) and that it is unrecoverable once replaced.
function ResetPasswordForm({ onDone }) {
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)

  async function submit(e) {
    e.preventDefault()
    if (password !== confirm) { setErr('Passwords do not match'); return }
    if (password.length < 8) { setErr('Password must be at least 8 characters.'); return }
    setLoading(true)
    setErr('')
    try {
      await postForcedReset({ new_password: password })
      const session = await getMe()
      if (!session) { setErr('Password reset succeeded. Sign in again.'); return }
      onDone(session)
    } catch (ex) {
      console.error('Password reset failed:', ex)
      setErr('Password reset failed. The temporary session may have expired — sign in again with the installer password.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <div>
        <p className="font-mono text-cyan text-xs tracking-widest uppercase mb-2">protocol sift gateway</p>
        <h1 className="font-display font-extrabold text-2xl text-text-bright">Set your password</h1>
        <p className="text-text-muted text-xs mt-1">
          First sign-in detected. You logged in with the one-time temporary
          password the installer wrote to the operator handoff file. Choose a
          permanent password to activate the account.
        </p>
      </div>
      <div
        className="rounded border px-3 py-2.5 text-[11px] leading-relaxed font-sans"
        style={{ background: 'var(--amber-dim)', borderColor: 'var(--amber)', color: 'var(--text-bright)' }}
      >
        <span className="font-semibold" style={{ color: 'var(--amber)' }}>Where did the temporary password come from?</span>
        <span className="block mt-1" style={{ color: 'var(--text-primary)' }}>
          The installer stored it in <span className="font-mono">/var/lib/sift/tokens/installer-handoff.txt</span> on
          the SIFT VM. Once you set a new password it is no longer recoverable
          from that file — rotate it through Supabase if it is ever lost.
        </span>
      </div>
      {err && <p className="text-crimson text-xs">{err}</p>}
      <Input label="New password" type="password" value={password} onChange={setPassword} autoComplete="new-password" />
      <Input label="Confirm password" type="password" value={confirm} onChange={setConfirm} autoComplete="new-password" />
      <button type="submit" disabled={loading} className="w-full py-2 rounded bg-cyan text-bg-base font-sans font-semibold text-sm hover:opacity-90 transition-opacity disabled:opacity-50">
        {loading ? 'Updating…' : 'Set password and continue'}
      </button>
    </form>
  )
}

// B-MVP-011 — Supabase Auth is the only login path. There is no local
// examiner.json setup/challenge fallback; the SPA goes straight to the
// email/password sign-in form.
export function LoginCard({ onLogin }) {
  const [phase, setPhase] = useState('login') // 'login' | 'reset'
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)

  // Supabase email/password login. The server validates the password against
  // Supabase Auth and sets a signed, HttpOnly session cookie. The browser never
  // receives, displays, or stores any JWT or refresh token.
  async function handleLogin(e) {
    e.preventDefault()
    setLoading(true)
    setErr('')
    try {
      const result = await postSupabaseLogin({ email, password })
      if (!result) { setErr('Authentication failed. Check your email and password.'); return }
      if (result?.error) { setErr(result.error); return }
      if (result?.must_reset) { setPhase('reset'); return }
      onLogin(result)
    } catch (ex) {
      console.error('Login failed:', ex)
      // 503 from the server means the control plane (Supabase) is unreachable.
      const msg = ex?.status === 503
        ? (ex?.message || 'Control plane unavailable — the gateway cannot reach Supabase Auth. Check the control plane and retry.')
        : 'Authentication failed. Check your email and password.'
      setErr(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg-base">
      <div className="w-full max-w-sm p-8 rounded-lg border border-border-soft bg-bg-surface">
        {phase === 'reset' ? (
          <ResetPasswordForm onDone={onLogin} />
        ) : (
          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <p className="font-mono text-cyan text-xs tracking-widest uppercase mb-2">protocol sift gateway</p>
              <h1 className="font-display font-extrabold text-2xl text-text-bright">Examiner Portal</h1>
              <p className="text-text-muted text-xs mt-1">Sign in with your Supabase operator email and password.</p>
            </div>
            {err && <p className="text-crimson text-xs">{err}</p>}
            <Input label="Email" type="email" value={email} onChange={setEmail} autoComplete="username" />
            <Input label="Password" type="password" value={password} onChange={setPassword} autoComplete="current-password" />
            <button type="submit" disabled={loading} className="w-full py-2 rounded bg-cyan text-bg-base font-sans font-semibold text-sm hover:opacity-90 transition-opacity disabled:opacity-50">
              {loading ? 'Authenticating…' : 'Sign in'}
            </button>
          </form>
        )}
      </div>
    </div>
  )
}
