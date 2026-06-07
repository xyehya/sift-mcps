import { useState, useEffect } from 'react'
import {
  getChallenge,
  getMe,
  postSupabaseLogin,
  postResetPassword,
  getSetupRequired,
  postSetup,
} from '../../api/endpoints'
import { computeChallengeResponse } from '../../api/crypto'

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

function SetupForm({ onDone }) {
  const [examiner, setExaminer] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)

  async function submit(e) {
    e.preventDefault()
    if (password !== confirm) { setErr('Passwords do not match'); return }
    setLoading(true)
    setErr('')
    try {
      await postSetup({ examiner, password })
      onDone()
    } catch (ex) {
      console.error('Setup failed:', ex)
      setErr('Setup failed — please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <div>
        <h1 className="font-display font-bold text-xl text-text-bright">First-time setup</h1>
        <p className="text-text-muted text-xs mt-1">Create the examiner account to begin.</p>
      </div>
      {err && <p className="text-crimson text-xs">{err}</p>}
      <Input label="Examiner ID" value={examiner} onChange={setExaminer} autoComplete="username" />
      <Input label="Password" type="password" value={password} onChange={setPassword} autoComplete="new-password" />
      <Input label="Confirm password" type="password" value={confirm} onChange={setConfirm} autoComplete="new-password" />
      <button type="submit" disabled={loading} className="w-full py-2 rounded bg-cyan text-bg-base font-sans font-semibold text-sm hover:opacity-90 transition-opacity disabled:opacity-50">
        {loading ? 'Creating…' : 'Create account'}
      </button>
    </form>
  )
}

function ResetPasswordForm({ examiner, currentPassword, onDone }) {
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
      const challenge = await getChallenge(examiner)
      const response = await computeChallengeResponse(currentPassword, challenge)
      await postResetPassword({ challenge_id: challenge.challenge_id, response, new_password: password })
      const session = await getMe()
      if (!session) { setErr('Password reset succeeded. Sign in again.'); return }
      onDone(session)
    } catch (ex) {
      console.error('Password reset failed:', ex)
      setErr('Password reset failed. Check the current password and try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      <div>
        <p className="font-mono text-cyan text-xs tracking-widest uppercase mb-2">sift-mcps</p>
        <h1 className="font-display font-extrabold text-2xl text-text-bright">Reset password</h1>
        <p className="text-text-muted text-xs mt-1">Set a new examiner password before using the portal.</p>
      </div>
      {err && <p className="text-crimson text-xs">{err}</p>}
      <Input label="New password" type="password" value={password} onChange={setPassword} autoComplete="new-password" />
      <Input label="Confirm password" type="password" value={confirm} onChange={setConfirm} autoComplete="new-password" />
      <button type="submit" disabled={loading} className="w-full py-2 rounded bg-cyan text-bg-base font-sans font-semibold text-sm hover:opacity-90 transition-opacity disabled:opacity-50">
        {loading ? 'Updating…' : 'Update password'}
      </button>
    </form>
  )
}

export function LoginCard({ onLogin }) {
  const [phase, setPhase] = useState('checking')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    getSetupRequired()
      .then((data) => setPhase((data?.setup_required ?? data?.required) ? 'setup' : 'login'))
      .catch(() => setPhase('login'))
  }, [])

  // PR03A — email/password Supabase login. The server validates the password
  // against Supabase Auth and sets a signed, HttpOnly session cookie. The
  // browser never receives, displays, or stores any JWT or refresh token.
  async function handleLogin(e) {
    e.preventDefault()
    setLoading(true)
    setErr('')
    try {
      const result = await postSupabaseLogin({ email, password })
      if (!result) { setErr('Authentication failed. Check your email and password.'); return }
      if (result?.error) { setErr(result.error); return }
      onLogin(result)
    } catch (ex) {
      console.error('Login failed:', ex)
      setErr('Authentication failed. Check your email and password.')
    } finally {
      setLoading(false)
    }
  }

  if (phase === 'checking') return null

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg-base">
      <div className="w-full max-w-sm p-8 rounded-lg border border-border-soft bg-bg-surface">
        {phase === 'setup' ? (
          <SetupForm onDone={() => setPhase('login')} />
        ) : phase === 'reset' ? (
          <ResetPasswordForm examiner={email} currentPassword={password} onDone={onLogin} />
        ) : (
          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <p className="font-mono text-cyan text-xs tracking-widest uppercase mb-2">sift-mcps</p>
              <h1 className="font-display font-extrabold text-2xl text-text-bright">Examiner Portal</h1>
              <p className="text-text-muted text-xs mt-1">Sign in with your Supabase email and password.</p>
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
