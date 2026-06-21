import { UserCog } from 'lucide-react'

// ─────────────────────────────────────────────────────────────────────────
// AccountSection — RBAC-aware account read-out for the signed-in operator.
// Shows the examiner identity + role (from the store user). The role badge
// signals write access (examiner) vs read-only (analyst), so the operator knows
// why the credential-issue + revoke controls are or aren't available.
// ─────────────────────────────────────────────────────────────────────────

export function AccountSection({ user }) {
  const role = user?.role || 'unknown'
  const canWrite = role === 'examiner'
  return (
    <div className="rounded-lg border border-border-faint bg-card p-4">
      <p className="mono mb-3 text-[10px] font-semibold uppercase tracking-[.1em] text-muted-foreground">
        Account
      </p>
      <div className="flex items-center gap-3">
        <div className="flex size-9 items-center justify-center rounded-full border border-border-soft bg-bg-raised text-muted-foreground">
          <UserCog className="size-4" aria-hidden />
        </div>
        <div className="flex flex-col">
          <span className="text-[13px] font-semibold text-foreground">{user?.examiner || 'Not signed in'}</span>
          <span className="mono flex items-center gap-2 text-[10px] text-muted-foreground">
            <span
              className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[.1em] ${
                canWrite
                  ? 'border-jade/30 bg-jade/10 text-status-approved'
                  : 'border-border-soft bg-bg-raised text-muted-foreground'
              }`}
            >
              {role}
            </span>
            {canWrite ? 'write access' : 'read-only'}
          </span>
        </div>
      </div>
    </div>
  )
}
