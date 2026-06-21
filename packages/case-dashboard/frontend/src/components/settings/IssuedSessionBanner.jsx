import { KeyRound, X } from 'lucide-react'

import { formatDateTime, formatTtl } from './settings-utils'

// ─────────────────────────────────────────────────────────────────────────
// IssuedSessionBanner — the issued-once token-material banner (legacy parity).
// Token material is returned exactly once and held in memory only (never
// localStorage). Dismissible. Reskinned to the orange accent (this is the
// primary credential the operator must copy now). The token strings are
// select-all so they can be copied; no value is persisted or logged.
// ─────────────────────────────────────────────────────────────────────────

function Field({ label, value, accent }) {
  return (
    <div>
      <span className="text-muted-foreground">{label}</span>{' '}
      <span className={accent ? 'select-all break-all text-primary' : 'text-foreground'}>{value}</span>
    </div>
  )
}

export function IssuedSessionBanner({ issued, nowMs, onDismiss }) {
  if (!issued) return null
  return (
    <div className="relative mb-4 space-y-2 rounded-lg border border-primary bg-primary/10 p-4 text-xs">
      <button
        type="button"
        onClick={onDismiss}
        aria-label="Dismiss issued session banner"
        className="absolute right-3 top-2 text-primary transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      >
        <X className="size-4" aria-hidden />
      </button>
      <div className="mono flex items-center gap-1.5 text-[13px] font-bold uppercase tracking-[.1em] text-primary">
        <KeyRound className="size-4" aria-hidden />
        New JWT Session Issued
      </div>
      <p className="text-xs leading-relaxed text-muted-foreground">
        Copy these tokens now. They are shown once and cannot be recovered.
      </p>
      <div className="mono space-y-1 break-all rounded-lg border border-border-soft bg-card p-2.5 text-[11px]">
        <Field label="principal:" value={`${issued.principal_type}/${issued.principal_id}`} accent />
        <Field label="token_type:" value="Supabase JWT" />
        <Field label="expires_at:" value={formatDateTime(issued.expires_at)} />
        <Field label="ttl_remaining:" value={formatTtl(issued.expires_at, nowMs)} />
        <Field label="access_token:" value={issued.access_token} accent />
        <Field label="refresh_token:" value={issued.refresh_token} accent />
        <Field label="fingerprint:" value={issued.token_fingerprint} />
      </div>
    </div>
  )
}
