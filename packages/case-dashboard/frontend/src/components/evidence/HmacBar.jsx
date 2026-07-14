import { CheckCircle2, AlertTriangle } from 'lucide-react'

import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { formatTime } from './evidence-utils'

// ─────────────────────────────────────────────────────────────────────────
// FullVerifyBar — full-width database-custody verification reminder. The API
// retains legacy hmac_* timestamp field names for compatibility, but the active
// workflow re-hashes mounted evidence against Postgres authority; it does not
// derive a password key or verify a file ledger.
// ─────────────────────────────────────────────────────────────────────────

export function FullVerifyBar({ chainStatus, onVerifyClick }) {
  if (!chainStatus) return null
  const needed = chainStatus.verification_needed ?? chainStatus.hmac_verify_needed
  const lastVerifiedAt = chainStatus.last_verified_at ?? chainStatus.hmac_last_verified_at
  const lastVerifiedBy = chainStatus.last_verified_by ?? chainStatus.hmac_last_verified_by
  const hasActiveManifest =
    Number(chainStatus.manifest_version || 0) > 0 && Number(chainStatus.active_count || 0) > 0
  const virginExternalBootstrap =
    chainStatus.storage_profile === 'EXTERNALLY_READ_ONLY' && !hasActiveManifest
  const Icon = needed ? AlertTriangle : CheckCircle2

  return (
    <div
      className={cn(
        'flex items-center justify-between gap-3 rounded-lg border p-3 text-xs transition-all',
        needed
          ? 'border-status-pending/25 bg-status-pending/5 text-status-pending'
          : 'border-status-approved/20 bg-status-approved/5 text-status-approved',
      )}
    >
      <div className="flex items-center gap-2">
        <Icon className="size-4 shrink-0" aria-hidden />
        <span>
          {needed
            ? virginExternalBootstrap
              ? 'Add & Seal establishes the first full-hash source and mount receipt. Full Verify becomes available after the active manifest exists.'
              : lastVerifiedAt
              ? `Full evidence verification is overdue (last: ${formatTime(lastVerifiedAt)}).`
              : 'Evidence has not yet been fully verified against database custody authority.'
            : `Evidence fully verified against database custody authority${
                lastVerifiedAt
                  ? ` — last verified ${formatTime(lastVerifiedAt)}`
                  : ''
              }${lastVerifiedBy ? ` by ${lastVerifiedBy}` : ''}.`}
        </span>
      </div>

      <Button
        type="button"
        variant="outline"
        size="xs"
        onClick={onVerifyClick}
        disabled={!hasActiveManifest}
        title={
          hasActiveManifest
            ? undefined
            : 'Add & Seal evidence before running Full Verify Evidence.'
        }
        className={cn(
          'mono shrink-0 text-[11px] font-semibold',
          needed
            ? 'text-status-pending border-status-pending/40 hover:bg-status-pending/10'
            : 'text-status-approved border-status-approved/40 hover:bg-status-approved/10',
        )}
      >
        {needed ? 'Full Verify Evidence' : 'Verify Again'}
      </Button>
    </div>
  )
}
