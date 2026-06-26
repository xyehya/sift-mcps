import { CheckCircle2, AlertTriangle } from 'lucide-react'

import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { formatTime } from './evidence-utils'

// ─────────────────────────────────────────────────────────────────────────
// HmacBar — full-width integrity reminder bar (legacy IA parity §2). When
// hmac_verify_needed it shows an amber "overdue / never verified" message and a
// "Verify Now" CTA; otherwise a jade "verified" line (with last-verified
// timestamp / examiner) and a "Re-verify" CTA. Opens the verify_hmac modal.
// ─────────────────────────────────────────────────────────────────────────

export function HmacBar({ chainStatus, onVerifyClick }) {
  if (!chainStatus) return null
  const needed = chainStatus.hmac_verify_needed
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
            ? chainStatus.hmac_last_verified_at
              ? `Evidence chain HMAC verification is overdue (last: ${formatTime(chainStatus.hmac_last_verified_at)}).`
              : 'Evidence chain HMAC has never been verified.'
            : `Evidence chain HMAC verified${
                chainStatus.hmac_last_verified_at
                  ? ` — last verified ${formatTime(chainStatus.hmac_last_verified_at)}`
                  : ''
              }${chainStatus.hmac_last_verified_by ? ` by ${chainStatus.hmac_last_verified_by}` : ''}.`}
        </span>
      </div>

      <Button
        type="button"
        variant="outline"
        size="xs"
        onClick={onVerifyClick}
        className={cn(
          'mono shrink-0 text-[11px] font-semibold',
          needed
            ? 'text-status-pending border-status-pending/40 hover:bg-status-pending/10'
            : 'text-status-approved border-status-approved/40 hover:bg-status-approved/10',
        )}
      >
        {needed ? 'Verify Now' : 'Re-verify'}
      </Button>
    </div>
  )
}
