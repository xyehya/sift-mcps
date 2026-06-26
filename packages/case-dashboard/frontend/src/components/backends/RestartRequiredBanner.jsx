import { AlertTriangle } from 'lucide-react'

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip'

// ─────────────────────────────────────────────────────────────────────────
// RestartRequiredInline — inline header indicator (contract §C "Backends —
// header"): when any registry row has pending_apply, a compact amber pill sits
// on the SAME horizontal level as the Scan button, just before it. The exact
// systemctl guidance moves into the tooltip so the header stays uncluttered.
// Renders nothing when there is nothing pending.
// ─────────────────────────────────────────────────────────────────────────

export function RestartRequiredInline({ pendingCount }) {
  if (!pendingCount) return null
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          role="status"
          aria-label={`Restart required to apply ${pendingCount} pending backend change${
            pendingCount === 1 ? '' : 's'
          }`}
          className="inline-flex items-center gap-1.5 rounded-full border border-status-pending/40 bg-status-pending/10 px-2.5 py-1 text-[11px] font-semibold text-status-pending"
        >
          <AlertTriangle className="size-3.5 shrink-0" aria-hidden />
          Restart required to apply ({pendingCount})
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs text-balance">
        {pendingCount} backend{pendingCount === 1 ? '' : 's'} {pendingCount === 1 ? 'was' : 'were'}{' '}
        registered or changed but {pendingCount === 1 ? 'is' : 'are'} not yet loaded into the
        running gateway. Run{' '}
        <span className="mono">sudo systemctl restart sift-gateway</span> on the SIFT VM, then Scan.
      </TooltipContent>
    </Tooltip>
  )
}
