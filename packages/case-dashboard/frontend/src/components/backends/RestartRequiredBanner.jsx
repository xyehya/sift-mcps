import { AlertTriangle } from 'lucide-react'

// ─────────────────────────────────────────────────────────────────────────
// RestartRequiredBanner — surfaced when any registry row has pending_apply
// (registered/changed but not yet loaded into the running gateway). Legacy IA
// parity §2: amber banner with the pending count + the exact systemctl
// guidance. Renders nothing when there is nothing pending.
// ─────────────────────────────────────────────────────────────────────────

export function RestartRequiredBanner({ pendingCount }) {
  if (!pendingCount) return null
  return (
    <div
      role="status"
      className="flex items-start gap-2.5 rounded-lg border border-status-pending/40 bg-status-pending/10 px-3 py-2.5 text-xs leading-relaxed text-foreground"
    >
      <AlertTriangle className="mt-0.5 size-4 shrink-0 text-status-pending" aria-hidden />
      <div>
        <span className="font-semibold text-status-pending">Restart required to apply.</span>{' '}
        {pendingCount} backend{pendingCount === 1 ? '' : 's'} {pendingCount === 1 ? 'was' : 'were'}{' '}
        registered or changed but {pendingCount === 1 ? 'is' : 'are'} not yet loaded into the running
        gateway. Run{' '}
        <code className="mono rounded bg-bg-raised px-1 py-0.5 text-[11px]">
          sudo systemctl restart sift-gateway
        </code>{' '}
        on the SIFT VM, then Refresh.
      </div>
    </div>
  )
}
