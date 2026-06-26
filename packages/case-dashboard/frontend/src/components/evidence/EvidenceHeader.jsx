import { RefreshCw } from 'lucide-react'

import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { sealBadgeClass } from './evidence-utils'

// ─────────────────────────────────────────────────────────────────────────
// EvidenceHeader — "Evidence Chain" title + seal/custody authority badge +
// Rescan. Single-column custody-dashboard header (legacy IA parity §1).
// The seal badge reads chainStatus.(seal_status||status), appends ·v{version}
// and ·db when authority==='db', and explains the authority source via title.
// ─────────────────────────────────────────────────────────────────────────

export function EvidenceHeader({ chainStatus, onRescan }) {
  const sealState = chainStatus?.seal_status ?? chainStatus?.status

  return (
    <header className="flex items-center justify-between gap-3 border-b border-border-faint pb-3">
      <div className="flex items-center gap-2">
        <h1 className="font-display text-lg font-bold text-foreground">Evidence Chain</h1>

        {chainStatus && sealState && (
          <span
            data-testid="seal-status-badge"
            title={
              chainStatus.authority === 'db'
                ? 'Seal status from Postgres custody authority'
                : 'Seal status from file manifest'
            }
            className={cn(
              'mono rounded border border-border-soft bg-secondary px-2 py-0.5 text-[10px] uppercase tracking-wider',
              sealBadgeClass(sealState),
            )}
          >
            {sealState}
            {chainStatus.manifest_version != null ? ` · v${chainStatus.manifest_version}` : ''}
            {chainStatus.authority === 'db' ? ' · db' : ''}
          </span>
        )}
      </div>

      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={onRescan}
        className="mono gap-1.5 text-xs"
      >
        <RefreshCw className="size-3.5" aria-hidden />
        Rescan
      </Button>
    </header>
  )
}
