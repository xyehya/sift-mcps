import { Lock, ShieldAlert, ShieldCheck, ChevronRight } from 'lucide-react'

import { cn } from '@/lib/utils'
import { useStoreSlice } from '@/store/useStore'
import { navigateToTab } from '@/hooks/useHashRoute'
import { deriveSeal, SEAL_DOT_CLASS, SEAL_TONE_CLASS } from '@/lib/chain-status'
import { Skeleton } from '@/components/ui/skeleton'

// ─────────────────────────────────────────────────────────────────────────
// Evidence chain summary — a compact custody readout derived from the SAME
// chain-status helper the Header pill + StatusBar use (single semantic source).
// Surfaces seal state, manifest version, and write-protection, and deep-links
// to the Evidence tab. Unsealed/violation states carry an explicit warning
// because agent tooling is blocked until the chain is sealed again.
// ─────────────────────────────────────────────────────────────────────────

function Stat({ label, value, valueClass }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[11px] uppercase tracking-wider text-muted-foreground">{label}</span>
      <span className={cn('tnum mono text-sm font-semibold', valueClass)}>{value}</span>
    </div>
  )
}

export function EvidenceChainSummary({ chainStatus, loading }) {
  const { setActiveTab } = useStoreSlice((s) => ({ setActiveTab: s.setActiveTab }))

  if (loading && !chainStatus) {
    return (
      <div className="space-y-3" aria-busy="true">
        <Skeleton className="h-6 w-40" />
        <Skeleton className="h-10 w-full" />
      </div>
    )
  }

  const { label, tone } = deriveSeal(chainStatus)
  const sealed = tone === 'sealed' || tone === 'pending'
  const violation = tone === 'violation'
  const Icon = violation ? ShieldAlert : sealed ? ShieldCheck : Lock

  return (
    <div className="flex flex-col gap-4">
      <button
        type="button"
        onClick={() => navigateToTab(setActiveTab, 'evidence')}
        aria-label="Go to Evidence tab"
        className={cn(
          'flex items-center gap-2 rounded-md border border-border px-3 py-2 text-left transition-colors',
          'hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
        )}
      >
        <Icon className={cn('size-4 shrink-0', SEAL_TONE_CLASS[tone])} aria-hidden />
        <span className={cn('mono text-xs font-semibold', SEAL_TONE_CLASS[tone])}>{label}</span>
        <span aria-hidden className={cn('size-1.5 rounded-full', SEAL_DOT_CLASS[tone])} />
        <ChevronRight className="ml-auto size-4 text-muted-foreground" aria-hidden />
      </button>

      <div className="grid grid-cols-2 gap-4">
        <Stat
          label="Manifest"
          value={chainStatus?.manifest_version > 0 ? `v${chainStatus.manifest_version}` : '—'}
        />
        <Stat
          label="Write-protect"
          value={chainStatus?.write_protected ? 'On' : 'Off'}
          valueClass={chainStatus?.write_protected ? 'text-status-staged' : 'text-muted-foreground'}
        />
      </div>

      {(violation || (chainStatus && !sealed)) && (
        <p role="alert" className={cn('text-xs', violation ? 'text-destructive' : 'text-status-pending')}>
          {violation
            ? 'Integrity violation detected — verify the chain on the Evidence tab.'
            : 'Chain is not sealed. Agent tools stay blocked until evidence is sealed.'}
        </p>
      )}
    </div>
  )
}
