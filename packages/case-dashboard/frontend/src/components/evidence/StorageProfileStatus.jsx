import { HardDrive, Network } from 'lucide-react'

import { Button } from '@/components/ui/button'

function profileLabel(profile) {
  if (profile === 'LOCAL_IMMUTABLE') return 'Local immutable'
  if (profile === 'EXTERNALLY_READ_ONLY') return 'Externally read-only'
  return 'Storage profile unavailable'
}

export function StorageProfileStatus({ chainStatus, onChange }) {
  if (!chainStatus) return null
  const profile = chainStatus.storage_profile
  const external = profile === 'EXTERNALLY_READ_ONLY'
  const local = profile === 'LOCAL_IMMUTABLE'
  const knownProfile = external || local
  const target = external ? 'LOCAL_IMMUTABLE' : 'EXTERNALLY_READ_ONLY'
  const authorizeSource = external && (
    chainStatus.storage_availability === 'IDENTITY_DRIFT'
    || chainStatus.storage_remediation === 'AUTHORIZE_SOURCE_CHANGE'
  )
  const Icon = external ? Network : HardDrive
  return (
    <section aria-label="Evidence storage profile" className="rounded-xl border border-border-soft bg-card p-4">
      <div className="flex items-center justify-between gap-4">
        <div className="flex min-w-0 items-start gap-3">
          <Icon className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
          <div>
            <div className="mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              Storage profile
            </div>
            <div className="mt-1 text-sm font-semibold text-foreground">
              {profileLabel(profile)}
            </div>
            <p className="mt-1 text-xs text-muted-foreground">
              State: {chainStatus.storage_availability || 'UNAVAILABLE'} · Remediation:{' '}
              {chainStatus.storage_remediation || 'FULL_VERIFY'}
            </p>
            <p className="mono mt-1 text-[10px] text-muted-foreground">
              Last full verify: {chainStatus.storage_last_full_verified_at || 'never'}
            </p>
          </div>
        </div>
        {knownProfile && (
          <div className="flex shrink-0 flex-col gap-2">
            {authorizeSource && (
              <Button type="button" variant="destructive" size="sm" onClick={() => onChange('EXTERNALLY_READ_ONLY')}>
                Authorize current source
              </Button>
            )}
            <Button type="button" variant="outline" size="sm" onClick={() => onChange(target)}>
              Change profile
            </Button>
          </div>
        )}
      </div>
    </section>
  )
}
