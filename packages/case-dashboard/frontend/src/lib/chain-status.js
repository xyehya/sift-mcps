// Evidence-chain seal status derivation (ported from old StatusBar.jsx +
// covered by SessionChanges B-03 logic). Centralised so the Header pill and the
// StatusBar render identical semantics.
//
// Field contract (preserve exactly — SessionChanges B-03 pins these names):
//   chainStatus.status            'ok' | 'unsealed' | 'violation' | …
//   chainStatus.manifest_version  > 0 once sealed
//   chainStatus.hmac_verify_needed
//   chainStatus.write_protected

/**
 * deriveSeal(chainStatus) → { label, tone }
 *   tone ∈ 'loading' | 'sealed' | 'pending' | 'unsealed' | 'violation'
 * tone maps to a forensic-semantic token at the call site (status-* / sev-*).
 */
export function deriveSeal(chainStatus) {
  if (!chainStatus) return { label: 'LOADING', tone: 'loading' }
  if (chainStatus.status === 'violation') return { label: 'VIOLATION', tone: 'violation' }

  const isSealed = chainStatus.status !== 'unsealed' && chainStatus.manifest_version > 0
  if (!isSealed) return { label: 'UNSEALED', tone: 'unsealed' }
  if (chainStatus.hmac_verify_needed) return { label: 'SEALED · verify pending', tone: 'pending' }
  return { label: 'SEALED', tone: 'sealed' }
}

/** Tailwind token classes (text + dot bg) for a seal tone. */
export const SEAL_TONE_CLASS = {
  loading: 'text-muted-foreground',
  sealed: 'text-status-approved',
  pending: 'text-status-pending',
  unsealed: 'text-destructive',
  violation: 'text-destructive',
}

export const SEAL_DOT_CLASS = {
  loading: 'bg-muted-foreground',
  sealed: 'bg-status-approved',
  pending: 'bg-status-pending',
  unsealed: 'bg-destructive',
  violation: 'bg-destructive',
}
