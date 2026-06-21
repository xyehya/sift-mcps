import { displayHost } from '@/components/common/entity-utils'

// ─────────────────────────────────────────────────────────────────────────
// IOC helpers — pure filter/derivation logic (no JSX, no store) so the IOC
// filter surface is unit-testable in isolation. Mirrors the legacy IocsTab
// behaviour: category from data, status DRAFT/APPROVED/REJECTED, and a
// value/id/type free-text search.
// ─────────────────────────────────────────────────────────────────────────

/** Distinct, sorted, non-empty category values present in the IOC set. */
export function iocCategories(iocs) {
  const cats = new Set()
  for (const ioc of iocs ?? []) {
    const cat = (ioc.category ?? '').trim()
    if (cat) cats.add(cat)
  }
  return [...cats].sort()
}

/** Filter IOCs by category + status + free-text (value/id/type). Parity port. */
export function filterIocs(iocs, { category = 'all', status = 'all', search = '' } = {}) {
  let list = iocs ?? []
  if (category !== 'all') list = list.filter((ioc) => (ioc.category ?? '') === category)
  if (status !== 'all') list = list.filter((ioc) => (ioc.status ?? '') === status)
  if (search) {
    const q = search.toLowerCase()
    list = list.filter(
      (ioc) =>
        (ioc.value ?? '').toLowerCase().includes(q) ||
        (ioc.id ?? '').toLowerCase().includes(q) ||
        (ioc.type ?? '').toLowerCase().includes(q),
    )
  }
  return list
}

/** Distinct hosts an IOC was sighted on (from its `sightings`), uppercased. */
export function iocHosts(ioc) {
  return [...new Set((ioc?.sightings ?? []).map((s) => s.host).filter(Boolean))].map(displayHost)
}

/** Status → shared EntityBadge tone key. */
export function iocStatusTone(status) {
  const s = (status ?? '').toUpperCase()
  if (s === 'APPROVED') return 'approved'
  if (s === 'REJECTED') return 'rejected'
  if (s === 'DRAFT') return 'pending'
  return 'muted'
}
