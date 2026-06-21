import { Archive, RefreshCw } from 'lucide-react'

import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { SkeletonBlock } from '@/components/common/Skeleton'

// ─────────────────────────────────────────────────────────────────────────
// EvidenceCustodyOps — the operational chain-of-custody panel: HMAC reminder,
// write-block status, Solana anchor, unregistered files, and the registered-
// evidence table with per-item Unseal / Verify actions. This is the port of the
// previous EvidenceTab body; it is rendered as a section inside the new
// design-system EvidenceTab layout so the existing API calls and test
// data-testids (unseal-btn-*, unseal-submit) remain in the DOM.
// ─────────────────────────────────────────────────────────────────────────

function formatTime(timestamp) {
  if (!timestamp) return '—'
  try {
    const date = new Date(timestamp)
    if (isNaN(date.getTime())) return String(timestamp)
    return date.toLocaleString()
  } catch {
    return String(timestamp)
  }
}

/** HMAC integrity reminder bar. */
export function HmacBar({ chainStatus, onVerifyClick }) {
  if (!chainStatus) return null
  const needed = chainStatus.hmac_verify_needed
  return (
    <div
      className={cn(
        'flex items-center justify-between rounded-lg border p-3 text-xs',
        needed
          ? 'border-status-pending/25 bg-status-pending/5 text-status-pending'
          : 'border-status-approved/20 bg-status-approved/5 text-status-approved',
      )}
    >
      <div className="flex items-center gap-2">
        <span>{needed ? '⚠' : '✓'}</span>
        <span>
          {needed
            ? chainStatus.hmac_last_verified_at
              ? `Evidence chain HMAC verification overdue (last: ${formatTime(chainStatus.hmac_last_verified_at)}).`
              : 'Evidence chain HMAC has never been verified.'
            : `Evidence chain HMAC verified${chainStatus.hmac_last_verified_at ? ` — ${formatTime(chainStatus.hmac_last_verified_at)}` : ''}${chainStatus.hmac_last_verified_by ? ` by ${chainStatus.hmac_last_verified_by}` : ''}.`}
        </span>
      </div>
      <Button
        type="button"
        variant="outline"
        size="xs"
        onClick={onVerifyClick}
        className={cn(
          'mono text-[11px] font-semibold shrink-0',
          needed ? 'text-status-pending border-status-pending/40' : 'text-status-approved border-status-approved/40',
        )}
      >
        {needed ? 'Verify Now' : 'Re-verify'}
      </Button>
    </div>
  )
}

/** Custody violations panel (missing + modified files). */
export function CustodyViolations({ chainStatus, onRetire, onReacquire }) {
  const missing = chainStatus?.missing ?? []
  const modified = chainStatus?.modified ?? []
  if (!missing.length && !modified.length) return null

  return (
    <div
      className="rounded-lg border p-4"
      role="alert"
      style={{ background: 'color-mix(in srgb,var(--sev-high) 5%,transparent)', borderColor: 'var(--sev-high)' }}
    >
      <h4 className="mb-2 flex items-center gap-1.5 text-xs font-bold" style={{ color: 'var(--sev-high)' }}>
        Chain of Custody Violation
      </h4>

      {missing.length > 0 && (
        <div className="mb-3 text-xs">
          <strong className="mb-1 block">Missing Files:</strong>
          <ul className="list-disc space-y-1 pl-5">
            {missing.map((f) => {
              const path = typeof f === 'string' ? f : (f.path || '')
              return (
                <li key={path} className="mono">
                  <div className="flex items-center justify-between">
                    <span className="break-all">{path}</span>
                    <Button
                      type="button"
                      variant="outline"
                      size="xs"
                      onClick={() => onRetire(path)}
                      className="mono ml-4 shrink-0 text-[10px] text-destructive border-destructive/40 hover:bg-destructive/10"
                    >
                      Retire File
                    </Button>
                  </div>
                </li>
              )
            })}
          </ul>
        </div>
      )}

      {modified.length > 0 && (
        <div className="text-xs">
          <strong className="mb-1 block">Modified Files (Hash Mismatch):</strong>
          <ul className="list-disc space-y-1 pl-5">
            {modified.map((f) => {
              const path = typeof f === 'string' ? f : (f.path || '')
              return (
                <li key={path} className="mono">
                  <div className="flex items-center justify-between gap-2">
                    <span className="break-all">{path}</span>
                    <div className="flex shrink-0 gap-2">
                      <Button
                        type="button"
                        variant="outline"
                        size="xs"
                        onClick={() => onReacquire(path)}
                        className="mono text-[10px] text-status-approved border-status-approved/40 hover:bg-status-approved/10"
                      >
                        Re-seal
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        size="xs"
                        onClick={() => onRetire(path)}
                        className="mono text-[10px] text-destructive border-destructive/40 hover:bg-destructive/10"
                      >
                        Retire
                      </Button>
                    </div>
                  </div>
                </li>
              )
            })}
          </ul>
        </div>
      )}
    </div>
  )
}

/** Unregistered files table with inline source/description inputs. */
export function UnregisteredFiles({ chainStatus, unregisteredMetadata, onMetaChange, onIgnore, onDelete, onSeal }) {
  const unregistered = chainStatus?.unregistered ?? []
  if (!unregistered.length) return null

  return (
    <div
      className="space-y-3 rounded-lg border p-4"
      style={{ borderColor: 'color-mix(in srgb,var(--amber) 30%,var(--border-soft))' }}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h4 className="flex items-center gap-1.5 text-xs font-bold" style={{ color: 'var(--text-bright)' }}>
          <Archive className="size-3.5" aria-hidden />
          Unregistered Evidence Files Detected
        </h4>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={onSeal}
          className="mono text-xs font-semibold text-status-pending border-status-pending/40 hover:bg-status-pending/10"
        >
          Seal Manifest ({unregistered.length} file{unregistered.length === 1 ? '' : 's'})
        </Button>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs" style={{ borderCollapse: 'collapse' }}>
          <thead>
            <tr className="border-b border-border text-muted-foreground">
              <th className="py-2 pr-4 font-semibold w-1/3">Path</th>
              <th className="py-2 pr-4 font-semibold w-1/3">Source Notes</th>
              <th className="py-2 pr-4 font-semibold w-1/3">Description</th>
              <th className="py-2 text-right font-semibold">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {unregistered.map((path) => (
              <tr key={path} className="text-foreground">
                <td className="mono py-2 pr-4 break-all">{path}</td>
                <td className="py-2 pr-4">
                  <input
                    type="text"
                    value={unregisteredMetadata[path]?.source ?? ''}
                    onChange={(e) => onMetaChange(path, 'source', e.target.value)}
                    placeholder="e.g. USB drive #1"
                    className="mono w-full rounded border border-border bg-secondary px-2 py-1 text-[11px] text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
                  />
                </td>
                <td className="py-2 pr-4">
                  <input
                    type="text"
                    value={unregisteredMetadata[path]?.description ?? ''}
                    onChange={(e) => onMetaChange(path, 'description', e.target.value)}
                    placeholder="e.g. Acquired disk image"
                    className="mono w-full rounded border border-border bg-secondary px-2 py-1 text-[11px] text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
                  />
                </td>
                <td className="py-2 whitespace-nowrap text-right">
                  <Button
                    type="button"
                    variant="ghost"
                    size="xs"
                    onClick={() => onIgnore(path)}
                    className="mono mr-1 text-[10px] text-muted-foreground"
                  >
                    Ignore
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    size="xs"
                    onClick={() => onDelete(path)}
                    className="mono text-[10px] text-muted-foreground hover:text-destructive"
                  >
                    Delete
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/** Registered evidence table (the operational API-backed list). */
export function RegisteredEvidenceTable({ evidence, evidenceLoading, evidenceError, chainStatus, verifyStatus, sortCol, sortAsc, onSort, onUnseal, onVerify, onNavigateFinding }) {
  return (
    <div className="space-y-2">
      <h3 className="mono text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
        Registered Evidence ({evidence.length} file{evidence.length === 1 ? '' : 's'})
      </h3>

      {evidenceError && (
        <div className="rounded-lg border border-destructive/20 bg-destructive/5 p-2.5 text-xs text-destructive">
          {evidenceError}
        </div>
      )}

      {evidenceLoading ? (
        <SkeletonBlock rows={5} gap={8} />
      ) : evidence.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-lg border border-border bg-card py-12 text-center">
          <Archive className="mb-3 size-12 text-muted-foreground opacity-30" aria-hidden />
          <p className="text-sm font-semibold text-foreground">No evidence files registered.</p>
          <p className="mt-1 max-w-xs text-xs text-muted-foreground">Use the Rescan button or add files to the evidence directory.</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border bg-card">
          <table className="w-full text-left text-xs" style={{ borderCollapse: 'collapse' }}>
            <thead>
              <tr className="border-b border-border text-muted-foreground">
                {[
                  { key: 'path', label: 'Path' },
                  { key: 'sha256', label: 'SHA-256' },
                  { key: 'description', label: 'Description' },
                  { key: 'registered_at', label: 'Registered At' },
                  { key: 'registered_by', label: 'Registered By' },
                ].map(({ key, label }) => (
                  <th
                    key={key}
                    className="mono cursor-pointer select-none px-3 py-2 font-semibold hover:text-foreground"
                    onClick={() => onSort(key)}
                    aria-sort={sortCol === key ? (sortAsc ? 'ascending' : 'descending') : 'none'}
                  >
                    {label} {sortCol === key ? (sortAsc ? '▲' : '▼') : ''}
                  </th>
                ))}
                <th className="mono px-3 py-2 font-semibold">Referenced By</th>
                <th className="mono px-3 py-2 text-right font-semibold">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {evidence.map((ev) => {
                const vStatus = verifyStatus[ev.path]
                return (
                  <tr key={ev.path} className="text-foreground transition-colors hover:bg-secondary/50">
                    <td className="mono break-all px-3 py-2">{ev.path}</td>
                    <td className="mono px-3 py-2" title={ev.sha256}>
                      {ev.sha256 ? `${ev.sha256.slice(0, 12)}…` : '—'}
                    </td>
                    <td className="px-3 py-2">{ev.description || '—'}</td>
                    <td className="mono whitespace-nowrap px-3 py-2">{formatTime(ev.registered_at)}</td>
                    <td className="mono px-3 py-2">{ev.registered_by || '—'}</td>
                    <td className="px-3 py-2">
                      <div className="flex flex-wrap gap-1">
                        {ev.referenced_by?.length > 0 ? (
                          ev.referenced_by.map((rid) => (
                            <button
                              key={rid}
                              type="button"
                              onClick={() => onNavigateFinding(rid)}
                              className="mono rounded px-1.5 py-0.5 text-[10px] text-primary hover:underline focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                            >
                              {rid}
                            </button>
                          ))
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 text-right">
                      {(chainStatus?.ok ?? []).includes(ev.path) && (
                        <button
                          type="button"
                          data-testid={`unseal-btn-${ev.path}`}
                          onClick={() => onUnseal(ev.path)}
                          className="mono mr-2 rounded border border-border px-2 py-1 text-[10px] font-semibold text-muted-foreground transition-colors hover:border-status-pending hover:text-status-pending focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                          title="Unseal: clear the immutable flag so this evidence can be replaced/re-imaged"
                        >
                          Unseal
                        </button>
                      )}
                      {vStatus === 'checking' ? (
                        <span className="mono animate-pulse text-xs text-muted-foreground">Checking…</span>
                      ) : vStatus === 'verified' ? (
                        <span className="mono text-xs font-semibold text-status-approved">Verified ✓</span>
                      ) : vStatus === 'failed' ? (
                        <span className="mono text-xs font-semibold text-destructive">FAILED ⚠</span>
                      ) : vStatus === 'error' ? (
                        <span className="mono text-xs text-destructive">Error</span>
                      ) : vStatus ? (
                        <span className="mono text-xs text-muted-foreground">{vStatus}</span>
                      ) : (
                        <button
                          type="button"
                          onClick={() => onVerify(ev.path)}
                          className="mono rounded border border-border px-2 py-1 text-[10px] font-semibold text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                        >
                          Verify
                        </button>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

/** Write-block status card. */
export function WriteBlockCard({ chainStatus }) {
  if (!chainStatus) return <div className="h-16 rounded-lg bg-secondary animate-pulse" aria-busy="true" />
  return chainStatus.write_protected ? (
    <div className="rounded-lg border border-status-approved/15 bg-status-approved/4 p-3 text-xs text-status-approved">
      <div className="mb-1 flex items-center gap-1.5 font-semibold">
        <span>✓</span> Write Protection Active
      </div>
      <div className="mono text-[11px] opacity-80">
        Evidence directory is write-protected (mounted read-only
        {chainStatus.write_block_mount_point ? ` on ${chainStatus.write_block_mount_point}` : ''}).
      </div>
    </div>
  ) : (
    <div className="rounded-lg border border-status-pending/20 bg-status-pending/5 p-3 text-xs text-status-pending">
      <div className="mb-1 flex items-center gap-1.5 font-semibold">
        <span>⚠</span> Write Protection Warning
      </div>
      <div className="mono text-[11px] opacity-80">
        Evidence directory is NOT write-protected. Forensic best practice requires mounting read-only.
      </div>
    </div>
  )
}

/** Solana anchor status card. */
export function SolanaCard({ chainStatus, onAnchor }) {
  if (!chainStatus) return <div className="h-16 rounded-lg bg-secondary animate-pulse" aria-busy="true" />
  const a = chainStatus.anchor ?? {}
  if (a.solana_tx && a.confirmed) {
    return (
      <div className="rounded-lg border border-status-approved/15 bg-status-approved/4 p-3 text-xs text-status-approved">
        <div className="mb-1 mono font-semibold">On-chain Anchored</div>
        <div className="mono text-[11px] opacity-80">
          Manifest v{a.manifest_version} anchored ({a.cluster || 'mainnet'}) {formatTime(a.timestamp)}
        </div>
        {a.explorer_url && (
          <a href={a.explorer_url} target="_blank" rel="noopener noreferrer" className="mono text-[11px] underline">
            Solscan ↗
          </a>
        )}
      </div>
    )
  }
  if (a.anchoring_enabled && (a.manifest_version ?? 0) > 0 && !a.solana_tx) {
    return (
      <div className="flex items-center justify-between rounded-lg border border-status-pending/15 bg-status-pending/5 p-3 text-xs text-status-pending">
        <div>
          <div className="mono mb-1 font-semibold">Unanchored</div>
          <div className="mono text-[11px] opacity-80">Manifest v{a.manifest_version} not yet anchored.</div>
        </div>
        <Button type="button" variant="outline" size="xs" onClick={onAnchor} className="mono text-[10px] text-status-pending border-status-pending/40">
          Anchor Now
        </Button>
      </div>
    )
  }
  return (
    <div className="rounded-lg border border-border bg-secondary/50 p-3 text-xs text-muted-foreground">
      <div className="mono font-semibold mb-1">Solana anchoring not configured</div>
      <div className="mono text-[11px] opacity-80">Set SIFT_SOLANA_KEYPAIR to enable on-chain timestamping.</div>
    </div>
  )
}

/** Rescan button row */
export function RescanBar({ onRescan }) {
  return (
    <div className="flex justify-end">
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={onRescan}
        className="mono gap-1.5 text-xs"
      >
        <RefreshCw className="size-3.5" aria-hidden />
        Rescan evidence
      </Button>
    </div>
  )
}
