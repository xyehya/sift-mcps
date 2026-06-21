import { CheckCircle2, AlertTriangle, Link2, Clock, ExternalLink } from 'lucide-react'

import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { formatTime, shortHash } from './evidence-utils'

// ─────────────────────────────────────────────────────────────────────────
// CustodyStatusGrid — the 2-column (md) custody-infrastructure grid (legacy IA
// parity §3): Write-Block status, Solana anchor status (4 states), and — for DB
// custody authority only — the Custody Proof Export panel. Single column on the
// dashboard; no master-detail.
// ─────────────────────────────────────────────────────────────────────────

/** Section panel shell with an uppercase mono micro-label. */
function StatusPanel({ label, children }) {
  return (
    <div className="flex flex-col justify-between rounded-lg border border-border-faint bg-card p-4">
      <div>
        <p className="mono mb-3 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
          {label}
        </p>
        {children}
      </div>
    </div>
  )
}

function LoadingTile() {
  return <div className="h-16 rounded-lg bg-secondary animate-pulse" aria-busy="true" />
}

// ── Write-block ────────────────────────────────────────────────────────────
function WriteBlock({ chainStatus }) {
  if (!chainStatus) return <LoadingTile />

  if (chainStatus.write_protected) {
    return (
      <div className="rounded-lg border border-status-approved/15 bg-status-approved/5 p-3 text-xs text-status-approved">
        <div className="mb-1 flex items-center gap-1.5 font-semibold">
          <CheckCircle2 className="size-3.5" aria-hidden /> Write Protection Active
        </div>
        <div className="mono text-[11px] opacity-80">
          Evidence directory is write-protected (mounted read-only
          {chainStatus.write_block_mount_point ? ` on ${chainStatus.write_block_mount_point}` : ''}).
        </div>
      </div>
    )
  }

  return (
    <div className="rounded-lg border border-status-pending/20 bg-status-pending/5 p-3 text-xs text-status-pending">
      <div className="mb-1 flex items-center gap-1.5 font-semibold">
        <AlertTriangle className="size-3.5" aria-hidden /> Write Protection Warning
      </div>
      <div className="mb-2 text-[11px] opacity-80">
        Evidence directory is NOT write-protected (mounted read-write). Forensic best practice
        requires mounting evidence read-only.
      </div>
      <p className="mono mb-1 text-[10px] font-semibold uppercase text-muted-foreground">
        Recommended Mount Command:
      </p>
      <pre className="mono select-all rounded border border-border-faint bg-bg-void p-2 text-[10px] text-text-bright">
        mount -o ro,noatime /dev/sdX /mnt/evidence
      </pre>
    </div>
  )
}

// ── Solana anchor ──────────────────────────────────────────────────────────
function SolanaAnchor({ chainStatus, onAnchor }) {
  if (!chainStatus) return <LoadingTile />
  const a = chainStatus.anchor ?? {}

  // 1 — confirmed on-chain
  if (a.solana_tx && a.confirmed) {
    return (
      <div className="flex items-start justify-between gap-2 rounded-lg border border-status-approved/15 bg-status-approved/5 p-3 text-xs text-status-approved">
        <div>
          <div className="mb-1 flex items-center gap-1.5 font-semibold">
            <Link2 className="size-3.5" aria-hidden /> On-chain Anchored
          </div>
          <div className="mono text-[11px] opacity-80">
            Manifest v{a.manifest_version} anchored on Solana ({a.cluster || 'mainnet'}) at {formatTime(a.timestamp)}
          </div>
        </div>
        {a.explorer_url && (
          <a
            href={a.explorer_url}
            target="_blank"
            rel="noopener noreferrer"
            className="mono inline-flex shrink-0 items-center gap-1 text-[11px] font-semibold underline hover:text-foreground"
          >
            Solscan <ExternalLink className="size-3" aria-hidden />
          </a>
        )}
      </div>
    )
  }

  // 2 — submitted, awaiting confirmation
  if (a.solana_tx && !a.confirmed) {
    return (
      <div className="flex items-start justify-between gap-2 rounded-lg border border-status-pending/20 bg-status-pending/5 p-3 text-xs text-status-pending">
        <div>
          <div className="mb-1 flex items-center gap-1.5 font-semibold">
            <Clock className="size-3.5" aria-hidden /> Anchor Pending
          </div>
          <div className="mono text-[11px] opacity-80">TX submitted, awaiting confirmation.</div>
        </div>
        {a.explorer_url && (
          <a
            href={a.explorer_url}
            target="_blank"
            rel="noopener noreferrer"
            className="mono inline-flex shrink-0 items-center gap-1 text-[11px] font-semibold underline hover:text-foreground"
          >
            Solscan <ExternalLink className="size-3" aria-hidden />
          </a>
        )}
      </div>
    )
  }

  // 3 — anchoring enabled, sealed manifest, not yet anchored
  if (a.anchoring_enabled && (a.manifest_version ?? 0) > 0) {
    return (
      <div className="flex items-center justify-between gap-4 rounded-lg border border-status-pending/15 bg-status-pending/5 p-3 text-xs text-status-pending">
        <div>
          <div className="mb-1 flex items-center gap-1.5 font-semibold">
            <Link2 className="size-3.5" aria-hidden /> Unanchored
          </div>
          <div className="text-[11px] opacity-80">
            Manifest v{a.manifest_version} not yet anchored on Solana.
          </div>
        </div>
        <Button
          type="button"
          variant="outline"
          size="xs"
          onClick={onAnchor}
          className="mono shrink-0 text-[10px] text-status-pending border-status-pending/40 hover:bg-status-pending/10"
        >
          Anchor Now
        </Button>
      </div>
    )
  }

  // 4 — not configured
  return (
    <div className="rounded-lg border border-border bg-secondary/50 p-3 text-xs text-muted-foreground">
      <div className="inline-flex items-start gap-1.5">
        <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-status-pending" aria-hidden />
        <span>
          Solana anchoring not configured. Set{' '}
          <code className="mono rounded border border-border-soft bg-bg-raised px-1 py-0.5 text-text-bright">
            SIFT_SOLANA_KEYPAIR
          </code>{' '}
          in the gateway environment to enable on-chain timestamping.{' '}
          <a
            href="https://github.com/sift-mcps/sift-mcps/blob/main/docs/solana.md"
            target="_blank"
            rel="noopener noreferrer"
            className="ml-1 inline-flex items-center gap-1 text-primary hover:underline"
          >
            Learn more <ExternalLink className="size-3" aria-hidden />
          </a>
        </span>
      </div>
    </div>
  )
}

// ── Custody proof export (DB authority only) ───────────────────────────────
function ProofExport({ chainStatus, onProofExport }) {
  const pe = chainStatus?.proof_export

  return (
    <div className="flex flex-col justify-between rounded-lg border border-border-faint bg-card p-4">
      <div>
        <p className="mono mb-3 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
          Custody Proof Export
        </p>
        {pe ? (
          <div className="rounded-lg border border-border-soft p-3 text-xs text-muted-foreground">
            <div className={cn('mono text-[11px] font-semibold', pe.verified ? 'text-status-approved' : 'text-status-pending')}>
              {pe.verified ? 'Verified against mounted evidence' : 'Recorded — verification reported issues'}
            </div>
            <div className="mono mt-1 break-all text-[11px] opacity-80">
              v{pe.manifest_version} · {pe.export_kind} · {shortHash(pe.proof_hash, 22)}
            </div>
            {pe.verified_at && (
              <div className="mt-1 text-[11px] opacity-60">Exported {formatTime(pe.verified_at)}</div>
            )}
          </div>
        ) : (
          <div className="rounded-lg border border-border-soft p-3 text-xs text-muted-foreground">
            No proof export recorded yet. Proof material is derived from Postgres custody authority and
            re-verified against mounted evidence.
          </div>
        )}
      </div>
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={onProofExport}
        className="mono mt-3 self-start text-[10px] text-primary border-primary/40 hover:bg-primary/10"
      >
        Generate Proof Export
      </Button>
    </div>
  )
}

export function CustodyStatusGrid({ chainStatus, onAnchor, onProofExport }) {
  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
      <StatusPanel label="Write Block Status">
        <WriteBlock chainStatus={chainStatus} />
      </StatusPanel>

      <StatusPanel label="Solana Anchor Status">
        <SolanaAnchor chainStatus={chainStatus} onAnchor={onAnchor} />
      </StatusPanel>

      {chainStatus?.authority === 'db' && (
        <ProofExport chainStatus={chainStatus} onProofExport={onProofExport} />
      )}
    </div>
  )
}
