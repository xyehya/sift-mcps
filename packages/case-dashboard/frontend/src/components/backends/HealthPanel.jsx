import { useCallback, useEffect, useState } from 'react'
import { Activity } from 'lucide-react'

import { cn } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { getHealth } from '@/api/endpoints'
import { healthDotClass, healthToneClass } from './backends-utils'

// ─────────────────────────────────────────────────────────────────────────
// HealthPanel — dense operator system-health panel (PT1/WI4; legacy IA parity
// §3). Feeds off the gateway /health probe (proxied at /portal/api/health;
// mock-served in ?mock=1). Shows overall status, control-plane rows (gateway +
// tools_count · Supabase auth · evidence root), and a per-backend health grid.
// Own refresh + 15s poll + loading/error. No secrets, tokens, or DSNs rendered.
// Reskinned to orange/graphite tokens, lucide icons, shadcn Button.
// ─────────────────────────────────────────────────────────────────────────

function StatusDot({ status }) {
  return (
    <span
      className={cn('inline-block size-2 shrink-0 rounded-full', healthDotClass(status))}
      aria-hidden
    />
  )
}

function Row({ label, status, detail }) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-border-faint py-1.5">
      <div className="flex min-w-0 items-center gap-2">
        <StatusDot status={status} />
        <span className="mono truncate text-[11px] text-foreground">{label}</span>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        {detail && (
          <span className="max-w-[220px] truncate text-[10px] text-muted-foreground" title={detail}>
            {detail}
          </span>
        )}
        <span
          className={cn(
            'mono text-[10px] font-semibold uppercase tracking-wider',
            healthToneClass(status),
          )}
        >
          {status || 'unknown'}
        </span>
      </div>
    </div>
  )
}

export function HealthPanel() {
  const [health, setHealth] = useState(null)
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState('')

  const fetchHealth = useCallback(async () => {
    setLoading(true)
    setErr('')
    try {
      const res = await getHealth()
      setHealth(res)
    } catch (e) {
      setErr(e?.message || 'Failed to load health')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    fetchHealth()
    const t = setInterval(fetchHealth, 15000)
    return () => clearInterval(t)
  }, [fetchHealth])

  const overall = health?.status || 'unknown'
  const backends = health?.backends ? Object.entries(health.backends) : []
  const supabase = health?.supabase || {}
  const evidence = health?.evidence_root || {}

  return (
    <section className="rounded-lg border border-border-soft bg-card p-4">
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Activity className="size-3.5 text-muted-foreground" aria-hidden />
          <h2 className="mono text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
            System Health
          </h2>
          <span
            className={cn(
              'mono rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase',
              overall === 'ok'
                ? 'bg-status-approved/10 text-status-approved'
                : 'bg-status-pending/10 text-status-pending',
            )}
          >
            {overall}
          </span>
        </div>
        <Button
          type="button"
          variant="outline"
          size="xs"
          onClick={fetchHealth}
          disabled={loading}
          className="mono text-[10px]"
        >
          {loading ? 'Refreshing…' : 'Refresh'}
        </Button>
      </div>

      {err && <p className="mono mb-2 text-[11px] text-destructive">{err}</p>}

      <div className="grid grid-cols-1 gap-x-6 lg:grid-cols-2">
        <div>
          <p className="mono mb-1 mt-1 text-[9px] uppercase tracking-widest text-text-ghost">
            Control plane
          </p>
          <Row
            label="Gateway"
            status={health ? 'ok' : 'unknown'}
            detail={health ? `${health.tools_count ?? 0} tools aggregated` : ''}
          />
          <Row
            label="Supabase Auth"
            status={supabase.status}
            detail={supabase.detail || (supabase.url ? 'reachable' : '')}
          />
          <Row
            label="Evidence root"
            status={evidence.status}
            detail={
              evidence.status
                ? [
                    evidence.path,
                    evidence.write_protected
                      ? 'write-blocked (ro)'
                      : evidence.writable
                        ? 'writable'
                        : 'read-only',
                    evidence.case_count != null ? `${evidence.case_count} cases` : null,
                  ]
                    .filter(Boolean)
                    .join(' · ')
                : ''
            }
          />
        </div>

        <div>
          <p className="mono mb-1 mt-1 text-[9px] uppercase tracking-widest text-text-ghost">
            Backends (OpenSearch · RAG · worker · add-ons)
          </p>
          {backends.length === 0 ? (
            <p className="mono py-2 text-[11px] text-muted-foreground">
              {loading ? 'Loading…' : 'No backends reported.'}
            </p>
          ) : (
            backends.map(([name, h]) => (
              <Row
                key={name}
                label={name}
                status={h?.status}
                detail={h?.detail || h?.error || (h?.mounted_proxy ? 'idle (mounted proxy)' : '')}
              />
            ))
          )}
        </div>
      </div>
    </section>
  )
}
