import { useState, useEffect, useCallback } from 'react'
import { getHealth } from '../../api/endpoints'

// PT1/WI4 — dense operator health panel. Feeds off the gateway /health probe
// (proxied at /portal/api/health). Mounted idle stdio backends are already
// normalized to "ok" server-side, so OpenSearch/RAG/add-on rows show as ready
// rather than "stopped". No secrets, tokens, or DSNs are rendered.

const STATUS_COLOR = {
  ok: 'var(--jade)',
  disabled: 'var(--text-muted)',
  gated: 'var(--amber)',
  warning: 'var(--amber)',
  stopped: 'var(--text-muted)',
  error: 'var(--crimson)',
  invalid_manifest: 'var(--crimson)',
  unknown: 'var(--text-muted)',
}

function statusColor(status) {
  return STATUS_COLOR[status] || 'var(--text-muted)'
}

function StatusDot({ status }) {
  return (
    <span
      className="inline-block w-2 h-2 rounded-full shrink-0"
      style={{ background: statusColor(status) }}
    />
  )
}

function Row({ label, status, detail }) {
  return (
    <div className="flex items-center justify-between gap-3 py-1.5 border-b" style={{ borderColor: 'var(--border-faint)' }}>
      <div className="flex items-center gap-2 min-w-0">
        <StatusDot status={status} />
        <span className="font-mono text-[11px] text-text-bright truncate">{label}</span>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        {detail && (
          <span className="font-sans text-[10px] text-text-muted truncate max-w-[220px]" title={detail}>{detail}</span>
        )}
        <span
          className="font-mono text-[10px] font-semibold uppercase tracking-wider"
          style={{ color: statusColor(status) }}
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
    fetchHealth()
    const t = setInterval(fetchHealth, 15000)
    return () => clearInterval(t)
  }, [fetchHealth])

  const overall = health?.status || 'unknown'
  const backends = health?.backends ? Object.entries(health.backends) : []
  const supabase = health?.supabase || {}
  const evidence = health?.evidence_root || {}

  return (
    <div className="p-4 rounded border" style={{ background: 'var(--bg-surface)', borderColor: 'var(--border-faint)' }}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <p className="text-[10px] font-sans font-semibold uppercase tracking-widest" style={{ color: 'var(--text-muted)' }}>
            System Health
          </p>
          <span
            className="px-1.5 py-0.5 rounded font-mono text-[9px] font-semibold uppercase"
            style={{ background: overall === 'ok' ? 'var(--jade-dim)' : 'var(--amber-dim)', color: overall === 'ok' ? 'var(--jade)' : 'var(--amber)' }}
          >
            {overall}
          </span>
        </div>
        <button
          onClick={fetchHealth}
          disabled={loading}
          className="px-2 py-0.5 rounded text-[10px] font-sans font-semibold border hover:opacity-85 disabled:opacity-50 transition-opacity"
          style={{ background: 'var(--bg-raised)', color: 'var(--text-primary)', borderColor: 'var(--border-soft)' }}
        >
          {loading ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>

      {err && (
        <p className="text-[11px] font-mono mb-2" style={{ color: 'var(--crimson)' }}>{err}</p>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-x-6">
        <div>
          <p className="text-[9px] font-mono uppercase tracking-widest mb-1 mt-1" style={{ color: 'var(--text-ghost)' }}>Control plane</p>
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
                    evidence.write_protected ? 'write-blocked (ro)' : (evidence.writable ? 'writable' : 'read-only'),
                    evidence.case_count != null ? `${evidence.case_count} cases` : null,
                  ].filter(Boolean).join(' · ')
                : ''
            }
          />
        </div>

        <div>
          <p className="text-[9px] font-mono uppercase tracking-widest mb-1 mt-1" style={{ color: 'var(--text-ghost)' }}>
            Backends (OpenSearch · RAG · worker · add-ons)
          </p>
          {backends.length === 0 ? (
            <p className="py-2 text-[11px] font-mono text-text-muted">
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
    </div>
  )
}
