import { Server } from 'lucide-react'

import { SkeletonBlock } from '@/components/common/Skeleton'
import { BackendServiceRow } from './BackendServiceRow'

// ─────────────────────────────────────────────────────────────────────────
// BackendRegistryList — the DB-registry table (legacy IA parity §4 + §7 empty
// state). Loading skeleton · empty-state guidance (setup-addon.sh → register →
// gateway restart) · per-row BackendServiceRow. Reskinned to orange/graphite
// tokens; the action handlers are passed through from the orchestrator.
// ─────────────────────────────────────────────────────────────────────────

const HEADERS = ['NAME', 'TYPE', 'STATUS', 'HEALTH', 'REQUIREMENTS']

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center px-4 py-10 text-center">
      <Server className="mb-3 size-10 text-muted-foreground opacity-30" aria-hidden />
      <p className="mono mb-2 text-sm font-semibold text-foreground">
        No DB-registered backends found.
      </p>
      <p className="max-w-xl text-[11px] leading-relaxed text-muted-foreground">
        A default install registers only <span className="mono">opensearch-mcp</span> and{' '}
        <span className="mono">forensic-rag-mcp</span>. Add-ons (
        <span className="mono">windows-triage-mcp</span>, <span className="mono">opencti-mcp</span>)
        are provisioned with <span className="mono">scripts/setup-addon.sh</span>, then Registered
        here, then applied with a gateway restart.
      </p>
    </div>
  )
}

export function BackendRegistryList({
  backends,
  loading,
  onToggleEnabled,
  onStart,
  onStop,
  onRestart,
  onUnregister,
}) {
  return (
    <section className="flex flex-col rounded-lg border border-border-soft bg-card p-4 lg:col-span-2">
      <p className="mono mb-3 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
        DB Registry Backends
      </p>

      {loading ? (
        <SkeletonBlock rows={4} gap={8} />
      ) : backends.length === 0 ? (
        <EmptyState />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-border-soft">
                {HEADERS.map((h) => (
                  <th key={h} className="mono py-2.5 text-[10px] font-semibold text-muted-foreground">
                    {h}
                  </th>
                ))}
                <th className="mono py-2.5 text-right text-[10px] font-semibold text-muted-foreground">
                  ACTIONS
                </th>
              </tr>
            </thead>
            <tbody>
              {backends.map((b) => (
                <BackendServiceRow
                  key={b.name}
                  backend={b}
                  onToggleEnabled={onToggleEnabled}
                  onStart={onStart}
                  onStop={onStop}
                  onRestart={onRestart}
                  onUnregister={onUnregister}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
