import { Server } from 'lucide-react'

import { SkeletonBlock } from '@/components/common/Skeleton'
import { BackendServiceRow } from './BackendServiceRow'

// ─────────────────────────────────────────────────────────────────────────
// BackendRegistryList — the DB-registry table, rebuilt to the reference-tab bar
// (Evidence RegisteredEvidenceTable): section label (mono 10px uppercase) over a
// `rounded-lg border bg-card` table; header row `bg-secondary/40`, mono labels;
// comfortable `px-3 py-2.5` cells, `divide-y` body, hover affordance. Loading
// skeleton · empty-state guidance · per-row BackendServiceRow. Action handlers
// are passed through from the orchestrator (each challenge-gated).
// ─────────────────────────────────────────────────────────────────────────

const HEADERS = ['Name', 'Type', 'Status', 'Health', 'Requirements']

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-border-soft bg-card px-4 py-12 text-center">
      <Server className="mb-3 size-10 text-muted-foreground opacity-30" aria-hidden />
      <p className="mb-2 text-sm font-semibold text-foreground">No DB-registered backends found.</p>
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
    <section className="flex flex-col gap-3 lg:col-span-2">
      <h3 className="mono text-[10px] font-semibold uppercase tracking-[.1em] text-muted-foreground">
        DB Registry Backends
      </h3>

      {loading ? (
        <SkeletonBlock rows={4} gap={8} />
      ) : backends.length === 0 ? (
        <EmptyState />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border-soft bg-card">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-border-soft bg-secondary/40 text-muted-foreground">
                {HEADERS.map((h) => (
                  <th
                    key={h}
                    scope="col"
                    className="mono px-3 py-2 text-[10px] font-semibold uppercase tracking-[.1em]"
                  >
                    {h}
                  </th>
                ))}
                <th scope="col" className="mono px-3 py-2 text-right text-[10px] font-semibold uppercase tracking-[.1em]">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-faint">
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
