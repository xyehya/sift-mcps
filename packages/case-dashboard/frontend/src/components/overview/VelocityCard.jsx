import { useMemo, useState } from 'react'

import { cn } from '@/lib/utils'
import { VELOCITY_RANGES, velocitySeries } from '@/components/overview/overview-metrics'
import { AreaTrend } from '@/components/charts/AreaTrend'

// ─────────────────────────────────────────────────────────────────────────
// Finding velocity — a themed recharts area chart (via AreaTrend) with a
// 24h / 7d / all range toggle. The series is derived from finding timestamps;
// the chart itself owns legend, tooltip, empty-state, skeleton, table fallback
// and reduced-motion handling.
// ─────────────────────────────────────────────────────────────────────────

export function VelocityCard({ findings, loading }) {
  const [range, setRange] = useState('7d')
  const data = useMemo(() => velocitySeries(findings, range), [findings, range])

  return (
    <div className="flex flex-col gap-3">
      <div className="inline-flex w-fit items-center gap-1 rounded-md border border-border p-0.5" role="group" aria-label="Velocity range">
        {VELOCITY_RANGES.map((r) => (
          <button
            key={r.key}
            type="button"
            onClick={() => setRange(r.key)}
            aria-pressed={range === r.key}
            className={cn(
              'rounded px-2.5 py-1 text-[11px] font-medium transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
              range === r.key ? 'bg-secondary text-foreground' : 'text-muted-foreground hover:text-foreground',
            )}
          >
            {r.label}
          </button>
        ))}
      </div>

      <AreaTrend
        data={data}
        loading={loading}
        seriesName="findings"
        colorVar="var(--chart-1)"
        emptyHint="No findings recorded in this window. Velocity charts the rate findings are added or edited over time."
      />
    </div>
  )
}
