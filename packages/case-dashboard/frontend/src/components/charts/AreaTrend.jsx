import { useId, useState } from 'react'
import { useReducedMotion } from 'framer-motion'
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { BarChart3, Table as TableIcon } from 'lucide-react'

import { cn } from '@/lib/utils'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

// ─────────────────────────────────────────────────────────────────────────
// AreaTrend — the canonical recharts wrapper for v3 (spec §3 chart rules).
// Every chart in the app should follow THIS pattern; Phase-1 agents copy it.
//   • Colour comes from --chart-* tokens (passed as `var(--chart-N)`), so it
//     swaps with the theme and never hard-codes hex.
//   • Legend + interactive tooltip + axis labels/units.
//   • Empty-data state (guidance, not a blank canvas) and a >300ms skeleton.
//   • reduced-motion safe: the draw animation is disabled and data is readable
//     immediately (spec §2). AA contrast in both themes.
//   • A11y fallback: a one-click data-table view of the same series, with an
//     sr-only summary, so the trend is reachable without reading the SVG.
// Data-driven inline styles are limited to the gradient stop colours (token
// vars), mirroring the vendored Progress primitive — no raw hex anywhere.
// ─────────────────────────────────────────────────────────────────────────

function ChartTooltip({ active, payload, label, seriesName, unit }) {
  if (!active || !payload?.length) return null
  const value = payload[0].value
  return (
    <div className="rounded-md border border-border bg-popover px-3 py-2 text-xs text-popover-foreground shadow-md">
      <p className="mono mb-0.5 text-muted-foreground">{label}</p>
      <p className="tnum font-semibold">
        {value} {seriesName}
        {unit ? ` ${unit}` : ''}
      </p>
    </div>
  )
}

export function AreaTrend({
  data = [],
  loading = false,
  xKey = 'label',
  dataKey = 'count',
  colorVar = 'var(--chart-1)',
  seriesName = 'findings',
  unit = '',
  height = 220,
  emptyHint = 'No data in this range yet.',
  className,
}) {
  const reduced = useReducedMotion()
  const gradientId = useId().replace(/:/g, '')
  const [view, setView] = useState('chart')

  const hasData = data.some((d) => Number(d[dataKey]) > 0)
  const total = data.reduce((sum, d) => sum + (Number(d[dataKey]) || 0), 0)

  return (
    <div className={cn('flex flex-col gap-3', className)}>
      {/* Legend + view toggle (chart ⇄ table a11y fallback). */}
      <div className="flex items-center justify-between">
        <span className="inline-flex items-center gap-2 text-xs text-muted-foreground">
          <span aria-hidden className="size-2 rounded-full" style={{ backgroundColor: colorVar }} />
          <span className="capitalize">{seriesName}</span>
          {/* /70 opacity drops contrast below 4.5:1 — use full-opacity muted-foreground */}
          <span className="tnum text-muted-foreground">· {total} total</span>
        </span>
        <div className="inline-flex overflow-hidden rounded-md border border-border" role="group" aria-label="Chart view">
          <ViewToggle active={view === 'chart'} onClick={() => setView('chart')} icon={BarChart3} label="Chart" />
          <ViewToggle active={view === 'table'} onClick={() => setView('table')} icon={TableIcon} label="Table" />
        </div>
      </div>

      {loading ? (
        <Skeleton style={{ height }} className="w-full" />
      ) : !hasData ? (
        <EmptyChart height={height} hint={emptyHint} />
      ) : view === 'table' ? (
        <TrendTable data={data} xKey={xKey} dataKey={dataKey} seriesName={seriesName} height={height} />
      ) : (
        <figure className="m-0" aria-label={`${seriesName} trend chart`}>
          {/* sr-only narrative so the trend is reachable without the SVG. */}
          <figcaption className="sr-only">
            {seriesName} trend: {total} total across {data.length} intervals from {data[0]?.[xKey]} to{' '}
            {data[data.length - 1]?.[xKey]}.
          </figcaption>
          <ResponsiveContainer width="100%" height={height}>
            <AreaChart data={data} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
              <defs>
                <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={colorVar} stopOpacity={0.35} />
                  <stop offset="100%" stopColor={colorVar} stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
              <XAxis
                dataKey={xKey}
                tick={{ fill: 'var(--muted-foreground)', fontSize: 11 }}
                tickLine={false}
                axisLine={{ stroke: 'var(--border)' }}
                minTickGap={16}
              />
              <YAxis
                allowDecimals={false}
                width={36}
                tick={{ fill: 'var(--muted-foreground)', fontSize: 11 }}
                tickLine={false}
                axisLine={false}
                label={{
                  value: seriesName,
                  angle: -90,
                  position: 'insideLeft',
                  style: { fill: 'var(--muted-foreground)', fontSize: 10, textAnchor: 'middle' },
                }}
              />
              <Tooltip
                cursor={{ stroke: 'var(--border)' }}
                content={<ChartTooltip seriesName={seriesName} unit={unit} />}
              />
              <Area
                type="monotone"
                dataKey={dataKey}
                name={seriesName}
                stroke={colorVar}
                strokeWidth={2}
                fill={`url(#${gradientId})`}
                isAnimationActive={!reduced}
                animationDuration={reduced ? 0 : 600}
                dot={false}
                activeDot={{ r: 3, fill: colorVar, stroke: 'var(--card)' }}
              />
            </AreaChart>
          </ResponsiveContainer>
        </figure>
      )}
    </div>
  )
}

function ViewToggle({ active, onClick, icon: Icon, label }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      aria-label={`${label} view`}
      className={cn(
        'inline-flex items-center gap-1 px-2 py-1 text-[11px] font-medium transition-colors',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
        active ? 'bg-secondary text-foreground' : 'text-muted-foreground hover:text-foreground',
      )}
    >
      <Icon className="size-3" aria-hidden />
      {label}
    </button>
  )
}

function EmptyChart({ height, hint }) {
  return (
    <div
      className="flex flex-col items-center justify-center gap-2 rounded-md border border-dashed border-border text-center"
      style={{ height }}
    >
      <BarChart3 className="size-5 text-muted-foreground/60" aria-hidden />
      <p className="max-w-[26ch] text-xs text-muted-foreground">{hint}</p>
    </div>
  )
}

function TrendTable({ data, xKey, dataKey, seriesName, height }) {
  return (
    <div className="overflow-auto rounded-md border border-border" style={{ maxHeight: height }}>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="text-xs">Interval</TableHead>
            <TableHead className="text-right text-xs capitalize">{seriesName}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.map((d) => (
            <TableRow key={d[xKey]}>
              <TableCell className="mono text-xs text-muted-foreground">{d[xKey]}</TableCell>
              <TableCell className="tnum text-right text-xs font-medium">{d[dataKey]}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}
