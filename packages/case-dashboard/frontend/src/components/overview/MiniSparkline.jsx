import { useMemo } from 'react'
import { motion } from 'framer-motion'

import { useMotionVariants } from '@/lib/motion'
import { velocitySeries } from '@/components/overview/overview-metrics'

// ─────────────────────────────────────────────────────────────────────────
// MiniSparkline — the agent hero's at-a-glance finding-velocity trend. Wires
// the `chartDraw` motion primitive: the line is a <motion.path> whose pathLength
// animates 0→1 on mount (reduced-motion shows it instantly via useMotionVariants).
// Colour is the --chart-1 token (no hex). Derived from the same velocitySeries
// the full VelocityCard chart uses, so the glance and the chart agree.
// ─────────────────────────────────────────────────────────────────────────

const W = 132
const H = 40
const PAD = 3

export function MiniSparkline({ findings, range = '24h' }) {
  const variants = useMotionVariants()
  const series = useMemo(() => velocitySeries(findings, range), [findings, range])

  const { line, area, lastX, lastY, hasData } = useMemo(() => {
    const vals = series.map((s) => s.count)
    if (vals.length === 0) return { hasData: false }
    const max = Math.max(1, ...vals)
    const x = (i) => PAD + (i * (W - 2 * PAD)) / Math.max(1, vals.length - 1)
    const y = (v) => H - PAD - (v / max) * (H - 2 * PAD)
    const linePath = vals.map((v, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ')
    const areaPath = `${linePath} L${x(vals.length - 1).toFixed(1)},${H} L${x(0).toFixed(1)},${H} Z`
    return {
      hasData: vals.some((v) => v > 0),
      line: linePath,
      area: areaPath,
      lastX: x(vals.length - 1),
      lastY: y(vals.at(-1)),
    }
  }, [series])

  if (!hasData) return null

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      width={W}
      height={H}
      preserveAspectRatio="none"
      role="img"
      aria-label="Finding velocity, last 24 hours"
      className="overflow-visible"
    >
      <defs>
        <linearGradient id="hero-spark-fill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="var(--chart-1)" stopOpacity={0.28} />
          <stop offset="100%" stopColor="var(--chart-1)" stopOpacity={0} />
        </linearGradient>
      </defs>
      <path d={area} fill="url(#hero-spark-fill)" />
      <motion.path
        d={line}
        fill="none"
        stroke="var(--chart-1)"
        strokeWidth={1.6}
        strokeLinecap="round"
        strokeLinejoin="round"
        variants={variants.chartDraw}
        initial="hidden"
        animate="show"
      />
      <circle cx={lastX} cy={lastY} r={2.4} fill="var(--chart-1)" />
    </svg>
  )
}
