import { motion, useReducedMotion } from 'framer-motion'

import { cn } from '@/lib/utils'
import { EASE } from '@/lib/motion'
import { confidenceGrade, confidenceScore } from '@/components/findings/findings-utils'

// ─────────────────────────────────────────────────────────────────────────
// ConfidenceRing — a graded SVG progress ring for a finding's confidence.
// Colour is graded (≥85 jade · ≥65 amber · else crimson) per DESIGN-SYSTEM.md,
// NOT branded by category. The arc draws on via `pathLength` (transform-safe);
// reduced-motion shows the final arc immediately. Stroke colour is a token CSS
// var (data-driven, never raw hex). The numeric score uses tabular mono figures.
// ─────────────────────────────────────────────────────────────────────────

export function ConfidenceRing({ finding, size = 44, stroke = 4, className }) {
  const reduced = useReducedMotion()
  const score = confidenceScore(finding)
  const grade = confidenceGrade(score)

  if (score == null || !grade) return null

  const r = (size - stroke) / 2
  const c = 2 * Math.PI * r
  const pct = Math.max(0, Math.min(100, score)) / 100

  return (
    <div
      className={cn('relative shrink-0', className)}
      style={{ width: size, height: size }}
      role="img"
      aria-label={`Confidence ${score} of 100`}
      title={`Confidence ${score}/100`}
    >
      <svg viewBox={`0 0 ${size} ${size}`} className="size-full -rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--border)" strokeWidth={stroke} />
        <motion.circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={grade.stroke}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={c}
          initial={reduced ? false : { strokeDashoffset: c }}
          animate={{ strokeDashoffset: c * (1 - pct) }}
          transition={reduced ? { duration: 0 } : { duration: 1, ease: EASE }}
        />
      </svg>
      <span className={cn('mono tnum absolute inset-0 flex items-center justify-center text-xs font-semibold', grade.text)}>
        {score}
      </span>
    </div>
  )
}
