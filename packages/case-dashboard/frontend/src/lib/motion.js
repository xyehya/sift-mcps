import { useEffect, useRef, useState } from "react"
import { useReducedMotion } from "framer-motion"

// Spec §2 + DESIGN-SYSTEM.md Motion layer — shared variants + helpers.
// Transform / opacity / pathLength ONLY (never animate w/h/top/left); colour is
// always carried by token classes, never by these variants. Everything is
// gated through useMotionVariants(): when the user prefers reduced motion the
// rich set is swapped for the `reduced` set, which collapses each animation to
// its final/instant state (looping animations stop, entrances snap in).

export const EASE = [0.16, 1, 0.3, 1]
export const EASE_OUT_CUBIC = [0.215, 0.61, 0.355, 1]
export const DUR = {
  micro: 0.18, // 150–220ms band
  enter: 0.22,
  exit: 0.14, // ~65% of enter
}
export const SPRING = { type: "spring", damping: 20, stiffness: 90 }
export const STAGGER = 0.045 // 35–50ms / item

/** easeOutCubic — the count-up curve (fast then settling). t ∈ [0,1]. */
export function easeOutCubic(t) {
  const c = Math.min(1, Math.max(0, t))
  return 1 - Math.pow(1 - c, 3)
}

// ---- Rich variants (motion on) ----
const rich = {
  // Entrance: rise + fade.
  fadeRise: {
    hidden: { opacity: 0, y: 8 },
    show: { opacity: 1, y: 0, transition: { duration: DUR.enter, ease: EASE } },
    exit: { opacity: 0, y: 6, transition: { duration: DUR.exit, ease: EASE } },
  },
  // Modal: spring scale-in.
  modal: {
    hidden: { opacity: 0, scale: 0.96, y: 8 },
    show: { opacity: 1, scale: 1, y: 0, transition: SPRING },
    exit: { opacity: 0, scale: 0.97, y: 6, transition: { duration: DUR.exit, ease: EASE } },
  },
  // Staggered list/grid container.
  staggerContainer: {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: STAGGER, delayChildren: 0.04 },
    },
  },
  staggerItem: {
    hidden: { opacity: 0, y: 8 },
    show: { opacity: 1, y: 0, transition: { duration: DUR.enter, ease: EASE } },
  },
  // Card hover: lift 2px (border-brighten applied via class).
  cardHover: {
    rest: { y: 0 },
    hover: { y: -2, transition: { duration: DUR.micro, ease: EASE } },
  },

  // ── Mission-Control ambient/loop primitives (DESIGN-SYSTEM.md motion table) ──
  // Agent orb: breathing core.
  breathingOrb: {
    animate: {
      scale: [1, 1.08, 1],
      opacity: [0.9, 1, 0.9],
      transition: { duration: 3.4, repeat: Infinity, ease: "easeInOut" },
    },
  },
  // Agent orb: a single ping ring (render two, stagger the second via `delay`).
  pingRing: {
    animate: {
      scale: [1, 2.2],
      opacity: [0.5, 0],
      transition: { duration: 2.8, repeat: Infinity, ease: "easeOut" },
    },
  },
  // Awaiting-auth hero: slow orange glow pulse (3.4s). Element is primary-tinted.
  authGlowPulse: {
    animate: {
      opacity: [0.35, 0.6, 0.35],
      scale: [1, 1.04, 1],
      transition: { duration: 3.4, repeat: Infinity, ease: "easeInOut" },
    },
  },
  // Severity bar: width fill on load (scaleX from a left origin; set `origin-left`).
  severityBarFill: {
    hidden: { scaleX: 0 },
    show: { scaleX: 1, transition: { duration: 0.6, ease: EASE } },
  },
  // Chart: draw-on (SVG path). Apply to a <motion.path>.
  chartDraw: {
    hidden: { pathLength: 0, opacity: 0 },
    show: {
      pathLength: 1,
      opacity: 1,
      transition: { pathLength: { duration: 1.1, ease: EASE }, opacity: { duration: 0.2 } },
    },
  },
  // Agent activity: streaming tail — each prepended line slides in.
  activityTailItem: {
    hidden: { opacity: 0, x: -12 },
    show: { opacity: 1, x: 0, transition: { duration: DUR.enter, ease: EASE } },
    exit: { opacity: 0, transition: { duration: DUR.exit, ease: EASE } },
  },
  // MCP / status dots: pulse (jade by default; amber for degraded — colour via class).
  statusDotPulse: {
    animate: {
      opacity: [1, 0.45, 1],
      scale: [1, 1.18, 1],
      transition: { duration: 1.8, repeat: Infinity, ease: "easeInOut" },
    },
  },
}

// ---- Reduced variants (prefers-reduced-motion) — no transforms, instant ----
const reduced = {
  fadeRise: { hidden: { opacity: 1 }, show: { opacity: 1, transition: { duration: 0 } }, exit: { opacity: 1 } },
  modal: { hidden: { opacity: 1 }, show: { opacity: 1, transition: { duration: 0 } }, exit: { opacity: 1 } },
  staggerContainer: { hidden: { opacity: 1 }, show: { opacity: 1, transition: { staggerChildren: 0 } } },
  staggerItem: { hidden: { opacity: 1 }, show: { opacity: 1, transition: { duration: 0 } } },
  cardHover: { rest: {}, hover: {} },
  breathingOrb: { animate: { scale: 1, opacity: 1 } },
  pingRing: { animate: { scale: 1, opacity: 0 } },
  authGlowPulse: { animate: { opacity: 0.4, scale: 1 } },
  severityBarFill: { hidden: { scaleX: 1 }, show: { scaleX: 1, transition: { duration: 0 } } },
  chartDraw: { hidden: { pathLength: 1, opacity: 1 }, show: { pathLength: 1, opacity: 1, transition: { duration: 0 } } },
  activityTailItem: { hidden: { opacity: 1, x: 0 }, show: { opacity: 1, x: 0, transition: { duration: 0 } }, exit: { opacity: 1 } },
  statusDotPulse: { animate: { opacity: 1, scale: 1 } },
}

export const variants = rich

/**
 * useMotionVariants — returns the shared variants, collapsed to no-transform
 * instant versions when the user prefers reduced motion.
 */
export function useMotionVariants() {
  const prefersReduced = useReducedMotion()
  return prefersReduced ? reduced : rich
}

/**
 * useCountUp — animates a numeric value from 0 → target on mount/target-change
 * using easeOutCubic. Returns the raw (un-rounded) value so the caller controls
 * formatting (compact `1.28M`, integers, etc.). Snaps straight to `target` when
 * the user prefers reduced motion (and when `target` isn't finite).
 *
 * `progress` is linear time t ∈ [0,1]; the eased value is derived during render.
 * State is only written inside the rAF callback (never synchronously in the
 * effect body), so the climb starts from 0 on the first frame.
 */
export function useCountUp(target, { duration = 900 } = {}) {
  const prefersReduced = useReducedMotion()
  const animate = !prefersReduced && Number.isFinite(target)
  const [progress, setProgress] = useState(animate ? 0 : 1)
  const rafRef = useRef(0)

  useEffect(() => {
    if (!animate) return undefined
    let start = null
    const tick = (ts) => {
      if (start === null) start = ts
      const t = Math.min(1, (ts - start) / duration)
      setProgress(t)
      if (t < 1) rafRef.current = requestAnimationFrame(tick)
    }
    rafRef.current = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(rafRef.current)
  }, [animate, duration, target])

  return Number.isFinite(target) ? target * easeOutCubic(progress) : target
}
