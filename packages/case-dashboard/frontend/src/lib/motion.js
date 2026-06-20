import { useReducedMotion } from "framer-motion"

// Spec §2 Motion — shared variants. Transform/opacity ONLY (never w/h/top/left).
export const EASE = [0.16, 1, 0.3, 1]
export const DUR = {
  micro: 0.18, // 150–220ms band
  enter: 0.22,
  exit: 0.14, // ~65% of enter
}
export const SPRING = { type: "spring", damping: 20, stiffness: 90 }
export const STAGGER = 0.045 // 35–50ms / item

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
  // Card hover lift (+ ring glow applied via class).
  cardHover: {
    rest: { y: 0 },
    hover: { y: -3, transition: { duration: DUR.micro, ease: EASE } },
  },
}

// ---- Reduced variants (prefers-reduced-motion) — no transforms, instant ----
const reduced = {
  fadeRise: { hidden: { opacity: 1 }, show: { opacity: 1, transition: { duration: 0 } }, exit: { opacity: 1 } },
  modal: { hidden: { opacity: 1 }, show: { opacity: 1, transition: { duration: 0 } }, exit: { opacity: 1 } },
  staggerContainer: { hidden: { opacity: 1 }, show: { opacity: 1, transition: { staggerChildren: 0 } } },
  staggerItem: { hidden: { opacity: 1 }, show: { opacity: 1, transition: { duration: 0 } } },
  cardHover: { rest: {}, hover: {} },
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
