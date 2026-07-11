import { clsx } from "clsx"
import { twMerge } from "tailwind-merge"

/**
 * cn — merge class names with Tailwind conflict resolution (shadcn convention).
 * @param {...any} inputs - clsx-compatible class values
 * @returns {string} merged className
 */
export function cn(...inputs) {
  return twMerge(clsx(inputs))
}

/**
 * parseTime — robust helper to avoid object allocation in hot loops
 * when sorting and filtering timestamps.
 */
export const parseTime = (t) => t?.getTime ? t.getTime() : typeof t === 'number' ? t : (Date.parse(t) || 0)
