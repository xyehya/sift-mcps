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
