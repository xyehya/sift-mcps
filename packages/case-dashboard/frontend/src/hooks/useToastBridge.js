import { useEffect, useRef } from 'react'
import { toast } from 'sonner'

import { useStoreSlice } from '@/store/useStore'

// ─────────────────────────────────────────────────────────────────────────
// Bridge the in-store toast queue (store.addToast, used by feature components
// and the command palette) to Sonner's imperative API. The store remains the
// single producer surface (the `toasts`/`addToast`/`dismissToast` contract is
// preserved); Sonner is the renderer. Each store toast is forwarded exactly
// once via its monotonic id. Store auto-dismiss + Sonner auto-dismiss both run
// independently, which is fine — the visible toast is Sonner's.
// ─────────────────────────────────────────────────────────────────────────

const VARIANT = {
  success: (msg) => toast.success(msg),
  error: (msg) => toast.error(msg),
  warn: (msg) => toast.warning(msg),
  info: (msg) => toast.info(msg),
}

export function useToastBridge() {
  const toasts = useStoreSlice((s) => s.toasts)
  const seen = useRef(new Set())

  useEffect(() => {
    for (const t of toasts) {
      if (seen.current.has(t.id)) continue
      seen.current.add(t.id)
      ;(VARIANT[t.type] ?? VARIANT.info)(t.msg)
    }
    // Prune ids no longer in the queue so the set can't grow unbounded.
    const live = new Set(toasts.map((t) => t.id))
    for (const id of seen.current) {
      if (!live.has(id)) seen.current.delete(id)
    }
  }, [toasts])
}
