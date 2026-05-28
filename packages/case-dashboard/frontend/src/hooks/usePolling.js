import { useEffect, useRef } from 'react'

export function usePolling(fn, intervalMs = 15000) {
  const fnRef = useRef(fn)
  fnRef.current = fn

  useEffect(() => {
    let cancelled = false
    const tick = async () => {
      if (!cancelled) await fnRef.current()
    }
    tick()
    const id = setInterval(tick, intervalMs)
    return () => {
      cancelled = true
      clearInterval(id)
    }
  }, [intervalMs])
}
